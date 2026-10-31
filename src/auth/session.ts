import { randomUUID } from 'node:crypto';
import { AuthorityError } from './authority.js';
import type { AuthorityCoordinator, AuthorityPolicy, Principal } from './authority.js';
import type { MetadataResolver } from '../network/discovery.js';
import { verifySessionJwt } from '../protocol/session.js';
import { secureUrl } from '../network/transport.js';

export interface SessionRecord {
  instanceId: string; clientId: string; sid: string; userId: string; agentId?: string;
  createdAt: number; expiresAt: number; ended: boolean; accountId?: string;
}
export interface SessionState { version: 1; generation: string; record: SessionRecord | null }
export interface SessionAdmission extends SessionState { activeCount: number; earliestExpiry: number | null }
/** Serialize admission per client across processes; callbacks are synchronous, detached, and atomic. */
export interface SessionStore {
  read(clientId: string, sid: string): Promise<SessionState>;
  transaction<T>(clientId: string, sid: string, at: number, change: (state: SessionAdmission) => T): Promise<T>;
}
export interface SessionAuthority {
  authenticate(request: Request, account?: { token: string; principal: Principal }): Promise<Principal>;
  end(clientId: string, sid: string): Promise<void>;
  policy: AuthorityPolicy;
}

/** Resources own Sessions; an OAuth issuer supplies only account authority. */
export function createSessionAuthority(options: {
  companyId: string; metadata: MetadataResolver; store: SessionStore; coordinator: AuthorityCoordinator;
  now: () => number; accountPolicy?: AuthorityPolicy; lifetimeSeconds?: number; maxSessionsPerClient?: number;
  acceptClient?: (clientId: string) => Promise<boolean>;
}): SessionAuthority {
  secureUrl(options.companyId);
  const lifetime = options.lifetimeSeconds ?? 86400;
  if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > 31_536_000) throw new TypeError('Session lifetime');
  const maxSessions = options.maxSessionsPerClient ?? 10000;
  if (!Number.isSafeInteger(maxSessions) || maxSessions < 1) throw new TypeError('maxSessionsPerClient');
  const invalid = () => new AuthorityError('invalid_session');
  async function current(principal: Principal): Promise<void> {
    const state = await options.store.read(principal.clientId, principal.sessionId), record = state.record;
    if (principal.issuer !== options.companyId || principal.sessionGeneration !== state.generation || !record || record.ended || record.expiresAt <= options.now()
      || record.clientId !== principal.clientId || record.sid !== principal.sessionId || record.userId !== principal.userId || record.instanceId !== principal.sessionInstanceId || record.agentId !== principal.agentId) throw invalid();
  }
  const policy: AuthorityPolicy = {
    withCurrent: (principal, scopes, action) => options.coordinator.run(async () => {
      await current(principal);
      if (principal.tokenExpiresAt <= options.now()) throw new AuthorityError('invalid_token');
      if (!scopes.every(scope => principal.scopes.includes(scope))) throw new AuthorityError(principal.accountId ? 'insufficient_scope' : 'account_required', { scope: scopes.join(' ') });
      if (principal.accountId) {
        if (!options.accountPolicy) throw new AuthorityError('invalid_token');
        return options.accountPolicy.withCurrent(principal, scopes, action);
      }
      return action();
    }),
    withAccepted: (accepted, scopes, action) => options.coordinator.run(async () => {
      const state = await options.store.read(accepted.principal.clientId, accepted.principal.sessionId);
      if (accepted.principal.issuer !== options.companyId || state.generation !== accepted.principal.sessionGeneration) throw invalid();
      if (!scopes.every(scope => accepted.principal.scopes.includes(scope))) throw new AuthorityError('insufficient_scope', { scope: scopes.join(' ') });
      if (accepted.principal.accountId) {
        if (!options.accountPolicy) throw new AuthorityError('invalid_token');
        return options.accountPolicy.withAccepted(accepted, scopes, action);
      }
      return action();
    }),
  };
  return {
    policy,
    async authenticate(request, account) {
      let claims;
      try {
        claims = await verifySessionJwt(request.headers.get('poppy-session'), {
          companyId: options.companyId, method: request.method, url: request.url, nowMs: options.now(), metadata: options.metadata,
          ...(account ? { accessToken: account.token, tokenClientId: account.principal.clientId } : {}),
        });
        if (options.acceptClient && !await options.acceptClient(claims.iss)) throw invalid();
      } catch { throw invalid(); }
      if (account && (account.principal.issuer !== options.companyId || account.principal.tokenExpiresAt <= options.now() || !account.principal.accountId)) throw new AuthorityError('invalid_token');
      return options.coordinator.run(() => options.store.transaction(claims.iss, claims.sid, options.now(), state => {
        const at = options.now();
        if (claims.iat < at / 1000 - 60 || claims.delegationExpiresAt <= at) throw invalid();
        if (!Number.isSafeInteger(state.activeCount) || state.activeCount < 0) throw new TypeError('Session admission count');
        if (!state.record && state.activeCount >= maxSessions) throw new AuthorityError('rate_limited', { retryAfter: Math.max(1, Math.ceil(((state.earliestExpiry ?? at + lifetime * 1000) - at) / 1000)) });
        const record = state.record ??= { instanceId: randomUUID(), clientId: claims.iss, sid: claims.sid, userId: claims.sub,
          ...(claims.agent_id === undefined ? {} : { agentId: claims.agent_id }), createdAt: at, expiresAt: at + lifetime * 1000, ended: false };
        if (record.clientId !== claims.iss || record.sid !== claims.sid || record.userId !== claims.sub || record.agentId !== claims.agent_id || record.ended || record.expiresAt <= at) throw invalid();
        record.instanceId ??= randomUUID();
        if (account) {
          if (record.accountId !== undefined && record.accountId !== account.principal.accountId) throw invalid();
          record.accountId = account.principal.accountId;
        }
        return { ...(account?.principal ?? { issuer: options.companyId, scopes: [], tokenExpiresAt: record.expiresAt }),
          issuer: options.companyId, clientId: claims.iss, userId: claims.sub, sessionId: claims.sid,
          ...(claims.agent_id === undefined ? {} : { agentId: claims.agent_id }), sessionVersion: 1, sessionInstanceId: record.instanceId, sessionGeneration: state.generation, sessionExpiresAt: record.expiresAt };
      }));
    },
    async end(clientId, sid) {
      await options.coordinator.run(() => options.store.transaction(clientId, sid, options.now(), state => { if (state.record) state.record.ended = true; }));
    },
  };
}
