import { createHash, randomBytes } from 'node:crypto';
import { calculateJwkThumbprint, compactVerify, createLocalJWKSet, errors } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { ValidationError, parseAssertionClaims, parseJson } from '../protocol/wire.js';
import type { AssertionClaims } from '../protocol/wire.js';
import { companyScopes, MEDIATED_GRANT, parseMediatedSignIn } from '../network/discovery.js';
import type { MetadataResolver } from '../network/discovery.js';
import { registeredRedirect } from '../network/redirect.js';
import { secureUrl } from '../network/transport.js';
import { own } from '../store.js';
import type { IssuerStore, IssuerSelection } from './store.js';
import { clientRevisionKey, accountRevisionKey } from './store.js';
import { AuthorityError } from '../auth/authority.js';
import type { AuthorityCoordinator, AuthorityPolicy, ExternalAuthorityAdapter, Principal } from '../auth/authority.js';
import { CLOCK_SKEW_SECONDS, PROOF_WINDOW_SECONDS, assertUniqueJwtMembers, verifyDpopProof } from '../auth/dpop.js';

export type { IssuerStore, IssuerSelection };
export { createMetadataResolver } from '../network/discovery.js';
export { createNodeTransport } from '../network/transport.js';
// accountId is sticky (spec 4.4): it stays after sign-out; grantId is the active sign-in, null when signed out.
// version only fills Principal.sessionVersion: it is never bumped, since a Session ends by deletion, which the policy already checks.
interface SessionRecord { clientId: string; userId: string; agentId?: string; version: number; createdAt: number; expiresAt: number; accountId: string | null; grantId: string | null }
// Stable lineage of one account sign-in; the ID survives Account Token rotation and expiresAt never moves.
interface GrantRecord { clientId: string; userId: string; accountId: string; scopes: string[]; expiresAt: number; revoked: boolean; refreshHash: string; previousHash: string }
interface AccessTokenRecord { clientId?: string; accountId?: string; sessionId: string; grantId: string | null; scopes: string[]; resource: string | null; jkt: string; expiresAt: number }
interface AuthorizationRecord { sessionKey: string | null; clientId: string; redirectUri: string; state: string; codeChallenge: string; scopes: string[]; browserHash: string; expiresAt: number; revision: number; completion?: { decisionHash: string; callback: string } }
// grantId is set once the code is exchanged, so a second use can revoke what the first produced (RFC 6749 4.1.2).
interface CodeRecord { sessionKey: string | null; clientId: string; redirectUri: string; codeChallenge: string; accountId: string; scopes: string[]; expiresAt: number; grantId: string | null; revision: number }
export type SignInRecord =
  | { kind: 'device'; sessionKey: string | null; clientId: string; scopes: string[]; expiresAt: number; deviceHash: string; status: 'pending' | 'approved' | 'denied' | 'consumed'; nextPollAt: number; intervalMs: number; revision: number; browserHash?: string; accountId?: string }
  | { kind: 'mediated'; resource?: string | null; grantId?: string; clientId: string; userId?: string; sessionId?: string; scopes: string[]; expiresAt: number; status: 'verifying' | 'pending' | 'failed' | 'expired' | 'complete'; attempts: number; executionId: string; revision: number; accountId?: string; challengeId?: string; sentTo?: string }
  | { kind: 'attempts'; clientId: string; sessionId?: string; expiresAt: number; count: number }
  | { kind: 'revision'; clientId: string; accountId?: string; expiresAt: number; revision: number };
export interface MediatedContext { clientId: string; issuer: string }
export interface MediatedOptions {
  endpoint?: string; scopes: string[]; fields: { name: string; label: string; secret: boolean }[];
  authenticate(credentials: Readonly<Record<string, string>>, context: MediatedContext): Promise<{ accountId: string; scopes?: string[]; challenge?: { id: string; sentTo: string } } | null>;
  verifyCode(input: { challengeId: string; code: string }, context: MediatedContext): Promise<boolean>;
  maxCodeAttempts?: number; maxAttemptsPerMinute?: number; maxClientAttemptsPerMinute?: number;
}
// Plain JSON. Tokens and codes are keyed by SHA-256 hash; plaintext tokens are never stored.
export interface IssuerState {
  limits?: { sessions: number; earliestSessionExpiry: number; pending: number; pendingForClient: number };
  version: 3 | 4 | 5;
  generation: string;
  sessions: Record<string, SessionRecord>;
  sessionKeys: Record<string, string>; // Thumbprint -> internal Session ID; retained indefinitely, including ended keys.
  grants: Record<string, GrantRecord>;
  refreshTokens: Record<string, string>; // Every issued Account Token hash -> grant ID, through the grant's fixed expiry
  authorizations: Record<string, AuthorizationRecord>;
  codes: Record<string, CodeRecord>;
  signIns: Record<string, SignInRecord>;
  accessTokens: Record<string, AccessTokenRecord>;
  replay: Record<string, number>; // assertion/proof jti key -> retain until (ms)
  nonces: { value: string; expiresAt: number }[];
}
export interface ReferenceIssuerOptions {
  issuer: string; tokenEndpoint: string; revocationEndpoint: string; authorizationEndpoint?: string;
  protectedResources: string[]; supportedScopes: string[];
  resources?: string[]; // exact supported resource identifiers; absent resource means default
  mcpResources?: { url: string; dpop: boolean }[];
  metadata: MetadataResolver;
  /** Required for Direct Sign-In: synchronous authenticated encryption with a durable host-owned key. */
  authorizationResultCipher?: { seal(value: string): string; open(value: string): string };
  store: IssuerStore;
  coordinator: AuthorityCoordinator; // deployment-wide, shared with conversation work and reset
  now: () => number;
  tokenLifetimeSeconds?: number; // default 3600
  accountLifetimeSeconds?: number; // default 2592000, rotation never extends it
  requireDpopNonce?: boolean; // default true at token endpoint
  maxPendingAuthorizations?: number; // default 1000; begin refuses more with temporarily_unavailable
  maxPendingAuthorizationsPerClient?: number; // default 100, so one client cannot use up the global cap
  maxSessionsPerClient?: number; // Removed: configure this on createSessionAuthority; passing it here fails explicitly.
  device?: { endpoint: string; verificationUri: string; intervalSeconds?: number };
  mediated?: MediatedOptions;
}
export interface AuthorizationView { id: string; clientId: string; clientName: string; scopes: string[]; expiresAt: number }
export type AuthorizationDecision = { accountId: string; scopes: string[] } | { denied: true };
export interface ReferenceIssuer {
  token(request: Request): Promise<Response>;
  revoke(request: Request): Promise<Response>;
  beginAuthorization(request: Request, browserBinding: string): Promise<AuthorizationView>;
  completeAuthorization(id: string, browserBinding: string, decision: AuthorizationDecision): Promise<URL>;
  deviceAuthorization(request: Request): Promise<Response>;
  beginDeviceAuthorization(userCode: string, browserBinding: string): Promise<AuthorizationView>;
  completeDeviceAuthorization(userCode: string, browserBinding: string, decision: AuthorizationDecision): Promise<void>;
  authorizationMetadata(): Record<string, unknown>;
  authority: ExternalAuthorityAdapter;
  disconnect(clientId: string, accountId: string): Promise<void>;
}
// Authorization request failure for the host's sign-in page. redirectTo is set only once client and redirect_uri are verified;
// without it the host shows an error page and never redirects (RFC 6749 4.1.2.1).
export class AuthorizationError extends Error {
  constructor(readonly code: string, readonly redirectTo?: URL) { super(`Authorization failed: ${code}`); this.name = 'AuthorizationError'; }
}

const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const ASSERTION_ALGORITHMS = ['ES256', 'RS256', 'PS384'];
const NONCE_SECONDS = 300;
const MAX_FORM_BYTES = 65536;
const AUTHORIZATION_MS = 600_000;
const CODE_MS = 60_000;
// A Session ends a day after the last token issued for it (spec 4.2: the Company decides how long a Session lasts).

const random = (bytes: number) => randomBytes(bytes).toString('base64url');
const tokenHash = (token: string) => createHash('sha256').update(token).digest('base64url');
const grantLive = (grant: GrantRecord | undefined, at: number) => !!grant && !grant.revoked && grant.expiresAt > at;
function callback(redirectUri: string, fields: Record<string, string>): string {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(fields)) url.searchParams.set(name, value);
  return url.href;
}

// Shape changes bump the version; other versions are refused instead of misread.
function checked(state: IssuerState): IssuerState {
  upgradeIssuerState(state);
  return state;
}

/** Run once over the complete namespace, under the adapter's writer lock. */
export function upgradeIssuerState(state: IssuerState): void {
  if (state.version === 5) return;
  if (state.version !== 3 && state.version !== 4) throw new Error('unsupported issuer state version');
  state.sessionKeys ??= {};
  for (const token of Object.values(state.accessTokens)) {
    const grant = token.grantId === null ? undefined : own(state.grants, token.grantId);
    const session = own(state.sessions, token.sessionId);
    if (grant && session && grant.clientId !== session.clientId) continue;
    const clientId = grant?.clientId ?? session?.clientId;
    if (clientId !== undefined) token.clientId ??= clientId;
    if (grant) token.accountId ??= grant.accountId;
  }
  // Keep legacy Sessions, pending consent, replay fences and uncertain hooks for explicit reconciliation.
  state.version = 5;
}

export function initialIssuerState(): IssuerState {
  return { version: 5, generation: random(16), sessions: {}, sessionKeys: {}, grants: {}, refreshTokens: {}, authorizations: {}, codes: {}, signIns: {}, accessTokens: {}, replay: {}, nonces: [] };
}

class TokenError extends Error {
  constructor(readonly code: string, readonly headers: Record<string, string> = {}) { super(`Token request failed: ${code}`); this.name = 'TokenError'; }
}
function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
}

// Unauthenticated public endpoint: stop reading once the byte limit is passed.
async function readForm(request: Request): Promise<string> {
  if (Number(request.headers.get('content-length') ?? 0) > MAX_FORM_BYTES) throw new TokenError('invalid_request');
  if (!request.body) return '';
  const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let length = 0;
  try {
    while (true) {
      const item = await reader.read(); if (item.done) break;
      length += item.value.length; if (length > MAX_FORM_BYTES) throw new TokenError('invalid_request');
      chunks.push(item.value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks).toString('utf8');
}
// Repeated parameters are rejected (RFC 6749 3.1, 3.2).
function uniqueParams(entries: Iterable<[string, string]>, error: () => Error): Map<string, string> {
  const params = new Map<string, string>();
  for (const [key, value] of entries) { if (params.has(key)) throw error(); params.set(key, value); }
  return params;
}
async function readParams(request: Request): Promise<Map<string, string>> {
  if (request.method !== 'POST' || !/^application\/x-www-form-urlencoded\s*(;|$)/i.test(request.headers.get('content-type') ?? '')) throw new TokenError('invalid_request');
  return uniqueParams(new URLSearchParams(await readForm(request)), () => new TokenError('invalid_request'));
}

export function createReferenceIssuer(options: ReferenceIssuerOptions): ReferenceIssuer {
  const { issuer, metadata, store, now } = options;
  if (secureUrl(issuer).search) throw new TypeError('issuer');
  secureUrl(options.tokenEndpoint); secureUrl(options.revocationEndpoint);
  if (!options.protectedResources.length) throw new TypeError('protectedResources');
  options.protectedResources.forEach(value => secureUrl(value));
  companyScopes(options.supportedScopes, true);
  if (options.authorizationEndpoint) secureUrl(options.authorizationEndpoint);
  if (options.mediated && companyScopes(options.mediated.scopes).some(scope => !options.supportedScopes.includes(scope))) throw new TypeError('mediated.scopes');
  const positive = (value: number | undefined, fallback: number, name: string) => {
    const result = value ?? fallback;
    if (!Number.isSafeInteger(result) || result <= 0) throw new TypeError(name);
    return result;
  };
  const lifetimeSeconds = positive(options.tokenLifetimeSeconds, 3600, 'tokenLifetimeSeconds');
  const lifetimeMs = lifetimeSeconds * 1000;
  const accountLifetimeMs = positive(options.accountLifetimeSeconds, 2_592_000, 'accountLifetimeSeconds') * 1000;
  const maxPending = positive(options.maxPendingAuthorizations, 1000, 'maxPendingAuthorizations');
  const maxPendingPerClient = positive(options.maxPendingAuthorizationsPerClient, 100, 'maxPendingAuthorizationsPerClient');
  if (options.maxSessionsPerClient !== undefined) throw new TypeError('maxSessionsPerClient moved to createSessionAuthority');
  const requireNonce = options.requireDpopNonce ?? true;
  if (options.device) { secureUrl(options.device.endpoint); const url = secureUrl(options.device.verificationUri); const hosts = [new URL(issuer).hostname, ...options.protectedResources.map(resource => new URL(resource).hostname)];
    if (!hosts.some(host => url.hostname === host || url.hostname.endsWith(`.${host}`))) throw new TypeError('verificationUri'); }
  if (options.mediated) parseMediatedSignIn({version:'1',fields:options.mediated.fields,scopes:options.mediated.scopes});
  const deviceIntervalMs = positive(options.device?.intervalSeconds, 5, 'intervalSeconds') * 1000;
  const maxCodeAttempts = positive(options.mediated?.maxCodeAttempts, 5, 'maxCodeAttempts');
  const maxAttempts = positive(options.mediated?.maxAttemptsPerMinute, 5, 'maxAttemptsPerMinute');
  const maxClientAttempts = positive(options.mediated?.maxClientAttemptsPerMinute, 100, 'maxClientAttemptsPerMinute');
  const mcpResources = options.mcpResources ?? [];
  for (const entry of mcpResources) { const url = secureUrl(entry.url); if (typeof entry.dpop !== 'boolean' || mcpResources.filter(item => item.url === entry.url).length !== 1) throw new TypeError('mcpResources'); }
  const resources = [...new Set([...(options.resources ?? []), ...mcpResources.map(entry => entry.url)])];
  const isBearerResource = (resource: string | undefined) => mcpResources.some(entry => entry.url === resource && !entry.dpop);
  // Every issuer mutation is ordered with conversation work by the shared coordinator.
  const read = async (selection: IssuerSelection = { kind: 'metadata' }) => checked(await store.read(selection));
  const commit = <T>(selection: IssuerSelection, change: (draft: IssuerState) => T) => options.coordinator.run(() => store.transaction(selection, draft => change(checked(draft))));

  // Reuse the current nonce while it has more than half its life left, so challenges cannot grow state.
  async function currentNonce(state: IssuerState): Promise<string> {
    const fresh = state.nonces.find(nonce => nonce.expiresAt - now() > NONCE_SECONDS * 500);
    if (fresh) return fresh.value;
    return commit({ kind: 'metadata' }, draft => {
      const value = random(16);
      draft.nonces = [...draft.nonces.filter(nonce => nonce.expiresAt > now()), { value, expiresAt: now() + NONCE_SECONDS * 1000 }].slice(-2);
      return value;
    });
  }

  async function verifyAssertion(jwt: string, keys: JSONWebKeySet): Promise<AssertionClaims> {
    assertUniqueJwtMembers(jwt); // before jose, which keeps the last of any duplicate claim
    const { payload, protectedHeader } = await compactVerify(jwt, createLocalJWKSet(keys), { algorithms: ASSERTION_ALGORITHMS });
    // Media types are case-insensitive and may carry the application/ prefix (RFC 7515 4.1.9).
    if (protectedHeader.typ?.toLowerCase().replace(/^application\//, '') === 'poppy-browser+jwt') throw new TypeError('browser assertion'); // spec 5: not accepted here
    return parseAssertionClaims(JSON.parse(new TextDecoder().decode(payload)));
  }
  const current = (claims: AssertionClaims) => claims.exp * 1000 > now() && claims.iat <= now() / 1000 + CLOCK_SKEW_SECONDS;

  // Fetches the client's keys and verifies its client assertion (spec 4.1); verify() is reused for the session assertion.
  async function authenticateClient(clientId: string, clientAssertion: string) {
    let jwksUri: string; let keys: JSONWebKeySet;
    try { jwksUri = (await metadata.resolveClient(clientId)).jwks_uri; keys = await metadata.resolveJwks(jwksUri) as unknown as JSONWebKeySet; } catch (error) {
      // The shared resolver signals its fetch cap as ValidationError('metadata.rate_limited'); its window is 60 s.
      if (error instanceof ValidationError && error.field === 'metadata.rate_limited') throw new TokenError('rate_limited', { 'Retry-After': '60' });
      throw new TokenError('invalid_client');
    }
    let refreshed = false;
    const verify = async (jwt: string) => {
      try { return await verifyAssertion(jwt, keys); } catch (error) {
        if (refreshed || !(error instanceof errors.JWKSNoMatchingKey)) throw error;
        refreshed = true; // one bounded refresh for an unknown kid; the resolver rate-limits it too
        try { keys = await metadata.resolveJwks(jwksUri, { refresh: true }) as unknown as JSONWebKeySet; } catch (limit) {
          if (limit instanceof ValidationError && limit.field === 'jwks.refresh_limited') throw new TokenError('rate_limited', { 'Retry-After': '60' });
          throw limit;
        }
        return verifyAssertion(jwt, keys);
      }
    };
    let client: AssertionClaims;
    try { client = await verify(clientAssertion); } catch (error) { throw error instanceof TokenError ? error : new TokenError('invalid_client'); }
    if (client.iss !== clientId || client.sub !== clientId || client.aud !== issuer || !current(client)) throw new TokenError('invalid_client');
    return { client, verify, keys: () => keys };
  }
  function clientCredentials(params: Map<string, string>) {
    const clientId = params.get('client_id'); const clientAssertion = params.get('client_assertion');
    if (!clientId || !clientAssertion || params.get('client_assertion_type') !== CLIENT_ASSERTION_TYPE) throw new TokenError('invalid_client');
    return { clientId, clientAssertion };
  }

  // Drops everything past its lifetime so state stays bounded by live records.
  function prune(draft: IssuerState, at: number): void {
    for (const [key, until] of Object.entries(draft.replay)) if (until < at) delete draft.replay[key];
    for (const [key, record] of Object.entries(draft.accessTokens)) if (record.expiresAt <= at) delete draft.accessTokens[key];
    for (const [key, record] of Object.entries(draft.sessions)) if (!(record.expiresAt > at)) delete draft.sessions[key];
    for (const [key, record] of Object.entries(draft.grants)) if (!grantLive(record, at)) delete draft.grants[key];
    for (const [key, grantId] of Object.entries(draft.refreshTokens)) if (!Object.hasOwn(draft.grants, grantId)) delete draft.refreshTokens[key];
    for (const [key, record] of Object.entries(draft.codes)) if (record.expiresAt <= at) delete draft.codes[key];
    for (const [key, record] of Object.entries(draft.authorizations)) if (record.expiresAt <= at) delete draft.authorizations[key];
    for (const [key, record] of Object.entries(draft.signIns)) if (!(record.kind === 'mediated' && record.status === 'verifying') && record.expiresAt + CLOCK_SKEW_SECONDS * 1000 < at) delete draft.signIns[key];
  }
  // Revoking a grant signs out every Session using it; they continue signed out and stay bound to the account (spec 4.9).
  function revokeGrant(draft: IssuerState, grantId: string): void {
    const grant = own(draft.grants, grantId);
    if (!grant) return;
    grant.revoked = true;
    for (const session of Object.values(draft.sessions)) if (session.grantId === grantId) session.grantId = null;
  }
  function issueSignIn(draft: IssuerState, clientId: string, accountId: string, scopes: string[], jkt: string, resource?: string): { grantId: string; body: Record<string, unknown> } {
    const grantId = 'grt_' + random(16), refreshToken = random(32), accessToken = random(32), at = now(), refreshHash = tokenHash(refreshToken);
    draft.grants[grantId] = {clientId,userId:'',accountId,scopes:[...scopes],expiresAt:at+accountLifetimeMs,revoked:false,refreshHash,previousHash:''};
    draft.refreshTokens[refreshHash] = grantId;
    draft.accessTokens[tokenHash(accessToken)] = {clientId,accountId,sessionId:'',grantId,scopes:[...scopes],resource:resource ?? null,jkt,expiresAt:at+lifetimeMs};
    return {grantId,body:{access_token:accessToken,token_type:jkt ? 'DPoP' : 'Bearer',expires_in:lifetimeSeconds,refresh_token:refreshToken,refresh_token_expires_in:Math.floor(accountLifetimeMs/1000),scope:scopes.join(' ')}};
  }
  function signInScopes(scope: string | undefined, allowed: readonly string[]): string[] {
    const scopes = scope?.split(' ') ?? [];
    if (!scopes.length || scopes.some(value => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(value) || !allowed.includes(value)) || new Set(scopes).size !== scopes.length) throw new TokenError('invalid_scope');
    return scopes;
  }
  function consumeReplay(draft: IssuerState, key: string, until: number): void {
    if ((own(draft.replay, key) ?? 0) > now()) throw new TokenError('invalid_grant');
    draft.replay[key] = until;
  }
  function revision(draft: IssuerState, key: string): number {
    const row = own(draft.signIns, key); return row?.kind === 'revision' ? row.revision : 0;
  }
  function consentCurrent(draft: IssuerState, clientId: string, accountId: string, started: number): boolean {
    return revision(draft, accountRevisionKey(clientId, accountId)) <= started;
  }
  async function startDevice(request: Request): Promise<Response> {
    if (!options.device) throw new TokenError('unsupported_grant_type');
    const params = await readParams(request), { clientId, clientAssertion } = clientCredentials(params);
    const scopes = signInScopes(params.get('scope'), options.supportedScopes), { client } = await authenticateClient(clientId, clientAssertion);
    const { generation } = await read(), userCode = random(8).toUpperCase(), deviceCode = `${userCode}.${random(32)}`, id = tokenHash(userCode);
    const replayKey = `assertion ${clientId} ${client.jti}`;
    await commit({ kind: 'sign_in', ids: [id, clientRevisionKey(clientId)], clientId, replayKeys: [replayKey], at: now() }, draft => {
      if (draft.generation !== generation || !current(client)) throw new TokenError('invalid_client');
      const pending = Object.values(draft.signIns).filter(row => (row.kind === 'mediated' && row.status === 'verifying') || row.expiresAt > now() && (row.kind === 'device' ? row.status === 'pending' || row.status === 'approved' : row.kind === 'mediated' && (row.status === 'pending' || row.status === 'verifying')));
      if ((draft.limits?.pending ?? pending.length) >= maxPending || (draft.limits?.pendingForClient ?? pending.filter(row => row.clientId === clientId).length) >= maxPendingPerClient) throw new TokenError('rate_limited', { 'Retry-After': '60' });
      consumeReplay(draft, replayKey, client.exp * 1000);
      draft.signIns[id] = { kind: 'device', sessionKey: null, clientId, scopes, expiresAt: now() + AUTHORIZATION_MS, deviceHash: tokenHash(deviceCode), status: 'pending', nextPollAt: now() + deviceIntervalMs, intervalMs: deviceIntervalMs, revision: revision(draft, clientRevisionKey(clientId)) };
    });
    const complete = new URL(options.device.verificationUri); complete.searchParams.set('user_code', userCode);
    return json(200, { device_code: deviceCode, user_code: userCode, verification_uri: options.device.verificationUri, verification_uri_complete: complete.href, expires_in: AUTHORIZATION_MS / 1000, interval: deviceIntervalMs / 1000 });
  }
  async function pollDevice(request: Request, params: Map<string, string>): Promise<Response> {
    if (!options.device) throw new TokenError('unsupported_grant_type');
    const {clientId,clientAssertion} = clientCredentials(params), code = params.get('device_code'), resource = params.get('resource');
    if (!code || params.has('session_id') || params.has('assertion')) throw new TokenError('invalid_request');
    if (resource !== undefined && !resources.includes(resource)) throw new TokenError('invalid_target');
    const state = await read();
    const proof = isBearerResource(resource) ? null : await verifyDpopProof(request.headers.get('dpop'),{method:'POST',url:options.tokenEndpoint,nowMs:now()});
    if (proof && requireNonce && !state.nonces.some(nonce=>nonce.value===proof.claims.nonce&&nonce.expiresAt>now())) throw new TokenError('use_dpop_nonce',{'DPoP-Nonce':await currentNonce(state)});
    const {client,keys} = await authenticateClient(clientId,clientAssertion);
    if (proof) for (const key of keys().keys) if (await calculateJwkThumbprint(key).catch(()=>null)===proof.jkt) throw new TokenError('invalid_dpop_proof');
    const id=tokenHash(code.split('.')[0]!),replayKey=`assertion ${clientId} ${client.jti}`,proofKey=proof?`proof ${proof.jkt} ${proof.claims.jti}`:null;
    const body=await commit({kind:'sign_in',ids:[id],clientId,replayKeys:[replayKey,...(proofKey?[proofKey]:[])],at:now()},draft=>{
      if(draft.generation!==state.generation||!current(client))throw new TokenError('invalid_client');
      consumeReplay(draft,replayKey,client.exp*1000);
      if(proof&&proofKey)consumeReplay(draft,proofKey,(proof.claims.iat+PROOF_WINDOW_SECONDS)*1000);
      const record=own(draft.signIns,id);
      if(!record||record.kind!=='device'||record.clientId!==clientId||record.deviceHash!==tokenHash(code))return {error:'invalid_grant'};
      if(record.expiresAt<=now())return {error:'expired_token'};
      if(record.status==='denied')return {error:'access_denied'};
      if(record.status==='consumed')return {error:'invalid_grant'};
      if(record.nextPollAt>now()){record.intervalMs+=5000;record.nextPollAt=now()+record.intervalMs;return {error:'slow_down'};}
      record.nextPollAt=now()+record.intervalMs;
      if(record.status==='pending')return {error:'authorization_pending'};
      if(!consentCurrent(draft,clientId,record.accountId!,record.revision))return {error:'invalid_grant'};
      const result=issueSignIn(draft,clientId,record.accountId!,record.scopes,proof?.jkt??'',resource);
      record.status='consumed';return result.body;
    });
    return json('error' in body?400:200,body);
  }
  async function mediatedSignIn(request: Request, supplied?: Map<string,string>): Promise<Response> {
    const config=options.mediated;
    if(!config)throw new TokenError('unsupported_grant_type');
    if(request.url!==options.tokenEndpoint)throw new TokenError('invalid_request');
    const params=supplied??await readParams(request),{clientId,clientAssertion}=clientCredentials(params);
    if(params.get('grant_type')!==MEDIATED_GRANT)throw new TokenError('invalid_request');
    const {client,keys}=await authenticateClient(clientId,clientAssertion),state=await read();
    const challenge=params.has('sign_in_id'),id=challenge?params.get('sign_in_id')!:random(32);
    if(!/^[A-Za-z0-9_-]{1,256}$/.test(id))throw new TokenError('invalid_grant');
    const key=tokenHash(id),existing=challenge?own((await read({kind:'sign_in',ids:[key],replayKeys:[],at:now()})).signIns,key):undefined;
    if(challenge&&(!existing||existing.kind!=='mediated'||existing.clientId!==clientId||!Object.hasOwn(existing,'resource')))throw new TokenError('invalid_grant');
    const resource=challenge&&existing?.kind==='mediated'?existing.resource??undefined:params.get('resource');
    if(resource!==undefined&&!resources.includes(resource))throw new TokenError('invalid_target');
    if(challenge&&params.has('resource')&&params.get('resource')!==resource)throw new TokenError('invalid_target');
    const proof=isBearerResource(resource)?null:await verifyDpopProof(request.headers.get('dpop'),{method:'POST',url:options.tokenEndpoint,nowMs:now()});
    if(proof&&requireNonce&&!state.nonces.some(nonce=>nonce.value===proof.claims.nonce&&nonce.expiresAt>now()))throw new TokenError('use_dpop_nonce',{'DPoP-Nonce':await currentNonce(state)});
    if(proof)for(const key of keys().keys)if(await calculateJwkThumbprint(key).catch(()=>null)===proof.jkt)throw new TokenError('invalid_dpop_proof');
    const credentials:Record<string,string>=Object.create(null);let oneTimeCode='';
    try {
      if(challenge){
        if(params.has('scope')||config.fields.some(field=>params.has(field.name)))throw new TokenError('invalid_request');
        oneTimeCode=params.get('one_time_code')??'';if(!oneTimeCode||oneTimeCode.length>4096)throw new TokenError('invalid_request');
      }else{
        if(params.has('one_time_code'))throw new TokenError('invalid_request');
        for(const field of config.fields){const value=params.get(field.name);if(!value||value.length>4096)throw new TokenError('invalid_request');credentials[field.name]=value;}
      }
      const scopes=challenge?[]:signInScopes(params.get('scope'),config.scopes),context:MediatedContext={issuer,clientId};
      const replayKey=`assertion ${clientId} ${client.jti}`,proofKey=proof?`proof ${proof.jkt} ${proof.claims.jti}`:null,limitId=tokenHash('credential attempts '+clientId),executionId=random(16);
      const selection:IssuerSelection={kind:'sign_in',ids:[key,limitId,clientRevisionKey(clientId)],clientId,replayKeys:[replayKey,...(proofKey?[proofKey]:[])],at:now()};
      const claim=await commit(selection,draft=>{
        if(draft.generation!==state.generation||!current(client))throw new TokenError('invalid_client');
        consumeReplay(draft,replayKey,client.exp*1000);if(proof&&proofKey)consumeReplay(draft,proofKey,(proof.claims.iat+PROOF_WINDOW_SECONDS)*1000);
        let row=own(draft.signIns,key);
        if(challenge){
          if(!row||row.kind!=='mediated'||row.clientId!==clientId||!Object.hasOwn(row,'resource'))throw new TokenError('invalid_grant');
          if(row.status==='complete'||row.status==='failed')return {error:'invalid_grant'};
          if(row.status==='verifying')throw new TokenError('temporarily_unavailable',{'Retry-After':'5'});
          if(row.expiresAt<=now()||row.status==='expired'){row.status='expired';return {error:'expired_token'};}
          if(row.attempts>=maxCodeAttempts){row.status='failed';return {error:'invalid_grant'};}
          row.attempts++;row.status='verifying';row.executionId=executionId;return {record:row};
        }
        const old=own(draft.signIns,limitId),window=old?.kind==='attempts'&&old.expiresAt>now()?old:{kind:'attempts' as const,clientId,count:0,expiresAt:now()+60000};
        if(window.count>=Math.min(maxAttempts,maxClientAttempts))throw new TokenError('rate_limited',{'Retry-After':String(Math.ceil((window.expiresAt-now())/1000))});
        window.count++;draft.signIns[limitId]=window;
        const pending=Object.values(draft.signIns).filter(row=>(row.kind==='mediated'&&row.status==='verifying')||row.expiresAt>now()&&((row.kind==='device'&&(row.status==='pending'||row.status==='approved'))||(row.kind==='mediated'&&(row.status==='pending'||row.status==='verifying'))));
        if((draft.limits?.pending??pending.length)>=maxPending||(draft.limits?.pendingForClient??pending.filter(row=>row.clientId===clientId).length)>=maxPendingPerClient)throw new TokenError('rate_limited',{'Retry-After':'60'});
        const record:Extract<SignInRecord,{kind:'mediated'}>={kind:'mediated',clientId,resource:resource??null,scopes,expiresAt:now()+AUTHORIZATION_MS,status:'verifying',attempts:0,executionId,revision:revision(draft,clientRevisionKey(clientId))};
        draft.signIns[key]=record;return {record};
      });
      if('error' in claim)return json(400,claim);
      const row=claim.record;
      let decision:Awaited<ReturnType<MediatedOptions['authenticate']>>=null,correct=false;
      try{if(challenge)correct=await config.verifyCode({challengeId:row.challengeId!,code:oneTimeCode},context);else decision=await config.authenticate(credentials,context);}catch{throw new TokenError('temporarily_unavailable',{'Retry-After':'5'});}
      if(challenge&&typeof correct!=='boolean')throw new TokenError('temporarily_unavailable');
      if(decision&&(typeof decision.accountId!=='string'||!decision.accountId||decision.accountId.length>256||(decision.scopes!==undefined&&(!Array.isArray(decision.scopes)||!decision.scopes.length||!decision.scopes.every(scope=>row.scopes.includes(scope))))||(decision.challenge&&(typeof decision.challenge.id!=='string'||!decision.challenge.id||typeof decision.challenge.sentTo!=='string'||decision.challenge.sentTo.length>512))))throw new TokenError('temporarily_unavailable');
      const accountId=decision?.accountId??row.accountId;
      const body=await commit({...selection,ids:[...selection.ids,...(accountId?[accountRevisionKey(clientId,accountId)]:[])]},draft=>{
        if(draft.generation!==state.generation||!current(client))throw new TokenError('invalid_client');
        const completed=own(draft.signIns,key);
        if(!completed||completed.kind!=='mediated'||completed.executionId!==executionId||completed.status!=='verifying')throw new TokenError('invalid_grant');
        if(accountId)completed.accountId=accountId;
        if(accountId&&!consentCurrent(draft,clientId,accountId,completed.revision)){completed.status='failed';return {error:'invalid_grant'};}
        if(completed.expiresAt<=now()){completed.status='expired';return {error:'expired_token'};}
        if((!challenge&&!decision)||(challenge&&!correct&&completed.attempts>=maxCodeAttempts)){completed.status='failed';return {error:'invalid_grant'};}
        if(decision?.scopes)completed.scopes=[...new Set(decision.scopes)];
        if(decision?.challenge){completed.challengeId=decision.challenge.id;completed.sentTo=Object.values(credentials).some(value=>decision!.challenge!.sentTo.includes(value))?'The company sent a one-time code.':decision.challenge.sentTo;}
        if((!challenge&&decision?.challenge)||(challenge&&!correct)){completed.status='pending';return {error:'code_required',sign_in_id:id,sent_to:completed.sentTo,expires_in:Math.ceil((completed.expiresAt-now())/1000)};}
        const result=issueSignIn(draft,clientId,completed.accountId!,completed.scopes,proof?.jkt??'',completed.resource??undefined);completed.status='complete';completed.grantId=result.grantId;return result.body;
      });
      return json('error' in body?400:200,body);
    } finally {for(const name of Object.keys(credentials))delete credentials[name];for(const name of config.fields.map(field=>field.name))params.delete(name);params.delete('one_time_code');oneTimeCode='';}
  }

  async function accountToken(request: Request, params: Map<string, string>): Promise<Response> {
    const { clientId, clientAssertion } = clientCredentials(params);
    const grantType = params.get('grant_type'), code = params.get('code'), refresh = params.get('refresh_token');
    const verifier = params.get('code_verifier'), redirect = params.get('redirect_uri'), resource = params.get('resource');
    if (params.has('session_id') || params.has('assertion')) throw new TokenError('invalid_request');
    if (resource !== undefined && !resources.includes(resource)) throw new TokenError('invalid_target');
    if (grantType === 'authorization_code' && (!code || !verifier || !redirect || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier))) throw new TokenError('invalid_request');
    if (grantType === 'refresh_token' && !refresh) throw new TokenError('invalid_request');
    const state = await read();
    const proof = isBearerResource(resource) ? null : await verifyDpopProof(request.headers.get('dpop'), { method: 'POST', url: options.tokenEndpoint, nowMs: now() });
    if (proof && requireNonce && !state.nonces.some(nonce => nonce.value === proof.claims.nonce && nonce.expiresAt > now())) throw new TokenError('use_dpop_nonce', { 'DPoP-Nonce': await currentNonce(state) });
    const { client, keys } = await authenticateClient(clientId, clientAssertion);
    if (proof) for (const key of keys().keys) if (await calculateJwkThumbprint(key).catch(() => null) === proof.jkt) throw new TokenError('invalid_dpop_proof');
    const replayKey = `assertion ${clientId} ${client.jti}`, proofKey = proof ? `proof ${proof.jkt} ${proof.claims.jti}` : null;
    const body = await commit({kind:'token',clientId,sessionKey:'',...(code ? {codeHash:tokenHash(code)} : {}),...(refresh ? {refreshHash:tokenHash(refresh)} : {}),replayKeys:[replayKey,...(proofKey ? [proofKey] : [])],at:now()}, draft => {
      const at = now();
      if (draft.generation !== state.generation || !current(client)) throw new TokenError('invalid_client');
      if ((own(draft.replay,replayKey) ?? 0) > at) throw new TokenError('invalid_client');
      consumeReplay(draft,replayKey,client.exp*1000);
      if (proof && proofKey) {
        if ((proof.claims.iat + PROOF_WINDOW_SECONDS)*1000 <= at || (own(draft.replay,proofKey) ?? 0) > at) throw new TokenError('invalid_dpop_proof');
        consumeReplay(draft,proofKey,(proof.claims.iat+PROOF_WINDOW_SECONDS)*1000);
      }
      if (grantType === 'authorization_code') {
        const row = own(draft.codes,tokenHash(code!));
        if (!row || row.sessionKey === undefined || row.clientId !== clientId || row.expiresAt <= at || (row.sessionKey !== null && row.sessionKey !== proof?.jkt)) throw new TokenError('invalid_grant');
        if (row.grantId !== null) { revokeGrant(draft,row.grantId); return null; }
        if (row.redirectUri !== redirect || tokenHash(verifier!) !== row.codeChallenge || !consentCurrent(draft,clientId,row.accountId,row.revision)) throw new TokenError('invalid_grant');
        const issued=issueSignIn(draft,clientId,row.accountId,row.scopes,proof?.jkt??'',resource);row.grantId=issued.grantId;return issued.body;
      }
      const hash=tokenHash(refresh!),grantId=own(draft.refreshTokens,hash),grant=grantId?own(draft.grants,grantId):undefined;
      if(grant&&grant.clientId===clientId&&grant.refreshHash!==hash){revokeGrant(draft,grantId!);return null;}
      if(!grant||!grantLive(grant,at)||grant.clientId!==clientId)throw new TokenError('invalid_grant');
      const token=random(32);
      if(params.has('scope'))signInScopes(params.get('scope'),grant.scopes);
      grant.previousHash=grant.refreshHash;grant.refreshHash=tokenHash(token);
      const scopes = grantType === 'refresh_token' && params.has('scope') ? signInScopes(params.get('scope'),grant.scopes) : [...grant.scopes];
      draft.refreshTokens[grant.refreshHash] = grantId!;
      const access = random(32);
      draft.accessTokens[tokenHash(access)] = {clientId,accountId:grant.accountId,sessionId:'',grantId:grantId!,scopes,resource:resource ?? null,jkt:proof?.jkt ?? '',expiresAt:at+lifetimeMs};
      return {access_token:access,token_type:proof ? 'DPoP' : 'Bearer',expires_in:lifetimeSeconds,refresh_token:token,refresh_token_expires_in:Math.floor((grant.expiresAt-at)/1000),scope:scopes.join(' ')};
    });
    if (body === null) throw new TokenError('invalid_grant');
    return json(200,body);
  }

  async function issue(request: Request): Promise<Response> {
    const params = await readParams(request);
    const grantType = params.get('grant_type');
    if (!grantType) throw new TokenError('invalid_request');
    if (grantType === DEVICE_GRANT) return pollDevice(request, params);
    if (grantType === MEDIATED_GRANT) return mediatedSignIn(request, params);
    if (grantType === 'authorization_code' || grantType === 'refresh_token') return accountToken(request, params);
    throw new TokenError('unsupported_grant_type');
  }

  // RFC 7009 with private_key_jwt client authentication; unknown and foreign tokens succeed without changing any grant.
  async function revokeToken(request: Request): Promise<Response> {
    const params = await readParams(request);
    const { clientId, clientAssertion } = clientCredentials(params);
    const token = params.get('token');
    if (!token) throw new TokenError('invalid_request');
    const { generation } = await read();
    const { client } = await authenticateClient(clientId, clientAssertion);
    await commit({ kind: 'revoke', refreshHash: tokenHash(token), replayKey: `assertion ${clientId} ${client.jti}` }, draft => {
      if (draft.generation !== generation) return; // reset already removed every grant
      const at = now();
      if (client.exp * 1000 <= at) throw new TokenError('invalid_client');
      prune(draft, at);
      const replayKey = `assertion ${clientId} ${client.jti}`;
      if (own(draft.replay, replayKey) !== undefined) throw new TokenError('invalid_client');
      draft.replay[replayKey] = client.exp * 1000;
      // A rotated token still names its lineage, so revoking it after a lost rotation response ends the successor too.
      const grantId = own(draft.refreshTokens, tokenHash(token));
      if (grantId !== undefined && own(draft.grants, grantId)?.clientId === clientId) revokeGrant(draft, grantId);
    });
    return new Response(null, { status: 200, headers: { 'cache-control': 'no-store' } });
  }

  async function respond(request: Request, handler: (request: Request) => Promise<Response>): Promise<Response> {
    try { return await handler(request); } catch (error) {
      // Early rejects leave the body unread; release the stream instead of leaving it open.
      if (!request.bodyUsed) await request.body?.cancel().catch(() => {});
      const code = error instanceof TokenError || error instanceof AuthorityError ? error.code : undefined;
      if (!code) throw error;
      const status = code === 'invalid_client' || code === 'invalid_token' ? 401 : code === 'rate_limited' ? 429 : code === 'sign_in_not_found' ? 404 : code === 'temporarily_unavailable' ? 503 : 400;
      return json(status,{error:code==='rate_limited'?'temporarily_unavailable':code},{...(code==='rate_limited'?{'Retry-After':'60'}:code==='temporarily_unavailable'?{'Retry-After':'5'}:{}),...(error instanceof TokenError?error.headers:{})});
    }
  }

  // Plain checks over one issuer snapshot; only the policy wrappers below take the coordinator, once.
  function liveGrant(state: IssuerState, principal: Principal): boolean {
    if (principal.accountId === undefined && principal.grantId === undefined) return true;
    const grant = principal.grantId === undefined ? undefined : own(state.grants, principal.grantId);
    return grantLive(grant, now()) && grant!.clientId === principal.clientId && grant!.accountId === principal.accountId;
  }
  function requireScopes(granted: readonly string[], scopes: readonly string[]): void {
    if (!scopes.every(scope => granted.includes(scope))) throw new AuthorityError('insufficient_scope', { scope: scopes.join(' ') });
  }
  // Order: coordinator -> issuer snapshot -> caller's conversation transaction, released in run's finally.
  const policy: AuthorityPolicy = {
    withCurrent: (principal, scopes, action) => options.coordinator.run(async () => {
      const state = await read({ kind: 'principal', sessionId: principal.sessionId, ...(principal.grantId ? { grantId: principal.grantId } : {}) });
      if (principal.issuer !== issuer || principal.issuerGeneration !== state.generation || principal.tokenExpiresAt <= now() || !liveGrant(state,principal)) throw new AuthorityError('invalid_token');
      requireScopes(principal.scopes, scopes);
      return action();
    }),
    withAccepted: (authority, scopes, action) => options.coordinator.run(async () => {
      const { principal } = authority;
      const state = await read({ kind: 'principal', sessionId: principal.sessionId, ...(principal.grantId ? { grantId: principal.grantId } : {}) });
      // Admission token expiry is ignored: accepted work outlives its token. A reset (new generation) never is.
      if (principal.issuer !== issuer || principal.issuerGeneration !== state.generation) throw new AuthorityError('invalid_token');
      if (authority.revocationPolicy !== 'allow-accepted-work-to-finish' && !liveGrant(state, principal)) throw new AuthorityError('invalid_token');
      // The ceiling is the accepted scopes; a later, broader sign-in never widens old work.
      requireScopes(principal.scopes, scopes);
      return action();
    }),
  };

  return {
    token: request => respond(request, issue),
    revoke: request => respond(request, revokeToken),
    deviceAuthorization: request => respond(request, startDevice),
    async beginDeviceAuthorization(userCode, browserBinding) {
      if (!options.device || typeof userCode !== 'string' || typeof browserBinding !== 'string' || browserBinding.length < 22) throw new AuthorizationError('invalid_request');
      const id = tokenHash(userCode), selection: IssuerSelection = { kind: 'sign_in', ids: [id], replayKeys: [], at: now() };
      const state = await read(selection), record = own(state.signIns, id);
      if (!record || record.kind !== 'device' || record.status !== 'pending' || record.expiresAt <= now()) throw new AuthorizationError('invalid_request');
      const client = await metadata.resolveClient(record.clientId);
      return commit(selection, draft => {
        const current = own(draft.signIns, id);
        if (!current || current.kind !== 'device' || current.status !== 'pending' || current.expiresAt <= now()) throw new AuthorizationError('invalid_request');
        current.browserHash = tokenHash(browserBinding);
        return { id: userCode, clientId: current.clientId, clientName: client.client_name, scopes: [...current.scopes], expiresAt: current.expiresAt };
      });
    },
    async completeDeviceAuthorization(userCode, browserBinding, decision) {
      if (!options.device || typeof userCode !== 'string' || typeof browserBinding !== 'string') throw new AuthorizationError('invalid_request');
      const id = tokenHash(userCode);
      const snapshot = await read({ kind: 'sign_in', ids: [id], replayKeys: [], at: now() }), found = own(snapshot.signIns, id);
      if (!found || found.kind !== 'device') throw new AuthorizationError('invalid_request');
      const accountId = 'accountId' in decision && typeof decision.accountId === 'string' ? decision.accountId : undefined;
      await commit({ kind: 'sign_in', ids: [id, ...(accountId ? [accountRevisionKey(found.clientId, accountId)] : [])], replayKeys: [], at: now() }, draft => {
        const record = own(draft.signIns, id);
        if (!record || record.kind !== 'device' || record.status !== 'pending' || record.expiresAt <= now() || record.browserHash !== tokenHash(browserBinding)) throw new AuthorizationError('invalid_request');
        if ('denied' in decision && decision.denied) { record.status = 'denied'; return; }
        const { accountId, scopes } = decision as { accountId: string; scopes: string[] };
        if (typeof accountId !== 'string' || !accountId || !Array.isArray(scopes) || !scopes.length || !scopes.every(scope => record.scopes.includes(scope))) throw new TypeError('decision');
        if (!consentCurrent(draft, record.clientId, accountId, record.revision)) throw new AuthorizationError('invalid_request');
        record.accountId = accountId; record.scopes = [...new Set(scopes)]; record.status = 'approved';
      });
    },

    // Validates the whole request before persisting anything; the host renders login and consent from the view.
    // Unauthenticated: hosts must rate-limit their /authorize route; the pending cap only bounds state and coordinator time.
    async beginAuthorization(request, browserBinding) {
      if (!options.authorizationResultCipher) throw new TypeError('authorizationResultCipher is required for Direct Sign-In');
      if (typeof browserBinding !== 'string' || !browserBinding) throw new TypeError('browserBinding');
      const params = uniqueParams(new URL(request.url).searchParams, () => new AuthorizationError('invalid_request'));
      const clientId = params.get('client_id'); const redirectUri = params.get('redirect_uri');
      if (!clientId || !redirectUri) throw new AuthorizationError('invalid_request');
      const { generation } = await read();
      let client;
      try { client = await metadata.resolveClient(clientId); } catch { throw new AuthorizationError('invalid_client'); }
      if (!registeredRedirect(redirectUri, client.redirect_uris ?? [], clientId)) throw new AuthorizationError('invalid_request');
      const state = params.get('state');
      const fail = (code: string) => new AuthorizationError(code, new URL(callback(redirectUri, { error: code, ...(state ? { state } : {}), iss: issuer })));
      if (params.get('response_type') !== 'code') throw fail('unsupported_response_type');
      if (!state || state.length > 512) throw fail('invalid_request');
      const codeChallenge = params.get('code_challenge') ?? '';
      if (params.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) throw fail('invalid_request');
      const sessionKey = params.get('dpop_jkt') ?? null;
      if (sessionKey !== null && !/^[A-Za-z0-9_-]{43}$/.test(sessionKey)) throw fail('invalid_request');
      const scopes = [...new Set((params.get('scope') ?? '').split(' ').filter(Boolean))];
      if (!scopes.length || !scopes.every(scope => options.supportedScopes.includes(scope))) throw fail('invalid_scope');
      // resource is accepted and ignored here: grants cover every resource, and each token request selects one (spec 4.3).
      const resource = params.get('resource');
      if (resource !== undefined && !resources.includes(resource)) throw fail('invalid_target');
      return commit({ kind: 'authorize', clientId, at: now() }, draft => {
        if (draft.generation !== generation) throw new AuthorizationError('invalid_request');
        const at = now(); prune(draft, at);
        // shortcut: an unauthenticated caller can fill one client's slots for AUTHORIZATION_MS (10 minutes); hosts must rate-limit /authorize.
        const pending = Object.values(draft.authorizations).filter(record => !record.completion);
        if ((draft.limits?.pending ?? pending.length) >= maxPending || (draft.limits?.pendingForClient ?? pending.filter(record => record.clientId === clientId).length) >= maxPendingPerClient) throw fail('temporarily_unavailable');
        const id = random(16); const expiresAt = at + AUTHORIZATION_MS;
        draft.authorizations[id] = { sessionKey, clientId, redirectUri, state, codeChallenge, scopes, browserHash: tokenHash(browserBinding), expiresAt, revision: revision(draft, clientRevisionKey(clientId)) };
        return { id, clientId, clientName: client.client_name, scopes, expiresAt };
      });
    },

    // Commit once; a bound identical decision can recover the encrypted callback without minting another code.
    async completeAuthorization(id, browserBinding, decision) {
      const cipher = options.authorizationResultCipher;
      if (!cipher) throw new TypeError('authorizationResultCipher is required for Direct Sign-In');
      if (typeof id !== 'string' || typeof browserBinding !== 'string') throw new AuthorizationError('invalid_request');
      const snapshot = own((await read({ kind: 'authorization', id })).authorizations, id);
      const accountId = 'accountId' in decision && typeof decision.accountId === 'string' ? decision.accountId : undefined;
      const href = await commit({ kind: 'authorization', id, ...(snapshot && accountId ? { revocationKey: accountRevisionKey(snapshot.clientId, accountId) } : {}) }, draft => {
        const record = own(draft.authorizations, id);
        if (!record || record.sessionKey === undefined || record.expiresAt <= now() || record.browserHash !== tokenHash(browserBinding)) throw new AuthorizationError('invalid_request');
        const denied = 'denied' in decision && decision.denied === true;
        const { accountId, scopes } = decision as { accountId: unknown; scopes: unknown };
        // Partial consent narrows; the host may never grant more than was requested.
        if (!denied && (typeof accountId !== 'string' || !accountId || !Array.isArray(scopes) || !scopes.length || !scopes.every(scope => record.scopes.includes(scope)))) throw new TypeError('decision');
        if (!denied && !consentCurrent(draft, record.clientId, accountId as string, record.revision)) throw new AuthorizationError('invalid_request');
        const granted = denied ? [] : [...new Set(scopes as string[])].sort();
        const decisionHash = tokenHash(JSON.stringify(denied ? { denied: true } : { accountId, scopes: granted }));
        if (record.completion) {
          if (record.completion.decisionHash !== decisionHash) throw new AuthorizationError('invalid_request');
          return cipher.open(record.completion.callback);
        }
        const fields = { state: record.state, iss: issuer };
        if (denied) {
          const href = callback(record.redirectUri, { error: 'access_denied', ...fields });
          record.completion = { decisionHash, callback: cipher.seal(href) }; return href;
        }
        const code = random(32);
        record.expiresAt = Math.min(record.expiresAt, now() + CODE_MS);
        draft.codes[tokenHash(code)] = { sessionKey: record.sessionKey, clientId: record.clientId, redirectUri: record.redirectUri, codeChallenge: record.codeChallenge, accountId: accountId as string, scopes: granted, expiresAt: record.expiresAt, grantId: null, revision: record.revision };
        const href = callback(record.redirectUri, { code, ...fields });
        record.completion = { decisionHash, callback: cipher.seal(href) }; return href;
      });
      return new URL(href);
    },

    authorizationMetadata() {
      return {
        issuer, token_endpoint: options.tokenEndpoint, revocation_endpoint: options.revocationEndpoint,
        ...(options.authorizationEndpoint ? { authorization_endpoint: options.authorizationEndpoint, response_types_supported: ['code'], code_challenge_methods_supported: ['S256'] } : {}),
        ...(options.device ? { device_authorization_endpoint: options.device.endpoint } : {}),
        dpop_signing_alg_values_supported: ['ES256'], token_endpoint_auth_signing_alg_values_supported: [...ASSERTION_ALGORITHMS], client_id_metadata_document_supported: true,
        protected_resources: [...options.protectedResources],
        grant_types_supported: ['refresh_token', ...(options.mediated?[MEDIATED_GRANT]:[]), ...(options.authorizationEndpoint ? ['authorization_code'] : []), ...(options.device ? [DEVICE_GRANT] : [])],
        scopes_supported: [...options.supportedScopes],
      };
    },
    authority: {
      issuer,
      revocationVisibility: 'immediate: every introspection and policy check reads the shared issuer store; policy checks are ordered by the shared coordinator',
      async introspect(token, resource) {
        const state = await read({kind:'access',hash:tokenHash(token)}), record = own(state.accessTokens,tokenHash(token));
        if (!record || !record.grantId || record.expiresAt <= now() || record.resource !== (resource ?? null)) throw new AuthorityError('invalid_token');
        const grant = own(state.grants,record.grantId);
        if (!grantLive(grant,now()) || (record.clientId !== undefined && record.clientId !== grant!.clientId) || (record.accountId !== undefined && record.accountId !== grant!.accountId)) throw new AuthorityError('invalid_token');
        return {principal:{issuer,clientId:grant!.clientId,userId:'',sessionId:'',accountId:grant!.accountId,grantId:record.grantId,scopes:[...record.scopes],tokenExpiresAt:record.expiresAt,sessionVersion:0,issuerGeneration:state.generation},dpopJkt:record.jkt || null};
      },
      policy,
    },
    // The User disconnected this Personal Agent: revoke its grants for the account and sign out their Sessions (spec 4.9).
    // Its codes for the account go too, so none consented before can sign in again; pending authorizations name no account until consent.
    disconnect: (clientId, accountId) => commit({ kind: 'disconnect', clientId, accountId }, draft => {
      for (const [grantId, grant] of Object.entries(draft.grants)) if (grant.clientId === clientId && grant.accountId === accountId) revokeGrant(draft, grantId);
      for (const [key, code] of Object.entries(draft.codes)) if (code.clientId === clientId && code.accountId === accountId) delete draft.codes[key];
      for (const [key, record] of Object.entries(draft.signIns)) if ((record.kind === 'device' || record.kind === 'mediated') && record.clientId === clientId && record.accountId === accountId) delete draft.signIns[key];
      const next = revision(draft, clientRevisionKey(clientId)) + 1;
      if (!Number.isSafeInteger(next)) throw new TokenError('temporarily_unavailable');
      // Retain account fences until explicit issuer reset; unrelated users sharing a client remain unaffected.
      draft.signIns[clientRevisionKey(clientId)] = { kind: 'revision', clientId, revision: next, expiresAt: Number.MAX_SAFE_INTEGER };
      draft.signIns[accountRevisionKey(clientId, accountId)] = { kind: 'revision', clientId, accountId, revision: next, expiresAt: Number.MAX_SAFE_INTEGER };
    }),
  };
}
