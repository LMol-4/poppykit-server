import { createHash, randomBytes } from 'node:crypto';
import { calculateJwkThumbprint, compactVerify, createLocalJWKSet, errors } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { parseAssertionClaims } from '../protocol/wire.js';
import type { AssertionClaims } from '../protocol/wire.js';
import type { MetadataResolver } from '../network/discovery.js';
import { secureUrl } from '../network/transport.js';
import { AuthorityError } from '../auth/authority.js';
import type { AuthorityCoordinator, AuthorityPolicy, ExternalAuthorityAdapter, Principal } from '../auth/authority.js';
import { CLOCK_SKEW_SECONDS, PROOF_WINDOW_SECONDS, verifyDpopProof } from '../auth/dpop.js';

export interface StateStore<State> {
  read(): Promise<State>;
  transaction<T>(change: (draft: State) => T): Promise<T>;
}
// accountId is sticky (spec 4.4): it stays after sign-out; grantId is the active sign-in, null when signed out.
// version only fills Principal.sessionVersion: it is never bumped, since a Session ends by deletion, which the policy already checks.
interface SessionRecord { clientId: string; userId: string; version: number; createdAt: number; expiresAt: number; accountId: string | null; grantId: string | null }
// Stable lineage of one account sign-in; the ID survives Account Token rotation and expiresAt never moves.
interface GrantRecord { clientId: string; userId: string; accountId: string; scopes: string[]; expiresAt: number; revoked: boolean; refreshHash: string; previousHash: string }
interface AccessTokenRecord { sessionId: string; grantId: string | null; scopes: string[]; resource: string | null; jkt: string; expiresAt: number }
interface AuthorizationRecord { clientId: string; redirectUri: string; state: string; codeChallenge: string; scopes: string[]; browserHash: string; expiresAt: number }
// grantId is set once the code is exchanged, so a second use can revoke what the first produced (RFC 6749 4.1.2).
interface CodeRecord { clientId: string; redirectUri: string; codeChallenge: string; accountId: string; scopes: string[]; expiresAt: number; grantId: string | null }
// Plain JSON. Tokens and codes are keyed by SHA-256 hash; plaintext tokens are never stored.
export interface IssuerState {
  version: 2;
  generation: string;
  sessions: Record<string, SessionRecord>;
  grants: Record<string, GrantRecord>;
  refreshTokens: Record<string, string>; // Account Token hash -> grant ID, current and previous only
  authorizations: Record<string, AuthorizationRecord>;
  codes: Record<string, CodeRecord>;
  accessTokens: Record<string, AccessTokenRecord>;
  replay: Record<string, number>; // assertion/proof jti key -> retain until (ms)
  nonces: { value: string; expiresAt: number }[];
}
export interface ReferenceIssuerOptions {
  issuer: string; tokenEndpoint: string; revocationEndpoint: string; authorizationEndpoint?: string;
  poppyDomains: string[]; directScopes: string[];
  resources?: string[]; // exact supported resource identifiers; absent resource means default
  metadata: MetadataResolver;
  store: StateStore<IssuerState>;
  coordinator: AuthorityCoordinator; // deployment-wide, shared with conversation work and reset
  now: () => number;
  tokenLifetimeSeconds?: number; // default 3600
  accountLifetimeSeconds?: number; // default 2592000, rotation never extends it
  requireDpopNonce?: boolean; // default true at token endpoint
  maxPendingAuthorizations?: number; // default 1000; begin refuses more with temporarily_unavailable
}
export interface AuthorizationView { id: string; clientId: string; clientName: string; scopes: string[]; expiresAt: number }
export type AuthorizationDecision = { accountId: string; scopes: string[] } | { denied: true };
export interface ReferenceIssuer {
  token(request: Request): Promise<Response>;
  revoke(request: Request): Promise<Response>;
  beginAuthorization(request: Request, browserBinding: string): Promise<AuthorizationView>;
  completeAuthorization(id: string, browserBinding: string, decision: AuthorizationDecision): Promise<URL>;
  authorizationMetadata(): Record<string, unknown>;
  authority: ExternalAuthorityAdapter;
  disconnect(clientId: string, accountId: string): Promise<void>;
}
// Authorization request failure for the host's sign-in page. redirectTo is set only once client and redirect_uri are verified;
// without it the host shows an error page and never redirects (RFC 6749 4.1.2.1).
export class AuthorizationError extends Error {
  constructor(readonly code: string, readonly redirectTo?: URL) { super(`Authorization failed: ${code}`); this.name = 'AuthorizationError'; }
}

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ASSERTION_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'RS256', 'PS256', 'EdDSA'];
const NONCE_SECONDS = 300;
const MAX_FORM_BYTES = 65536;
const AUTHORIZATION_MS = 600_000;
const CODE_MS = 60_000;
// A Session ends a day after the last token issued for it (spec 4.2: the Company decides how long a Session lasts).
const SESSION_IDLE_SECONDS = 86_400;

const random = (bytes: number) => randomBytes(bytes).toString('base64url');
const tokenHash = (token: string) => createHash('sha256').update(token).digest('base64url');
const own = <T>(record: Record<string, T>, key: string): T | undefined => Object.hasOwn(record, key) ? record[key] : undefined;
const grantLive = (grant: GrantRecord | undefined, at: number) => !!grant && !grant.revoked && grant.expiresAt > at;
function callback(redirectUri: string, fields: Record<string, string>): string {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(fields)) url.searchParams.set(name, value);
  return url.href;
}

// Shape changes bump the version; other versions are refused instead of misread.
function checked(state: IssuerState): IssuerState {
  if (state.version !== 2) throw new Error('unsupported issuer state version');
  return state;
}

export function initialIssuerState(): IssuerState {
  return { version: 2, generation: random(16), sessions: {}, grants: {}, refreshTokens: {}, authorizations: {}, codes: {}, accessTokens: {}, replay: {}, nonces: [] };
}

class TokenError extends Error {
  constructor(readonly code: string, readonly nonce?: string) { super(`Token request failed: ${code}`); this.name = 'TokenError'; }
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
  const positive = (value: number | undefined, fallback: number, name: string) => {
    const result = value ?? fallback;
    if (!Number.isSafeInteger(result) || result <= 0) throw new TypeError(name);
    return result;
  };
  const lifetimeSeconds = positive(options.tokenLifetimeSeconds, 3600, 'tokenLifetimeSeconds');
  const lifetimeMs = lifetimeSeconds * 1000;
  const accountLifetimeMs = positive(options.accountLifetimeSeconds, 2_592_000, 'accountLifetimeSeconds') * 1000;
  const maxPending = positive(options.maxPendingAuthorizations, 1000, 'maxPendingAuthorizations');
  const sessionMs = Math.max(SESSION_IDLE_SECONDS, lifetimeSeconds) * 1000;
  const requireNonce = options.requireDpopNonce ?? true;
  const resources = options.resources ?? [];
  // Every issuer mutation is ordered with conversation work by the shared coordinator.
  const read = async () => checked(await store.read());
  const commit = <T>(change: (draft: IssuerState) => T) => options.coordinator.run(() => store.transaction(draft => change(checked(draft))));

  // Reuse the current nonce while it has more than half its life left, so challenges cannot grow state.
  async function currentNonce(state: IssuerState): Promise<string> {
    const fresh = state.nonces.find(nonce => nonce.expiresAt - now() > NONCE_SECONDS * 500);
    if (fresh) return fresh.value;
    return commit(draft => {
      const value = random(16);
      draft.nonces = [...draft.nonces.filter(nonce => nonce.expiresAt > now()), { value, expiresAt: now() + NONCE_SECONDS * 1000 }].slice(-2);
      return value;
    });
  }

  async function verifyAssertion(jwt: string, keys: JSONWebKeySet): Promise<AssertionClaims> {
    const { payload, protectedHeader } = await compactVerify(jwt, createLocalJWKSet(keys), { algorithms: ASSERTION_ALGORITHMS });
    // Media types are case-insensitive and may carry the application/ prefix (RFC 7515 4.1.9).
    if (protectedHeader.typ?.toLowerCase().replace(/^application\//, '') === 'poppy-browser+jwt') throw new TypeError('browser assertion'); // spec 5: not accepted here
    return parseAssertionClaims(JSON.parse(new TextDecoder().decode(payload)));
  }
  const current = (claims: AssertionClaims) => claims.exp * 1000 > now() && claims.iat <= now() / 1000 + CLOCK_SKEW_SECONDS;

  // Fetches the client's keys and verifies its client assertion (spec 4.1); verify() is reused for the session assertion.
  async function authenticateClient(clientId: string, clientAssertion: string) {
    let jwksUri: string; let keys: JSONWebKeySet;
    try { jwksUri = (await metadata.resolveClient(clientId)).jwks_uri; keys = await metadata.resolveJwks(jwksUri) as unknown as JSONWebKeySet; } catch { throw new TokenError('invalid_client'); }
    let refreshed = false;
    const verify = async (jwt: string) => {
      try { return await verifyAssertion(jwt, keys); } catch (error) {
        if (refreshed || !(error instanceof errors.JWKSNoMatchingKey)) throw error;
        refreshed = true; // one bounded refresh for an unknown kid; the resolver rate-limits it too
        keys = await metadata.resolveJwks(jwksUri, { refresh: true }) as unknown as JSONWebKeySet;
        return verifyAssertion(jwt, keys);
      }
    };
    let client: AssertionClaims;
    try { client = await verify(clientAssertion); } catch { throw new TokenError('invalid_client'); }
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
  }
  // Revoking a grant signs out every Session using it; they continue signed out and stay bound to the account (spec 4.9).
  function revokeGrant(draft: IssuerState, grantId: string): void {
    const grant = own(draft.grants, grantId);
    if (!grant) return;
    grant.revoked = true;
    for (const session of Object.values(draft.sessions)) if (session.grantId === grantId) session.grantId = null;
  }

  async function issue(request: Request): Promise<Response> {
    const params = await readParams(request);
    const grantType = params.get('grant_type');
    if (!grantType) throw new TokenError('invalid_request');
    if (grantType !== JWT_BEARER && grantType !== 'authorization_code' && grantType !== 'refresh_token') throw new TokenError('unsupported_grant_type');
    const { clientId, clientAssertion } = clientCredentials(params);
    const assertion = params.get('assertion'); const code = params.get('code'); const redirectUri = params.get('redirect_uri');
    const codeVerifier = params.get('code_verifier'); const refreshToken = params.get('refresh_token');
    const sessionId = params.get('session_id'); const resource = params.get('resource'); const scope = params.get('scope');
    if (sessionId === '') throw new TokenError('invalid_request');
    // Each grant takes only its own credential, so a stray assertion can never stand in for a code or Account Token.
    if (grantType !== JWT_BEARER && assertion !== undefined) throw new TokenError('invalid_request');
    if (grantType === JWT_BEARER) {
      // A missing assertion is invalid_grant (spec 4.2 error table).
      if (!assertion) throw new TokenError('invalid_grant');
      // Signed-out sessions hold no account scopes.
      if (scope?.trim()) throw new TokenError('invalid_scope');
    } else if (grantType === 'authorization_code') {
      // Direct Sign-In always names the Session to sign in (spec 4.5).
      if (!code || !redirectUri || !codeVerifier || sessionId === undefined) throw new TokenError('invalid_request');
      // RFC 7636 4.1: 43-128 unreserved characters.
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) throw new TokenError('invalid_request');
    } else if (!refreshToken) throw new TokenError('invalid_request');
    // scope narrows only (spec 4.3, 4.8); an empty request asks for nothing and is refused.
    const requested = scope === undefined || grantType === JWT_BEARER ? undefined : [...new Set(scope.split(' ').filter(Boolean))];
    if (requested?.length === 0) throw new TokenError('invalid_scope');
    // Resources are exact configured identifiers, chosen per token request; grants are never narrowed to one.
    if (resource !== undefined && !resources.includes(resource)) throw new TokenError('invalid_target');

    const state = await read(); const generation = state.generation;
    // htu is checked against the configured token endpoint, never the incoming Request URL.
    const proof = await verifyDpopProof(request.headers.get('dpop'), { method: 'POST', url: options.tokenEndpoint, nowMs: now() });
    // Nonce challenge precedes any network fetch and any replay consumption.
    if (requireNonce && !state.nonces.some(nonce => nonce.value === proof.claims.nonce && nonce.expiresAt > now())) throw new TokenError('use_dpop_nonce', await currentNonce(state));

    const { client, verify, keys } = await authenticateClient(clientId, clientAssertion);
    let session: AssertionClaims | undefined;
    if (grantType === JWT_BEARER) {
      try { session = await verify(assertion!); } catch { throw new TokenError('invalid_grant'); }
      if (session.iss !== clientId || session.aud !== issuer || session.sub.length > 256 || !current(session) || session.jti === client.jti) throw new TokenError('invalid_grant');
    }
    // Identity keys and DPoP keys must differ (spec 4.1).
    for (const key of keys().keys) if (await calculateJwkThumbprint(key).catch(() => null) === proof.jkt) throw new TokenError('invalid_dpop_proof');

    const body = await commit(draft => {
      // A reset between verification and commit must not recreate state from a stale verification.
      if (draft.generation !== generation) throw new TokenError('invalid_grant');
      // Re-check freshness at commit time with the same clock used to prune, so a slow fetch cannot outlive its replay entry.
      const at = now();
      if ((proof.claims.iat + PROOF_WINDOW_SECONDS) * 1000 < at) throw new TokenError('invalid_dpop_proof');
      if (client.exp * 1000 <= at) throw new TokenError('invalid_client');
      if (session && session.exp * 1000 <= at) throw new TokenError('invalid_grant');
      prune(draft, at);
      // Client and session assertions share one jti namespace per client.
      const assertions = session ? [client, session] : [client];
      const assertionKeys = assertions.map(claims => `assertion ${clientId} ${claims.jti}`);
      const proofKey = `proof ${proof.jkt} ${proof.claims.jti}`;
      if (assertionKeys.some(key => own(draft.replay, key) !== undefined)) throw new TokenError('invalid_grant');
      if (own(draft.replay, proofKey) !== undefined) throw new TokenError('invalid_dpop_proof');
      assertions.forEach((claims, index) => { draft.replay[assertionKeys[index]] = claims.exp * 1000; });
      draft.replay[proofKey] = (proof.claims.iat + PROOF_WINDOW_SECONDS) * 1000;

      const existing = (userId?: string) => {
        const found = sessionId === undefined ? undefined : own(draft.sessions, sessionId);
        if (!found || !(found.expiresAt > at) || found.clientId !== clientId || (userId !== undefined && found.userId !== userId)) throw new TokenError('invalid_session');
        return found;
      };
      const create = (userId: string): [string, SessionRecord] => {
        const id = `ses_${random(16)}`;
        return [id, draft.sessions[id] = { clientId, userId, version: 1, createdAt: at, expiresAt: at, accountId: null, grantId: null }];
      };
      const accessToken = random(32);
      const grant = (id: string, record: SessionRecord, grantId: string | null, scopes: string[]) => {
        record.expiresAt = at + sessionMs;
        draft.accessTokens[tokenHash(accessToken)] = { sessionId: id, grantId, scopes, resource: resource ?? null, jkt: proof.jkt, expiresAt: at + lifetimeMs };
        return { access_token: accessToken, token_type: 'DPoP', expires_in: lifetimeSeconds, scope: scopes.join(' '), session_id: id, signed_in: grantId !== null };
      };
      // Signs the Session in to the lineage and rotates its Account Token: consume, successor and session update in this one commit.
      const signIn = (id: string, record: SessionRecord, grantId: string) => {
        const lineage = draft.grants[grantId];
        // Sticky account (spec 4.4): a Session once signed in to another account never switches, and no tokens are issued.
        if (record.accountId !== null && record.accountId !== lineage.accountId) throw new TokenError('account_mismatch');
        const scopes = requested ?? lineage.scopes;
        if (!scopes.every(item => lineage.scopes.includes(item))) throw new TokenError('invalid_scope');
        const successor = random(32);
        // Older hashes are forgotten: the previous one is enough to revoke after a lost rotation response.
        delete draft.refreshTokens[lineage.previousHash];
        lineage.previousHash = lineage.refreshHash; lineage.refreshHash = tokenHash(successor); draft.refreshTokens[lineage.refreshHash] = grantId;
        record.accountId = lineage.accountId; record.grantId = grantId;
        return { ...grant(id, record, grantId, scopes), refresh_token: successor, refresh_token_expires_in: Math.floor((lineage.expiresAt - at) / 1000) };
      };

      if (grantType === JWT_BEARER) {
        if (!session) throw new TokenError('invalid_grant');
        if (sessionId === undefined) return grant(...create(session.sub), null, []);
        const record = existing(session.sub);
        // A signed-in Session is renewed with its Account Token instead (spec 4.2).
        if (record.grantId !== null && grantLive(own(draft.grants, record.grantId), at)) throw new TokenError('invalid_grant');
        return grant(sessionId, record, null, []);
      }
      if (grantType === 'authorization_code') {
        const record = own(draft.codes, tokenHash(code!));
        if (!record || record.expiresAt <= at || record.clientId !== clientId) throw new TokenError('invalid_grant');
        if (record.grantId !== null) { revokeGrant(draft, record.grantId); return null; }
        if (record.redirectUri !== redirectUri || tokenHash(codeVerifier!) !== record.codeChallenge) throw new TokenError('invalid_grant');
        const target = existing();
        const grantId = `grt_${random(16)}`;
        draft.grants[grantId] = { clientId, userId: target.userId, accountId: record.accountId, scopes: record.scopes, expiresAt: at + accountLifetimeMs, revoked: false, refreshHash: '', previousHash: '' };
        record.grantId = grantId;
        return signIn(sessionId!, target, grantId);
      }
      const presented = tokenHash(refreshToken!);
      const grantId = own(draft.refreshTokens, presented);
      const lineage = grantId === undefined ? undefined : own(draft.grants, grantId);
      // Reuse of the previous Account Token (e.g. a retry after a lost response) revokes the lineage, so its Sessions
      // continue signed out instead of staying bound to a successor nobody holds (RFC 9700 4.14.2).
      if (lineage && lineage.clientId === clientId && presented === lineage.previousHash) { revokeGrant(draft, grantId!); return null; }
      // A rotated Account Token never issues another successor.
      if (!lineage || !grantLive(lineage, at) || lineage.clientId !== clientId || lineage.refreshHash !== presented) throw new TokenError('invalid_grant');
      return sessionId === undefined ? signIn(...create(lineage.userId), grantId!) : signIn(sessionId, existing(lineage.userId), grantId!);
    });
    // A reused code or previous Account Token revoked its lineage in the commit above.
    if (body === null) throw new TokenError('invalid_grant');
    return json(200, body);
  }

  // RFC 7009 with private_key_jwt client authentication; unknown and foreign tokens succeed without changing any grant.
  async function revokeToken(request: Request): Promise<Response> {
    const params = await readParams(request);
    const { clientId, clientAssertion } = clientCredentials(params);
    const token = params.get('token');
    if (!token) throw new TokenError('invalid_request');
    const { generation } = await read();
    const { client } = await authenticateClient(clientId, clientAssertion);
    await commit(draft => {
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
      return json(code === 'invalid_client' ? 401 : 400, { error: code }, error instanceof TokenError && error.nonce ? { 'DPoP-Nonce': error.nonce } : {});
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
      const state = await read();
      const session = own(state.sessions, principal.sessionId);
      if (principal.issuer !== issuer || principal.issuerGeneration !== state.generation || !session || session.clientId !== principal.clientId
        || session.userId !== principal.userId || !liveGrant(state, principal)) throw new AuthorityError('invalid_token');
      requireScopes(principal.scopes, scopes);
      return action();
    }),
    withAccepted: (authority, scopes, action) => options.coordinator.run(async () => {
      const state = await read();
      const { principal } = authority;
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

    // Validates the whole request before persisting anything; the host renders login and consent from the view.
    // Unauthenticated: hosts must rate-limit their /authorize route; the pending cap only bounds state and coordinator time.
    async beginAuthorization(request, browserBinding) {
      if (typeof browserBinding !== 'string' || !browserBinding) throw new TypeError('browserBinding');
      const params = uniqueParams(new URL(request.url).searchParams, () => new AuthorizationError('invalid_request'));
      const clientId = params.get('client_id'); const redirectUri = params.get('redirect_uri');
      if (!clientId || !redirectUri) throw new AuthorizationError('invalid_request');
      const { generation } = await read();
      let client;
      try { client = await metadata.resolveClient(clientId); } catch { throw new AuthorizationError('invalid_client'); }
      // Exact string match against the client's metadata (spec 4.5).
      if (!client.redirect_uris.includes(redirectUri)) throw new AuthorizationError('invalid_request');
      const state = params.get('state');
      const fail = (code: string) => new AuthorizationError(code, new URL(callback(redirectUri, { error: code, ...(state ? { state } : {}), iss: issuer })));
      if (params.get('response_type') !== 'code') throw fail('unsupported_response_type');
      if (!state || state.length > 512) throw fail('invalid_request');
      const codeChallenge = params.get('code_challenge') ?? '';
      if (params.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) throw fail('invalid_request');
      const scopes = [...new Set((params.get('scope') ?? '').split(' ').filter(Boolean))];
      if (!scopes.length || !scopes.every(scope => options.directScopes.includes(scope))) throw fail('invalid_scope');
      // resource is accepted and ignored here: grants cover every resource, and each token request selects one (spec 4.3).
      const resource = params.get('resource');
      if (resource !== undefined && !resources.includes(resource)) throw fail('invalid_target');
      return commit(draft => {
        if (draft.generation !== generation) throw new AuthorizationError('invalid_request');
        const at = now(); prune(draft, at);
        if (Object.keys(draft.authorizations).length >= maxPending) throw fail('temporarily_unavailable');
        const id = random(16); const expiresAt = at + AUTHORIZATION_MS;
        draft.authorizations[id] = { clientId, redirectUri, state, codeChallenge, scopes, browserHash: tokenHash(browserBinding), expiresAt };
        return { id, clientId, clientName: client.client_name, scopes, expiresAt };
      });
    },

    // Consumes the authorization once; the browser binding is checked before deny as well as approve.
    async completeAuthorization(id, browserBinding, decision) {
      if (typeof id !== 'string' || typeof browserBinding !== 'string') throw new AuthorizationError('invalid_request');
      const href = await commit(draft => {
        const record = own(draft.authorizations, id);
        if (!record || record.expiresAt <= now() || record.browserHash !== tokenHash(browserBinding)) throw new AuthorizationError('invalid_request');
        const fields = { state: record.state, iss: issuer };
        if ('denied' in decision && decision.denied === true) { delete draft.authorizations[id]; return callback(record.redirectUri, { error: 'access_denied', ...fields }); }
        const { accountId, scopes } = decision as { accountId: unknown; scopes: unknown };
        // Partial consent narrows; the host may never grant more than was requested.
        if (typeof accountId !== 'string' || !accountId || !Array.isArray(scopes) || !scopes.length || !scopes.every(scope => record.scopes.includes(scope))) throw new TypeError('decision');
        delete draft.authorizations[id];
        const code = random(32);
        draft.codes[tokenHash(code)] = { clientId: record.clientId, redirectUri: record.redirectUri, codeChallenge: record.codeChallenge, accountId, scopes: [...new Set(scopes as string[])], expiresAt: now() + CODE_MS, grantId: null };
        return callback(record.redirectUri, { code, ...fields });
      });
      return new URL(href);
    },

    authorizationMetadata() {
      return {
        issuer, token_endpoint: options.tokenEndpoint, revocation_endpoint: options.revocationEndpoint,
        ...(options.authorizationEndpoint ? { authorization_endpoint: options.authorizationEndpoint, response_types_supported: ['code'], code_challenge_methods_supported: ['S256'] } : {}),
        dpop_signing_alg_values_supported: ['ES256'], client_id_metadata_document_supported: true,
        poppy_domains: [...options.poppyDomains],
      };
    },
    authority: {
      issuer,
      revocationVisibility: 'immediate: every introspection and policy check reads the shared issuer store; policy checks are ordered by the shared coordinator',
      async introspect(token, resource) {
        const state = await read(); const at = now();
        const record = own(state.accessTokens, tokenHash(token));
        const session = record && own(state.sessions, record.sessionId);
        if (!record || !session || !(session.expiresAt > at) || record.expiresAt <= at || record.resource !== (resource ?? null)) throw new AuthorityError('invalid_token');
        // A signed-in token stops working once its sign-in is revoked or expires; a signed-out one stays signed out.
        const grant = record.grantId === null ? undefined : own(state.grants, record.grantId);
        if (record.grantId !== null && !grantLive(grant, at)) throw new AuthorityError('invalid_token');
        return {
          principal: {
            issuer, clientId: session.clientId, userId: session.userId, sessionId: record.sessionId,
            ...(grant ? { accountId: grant.accountId, grantId: record.grantId! } : {}),
            scopes: [...record.scopes], tokenExpiresAt: record.expiresAt, sessionVersion: session.version, issuerGeneration: state.generation,
          },
          dpopJkt: record.jkt,
        };
      },
      policy,
    },
    // The User disconnected this Personal Agent: revoke its grants for the account and sign out their Sessions (spec 4.9).
    disconnect: (clientId, accountId) => commit(draft => {
      for (const [grantId, grant] of Object.entries(draft.grants)) if (grant.clientId === clientId && grant.accountId === accountId) revokeGrant(draft, grantId);
    }),
  };
}
