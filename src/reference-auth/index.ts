import { createHash, randomBytes } from 'node:crypto';
import { calculateJwkThumbprint, compactVerify, createLocalJWKSet, errors } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { parseAssertionClaims } from '../protocol/wire.js';
import type { AssertionClaims } from '../protocol/wire.js';
import type { MetadataResolver } from '../network/discovery.js';
import { secureUrl } from '../network/transport.js';
import { AuthorityError } from '../auth/authority.js';
import type { ExternalAuthorityAdapter } from '../auth/authority.js';
import { CLOCK_SKEW_SECONDS, PROOF_WINDOW_SECONDS, verifyDpopProof } from '../auth/dpop.js';

export interface StateStore<State> {
  read(): Promise<State>;
  transaction<T>(change: (draft: State) => T): Promise<T>;
}
interface SessionRecord { clientId: string; userId: string; version: number; createdAt: number }
interface AccessTokenRecord { sessionId: string; scopes: string[]; resource: string | null; jkt: string; expiresAt: number }
// Plain JSON. Token records are keyed by SHA-256 hash; plaintext tokens are never stored.
export interface IssuerState {
  version: 1;
  generation: string;
  sessions: Record<string, SessionRecord>;
  accessTokens: Record<string, AccessTokenRecord>;
  replay: Record<string, number>; // assertion/proof jti key -> retain until (ms)
  nonces: { value: string; expiresAt: number }[];
}
export interface ReferenceIssuerOptions {
  issuer: string; tokenEndpoint: string; revocationEndpoint: string; authorizationEndpoint?: string;
  poppyDomains: string[];
  resources?: string[]; // exact supported resource identifiers; absent resource means default
  metadata: MetadataResolver;
  store: StateStore<IssuerState>;
  now: () => number;
  tokenLifetimeSeconds?: number; // default 3600
  requireDpopNonce?: boolean; // default true at token endpoint
}
export interface ReferenceIssuer {
  token(request: Request): Promise<Response>;
  authorizationMetadata(): Record<string, unknown>;
  authority: Pick<ExternalAuthorityAdapter, 'issuer' | 'revocationVisibility' | 'introspect'>;
}

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ASSERTION_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'RS256', 'PS256', 'EdDSA'];
const NONCE_SECONDS = 300;
const MAX_FORM_BYTES = 65536;

const random = (bytes: number) => randomBytes(bytes).toString('base64url');
const tokenHash = (token: string) => createHash('sha256').update(token).digest('base64url');
const own = <T>(record: Record<string, T>, key: string): T | undefined => Object.hasOwn(record, key) ? record[key] : undefined;

export function initialIssuerState(): IssuerState {
  return { version: 1, generation: random(16), sessions: {}, accessTokens: {}, replay: {}, nonces: [] };
}

class TokenError extends Error {
  constructor(readonly code: string, readonly nonce?: string) { super(`Token request failed: ${code}`); this.name = 'TokenError'; }
}
function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
}

export function createReferenceIssuer(options: ReferenceIssuerOptions): ReferenceIssuer {
  const { issuer, metadata, store, now } = options;
  if (secureUrl(issuer).search) throw new TypeError('issuer');
  secureUrl(options.tokenEndpoint); secureUrl(options.revocationEndpoint);
  const lifetimeSeconds = options.tokenLifetimeSeconds ?? 3600;
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds <= 0) throw new TypeError('tokenLifetimeSeconds');
  const lifetimeMs = lifetimeSeconds * 1000;
  const requireNonce = options.requireDpopNonce ?? true;

  // Reuse the current nonce while it has more than half its life left, so challenges cannot grow state.
  async function currentNonce(state: IssuerState): Promise<string> {
    const fresh = state.nonces.find(nonce => nonce.expiresAt - now() > NONCE_SECONDS * 500);
    if (fresh) return fresh.value;
    return store.transaction(draft => {
      const value = random(16);
      draft.nonces = [...draft.nonces.filter(nonce => nonce.expiresAt > now()), { value, expiresAt: now() + NONCE_SECONDS * 1000 }].slice(-2);
      return value;
    });
  }

  async function verifyAssertion(jwt: string, keys: JSONWebKeySet): Promise<AssertionClaims> {
    const { payload } = await compactVerify(jwt, createLocalJWKSet(keys), { algorithms: ASSERTION_ALGORITHMS });
    return parseAssertionClaims(JSON.parse(new TextDecoder().decode(payload)));
  }
  const current = (claims: AssertionClaims) => claims.exp * 1000 > now() && claims.iat <= now() / 1000 + CLOCK_SKEW_SECONDS;

  async function issue(request: Request): Promise<Response> {
    if (request.method !== 'POST' || !/^application\/x-www-form-urlencoded\s*(;|$)/i.test(request.headers.get('content-type') ?? '')) throw new TokenError('invalid_request');
    // shortcut: body is read before the size check, so the host must also cap request bodies.
    const body = await request.text();
    if (body.length > MAX_FORM_BYTES) throw new TokenError('invalid_request');
    const params = new Map<string, string>();
    for (const [key, value] of new URLSearchParams(body)) { if (params.has(key)) throw new TokenError('invalid_request'); params.set(key, value); }
    const grantType = params.get('grant_type');
    if (!grantType) throw new TokenError('invalid_request');
    // shortcut: refresh_token and authorization_code grants arrive with sign-in (J10).
    if (grantType !== JWT_BEARER) throw new TokenError('unsupported_grant_type');
    const clientId = params.get('client_id'); const clientAssertion = params.get('client_assertion'); const assertion = params.get('assertion');
    if (!clientId || !clientAssertion || params.get('client_assertion_type') !== CLIENT_ASSERTION_TYPE) throw new TokenError('invalid_client');
    if (!assertion) throw new TokenError('invalid_grant');
    const sessionId = params.get('session_id'); const resource = params.get('resource');
    if (sessionId === '') throw new TokenError('invalid_request');
    // Signed-out sessions hold no account scopes; resources are exact configured identifiers.
    if (params.get('scope')?.trim()) throw new TokenError('invalid_scope');
    if (resource !== undefined && !(options.resources ?? []).includes(resource)) throw new TokenError('invalid_target');

    const state = await store.read(); const generation = state.generation;
    // htu is checked against the configured token endpoint, never the incoming Request URL.
    const proof = await verifyDpopProof(request.headers.get('dpop'), { method: 'POST', url: options.tokenEndpoint, nowMs: now() });
    // Nonce challenge precedes any network fetch and any replay consumption.
    if (requireNonce && !state.nonces.some(nonce => nonce.value === proof.claims.nonce && nonce.expiresAt > now())) throw new TokenError('use_dpop_nonce', await currentNonce(state));

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
    let client: AssertionClaims; let session: AssertionClaims;
    try { client = await verify(clientAssertion); } catch { throw new TokenError('invalid_client'); }
    if (client.iss !== clientId || client.sub !== clientId || client.aud !== issuer || !current(client)) throw new TokenError('invalid_client');
    try { session = await verify(assertion); } catch { throw new TokenError('invalid_grant'); }
    if (session.iss !== clientId || session.aud !== issuer || session.sub.length > 256 || !current(session) || session.jti === client.jti) throw new TokenError('invalid_grant');
    // Identity keys and DPoP keys must differ (spec 4.1).
    for (const key of keys.keys) if (await calculateJwkThumbprint(key).catch(() => null) === proof.jkt) throw new TokenError('invalid_dpop_proof');

    const accessToken = random(32); const userId = session.sub;
    const id = await store.transaction(draft => {
      // A reset between verification and commit must not recreate state from a stale verification.
      if (draft.generation !== generation) throw new TokenError('invalid_grant');
      // Re-check freshness at commit time with the same clock used to prune, so a slow fetch cannot outlive its replay entry.
      const issuedAt = now();
      if ((proof.claims.iat + PROOF_WINDOW_SECONDS) * 1000 < issuedAt) throw new TokenError('invalid_dpop_proof');
      if (client.exp * 1000 <= issuedAt) throw new TokenError('invalid_client');
      if (session.exp * 1000 <= issuedAt) throw new TokenError('invalid_grant');
      for (const [key, until] of Object.entries(draft.replay)) if (until < issuedAt) delete draft.replay[key];
      for (const [key, record] of Object.entries(draft.accessTokens)) if (record.expiresAt <= issuedAt) delete draft.accessTokens[key];
      // Client and session assertions share one jti namespace per client.
      const assertionKeys = [client, session].map(claims => `assertion ${clientId} ${claims.jti}`);
      const proofKey = `proof ${proof.jkt} ${proof.claims.jti}`;
      if (assertionKeys.some(key => own(draft.replay, key) !== undefined)) throw new TokenError('invalid_grant');
      if (own(draft.replay, proofKey) !== undefined) throw new TokenError('invalid_dpop_proof');
      draft.replay[assertionKeys[0]] = client.exp * 1000; draft.replay[assertionKeys[1]] = session.exp * 1000;
      draft.replay[proofKey] = (proof.claims.iat + PROOF_WINDOW_SECONDS) * 1000;
      let target = sessionId;
      if (target === undefined) {
        target = `ses_${random(16)}`;
        draft.sessions[target] = { clientId, userId, version: 1, createdAt: issuedAt };
      } else {
        // shortcut: sessions never end in the reference issuer; signed-in renewal checks arrive with J10.
        const existing = own(draft.sessions, target);
        if (!existing || existing.clientId !== clientId || existing.userId !== userId) throw new TokenError('invalid_session');
      }
      draft.accessTokens[tokenHash(accessToken)] = { sessionId: target, scopes: [], resource: resource ?? null, jkt: proof.jkt, expiresAt: issuedAt + lifetimeMs };
      return target;
    });
    return json(200, { access_token: accessToken, token_type: 'DPoP', expires_in: lifetimeSeconds, scope: '', session_id: id, signed_in: false });
  }

  return {
    async token(request) {
      try { return await issue(request); } catch (error) {
        const code = error instanceof TokenError || error instanceof AuthorityError ? error.code : undefined;
        if (!code) throw error;
        return json(code === 'invalid_client' ? 401 : 400, { error: code }, error instanceof TokenError && error.nonce ? { 'DPoP-Nonce': error.nonce } : {});
      }
    },
    authorizationMetadata() {
      return {
        issuer, token_endpoint: options.tokenEndpoint, revocation_endpoint: options.revocationEndpoint,
        ...(options.authorizationEndpoint ? { authorization_endpoint: options.authorizationEndpoint } : {}),
        dpop_signing_alg_values_supported: ['ES256'], client_id_metadata_document_supported: true,
        poppy_domains: [...options.poppyDomains],
      };
    },
    authority: {
      issuer,
      revocationVisibility: 'immediate: every introspection reads the shared issuer store',
      async introspect(token, resource) {
        const state = await store.read();
        const record = own(state.accessTokens, tokenHash(token));
        const session = record && own(state.sessions, record.sessionId);
        if (!record || !session || record.expiresAt <= now() || record.resource !== (resource ?? null)) throw new AuthorityError('invalid_token');
        return {
          principal: { issuer, clientId: session.clientId, userId: session.userId, sessionId: record.sessionId, scopes: [...record.scopes], tokenExpiresAt: record.expiresAt, sessionVersion: session.version, issuerGeneration: state.generation },
          dpopJkt: record.jkt,
        };
      }
    }
  };
}
