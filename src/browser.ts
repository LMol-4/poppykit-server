import { createHash, randomBytes } from 'node:crypto';
import { compactVerify, createLocalJWKSet, decodeJwt, errors } from 'jose';
import type { JSONWebKeySet } from 'jose';
import type { MetadataResolver } from './network/discovery.js';
import { secureUrl } from './network/transport.js';
import { parseJson, object } from './protocol/wire.js';
import { assertUniqueJwtMembers } from './auth/dpop.js';
import type { Principal, AuthorityPolicy } from './auth/authority.js';
import { AuthorityError } from './auth/authority.js';

export interface BrowserBinding { clientId: string; userId: string; sessionId: string; issuerGeneration?: string }
export interface BrowserSession extends BrowserBinding { principal: Principal; expiresAt: number }
export interface BrowserSessionAuthority {
  // Must atomically validate the live client/user/session and consume jti until expiresAt.
  join(binding: BrowserBinding, assertion: { jti: string; expiresAt: number }): Promise<BrowserSession>;
  current(binding: BrowserBinding): Promise<BrowserSession>;
}
export interface BrowserCookieStore {
  put(hash: string, binding: BrowserBinding & { expiresAt: number }): Promise<void>;
  get(hash: string): Promise<(BrowserBinding & { expiresAt: number }) | null>;
}
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
export async function boundedText(request: Request, max: number): Promise<string> {
  if (!request.body) throw new TypeError('body');
  const reader = request.body.getReader(); let size = 0; const parts: Uint8Array[] = [];
  try { for (;;) { const next = await reader.read(); if (next.done) break; size += next.value.byteLength; if (size > max) throw new TypeError('body'); parts.push(next.value); } }
  catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts));
}
export function createBrowserSessions(options: {
  endpoint: string; domain: string; metadata: MetadataResolver; authority: BrowserSessionAuthority;
  cookies: BrowserCookieStore; policy: AuthorityPolicy; now: () => number;
  cookieName?: string; sameSite?: 'Lax' | 'None'; cookieLifetimeSeconds?: number;
}) {
  secureUrl(options.endpoint);
  const name = options.cookieName ?? '__Host-poppy-session', sameSite = options.sameSite ?? 'Lax', lifetime = options.cookieLifetimeSeconds ?? 3600;
  if (!/^[A-Za-z0-9_-]+$/.test(name) || !['Lax', 'None'].includes(sameSite) || !Number.isSafeInteger(lifetime) || lifetime < 1 || !/^[a-z0-9.-]+$/i.test(options.domain)) throw new TypeError('browser options');
  const invalid = () => new Error('Invalid browser session');
  async function authenticate(request: Request): Promise<Principal> {
    const cookies = (request.headers.get('cookie') ?? '').split(';').map(part => part.trim().split('='));
    const matches = cookies.filter(([key]) => key === name);
    if (matches.length !== 1 || matches[0]!.length !== 2 || !/^[A-Za-z0-9_-]{43}$/.test(matches[0]![1]!)) throw invalid();
    const binding = await options.cookies.get(hash(matches[0]![1]!));
    if (!binding || binding.expiresAt <= options.now()) throw invalid();
    const session = await options.authority.current(binding);
    if (session.expiresAt <= options.now() || session.clientId !== binding.clientId || session.userId !== binding.userId || session.sessionId !== binding.sessionId || session.issuerGeneration !== binding.issuerGeneration) throw invalid();
    return session.principal;
  }
  return {
    authenticate,
    async withSession<T>(request: Request, scopes: readonly string[], action: (principal: Principal) => Promise<T>): Promise<T> {
      const principal = await authenticate(request);
      return options.policy.withCurrent(principal, [], async () => {
        const current = await options.authority.current(principal);
        if (!scopes.every(scope => current.principal.scopes.includes(scope))) throw new AuthorityError('insufficient_scope');
        return action(current.principal);
      });
    },
    async join(request: Request): Promise<Response> {
      try {
        if (request.method !== 'POST' || request.url !== options.endpoint || request.headers.get('content-type')?.split(';')[0] !== 'application/x-www-form-urlencoded') throw invalid();
        const fields = new URLSearchParams(await boundedText(request, 16384));
        if (fields.getAll('assertion').length !== 1 || [...fields.keys()].some(key => key !== 'assertion')) throw invalid();
        const jwt = fields.get('assertion')!; if (jwt.length > 8192) throw invalid();
        assertUniqueJwtMembers(jwt);
        const untrusted = decodeJwt(jwt); if (typeof untrusted.iss !== 'string') throw invalid();
        const client = await options.metadata.resolveClient(untrusted.iss);
        let keys = await options.metadata.resolveJwks(client.jwks_uri) as unknown as JSONWebKeySet;
        let verified;
        try { verified = await compactVerify(jwt, createLocalJWKSet(keys), { algorithms: ['ES256', 'RS256'] }); }
        catch (error) { if (!(error instanceof errors.JWKSNoMatchingKey)) throw error; keys = await options.metadata.resolveJwks(client.jwks_uri, { refresh: true }) as unknown as JSONWebKeySet; verified = await compactVerify(jwt, createLocalJWKSet(keys), { algorithms: ['ES256', 'RS256'] }); }
        const claims = object(parseJson(new TextDecoder().decode(verified.payload)));
        if (verified.protectedHeader.typ?.toLowerCase().replace(/^application\//, '') !== 'poppy-browser+jwt' || claims.iss !== client.client_id || claims.aud !== options.endpoint || typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 256 || typeof claims.session_id !== 'string' || !claims.session_id || typeof claims.jti !== 'string' || !claims.jti || claims.jti.length > 256 || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || (claims.exp as number) <= options.now() / 1000 || (claims.iat as number) > options.now() / 1000 + 30 || (claims.exp as number) <= (claims.iat as number) || (claims.exp as number) - (claims.iat as number) > 60 || typeof claims.return_to !== 'string') throw invalid();
        const destination = secureUrl(claims.return_to);
        if (destination.hostname !== options.domain.toLowerCase() && !destination.hostname.endsWith(`.${options.domain.toLowerCase()}`)) throw invalid();
        const session = await options.authority.join({ clientId: client.client_id, userId: claims.sub, sessionId: claims.session_id }, { jti: claims.jti, expiresAt: (claims.exp as number) * 1000 });
        const seconds = Math.floor(Math.min(session.expiresAt - options.now(), lifetime * 1000) / 1000);
        if (seconds < 1) throw invalid();
        const value = randomBytes(32).toString('base64url');
        const { clientId, userId, sessionId, issuerGeneration } = session;
        await options.cookies.put(hash(value), { clientId, userId, sessionId, ...(issuerGeneration === undefined ? {} : { issuerGeneration }), expiresAt: options.now() + seconds * 1000 });
        return new Response(null, { status: 303, headers: { Location: claims.return_to, 'Set-Cookie': `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${seconds}`, 'Cache-Control': 'no-store' } });
      } catch { return new Response('Invalid browser session', { status: 400, headers: { 'Cache-Control': 'no-store', 'Content-Type': 'text/plain' } }); }
    },
  };
}
