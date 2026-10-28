import { createHash, randomBytes } from 'node:crypto';
import { secureUrl } from './network/transport.js';
import { verifyDpopProof } from './auth/dpop.js';
import type { Principal, AuthorityPolicy } from './auth/authority.js';
import { AuthorityError } from './auth/authority.js';

export interface BrowserBinding { clientId: string; userId: string; sessionId: string; issuerGeneration?: string }
export interface BrowserSession extends BrowserBinding { principal: Principal; expiresAt: number }
export interface BrowserSessionAuthority {
  // Resolve only an existing active Session Key; never create a Session.
  join(sessionKey: string): Promise<BrowserSession>;
  current(binding: BrowserBinding): Promise<BrowserSession>;
}
export interface BrowserCookieStore {
  put(hash: string, binding: BrowserBinding & { expiresAt: number }): Promise<void>;
  get(hash: string): Promise<(BrowserBinding & { expiresAt: number }) | null>;
  putJoin(codeHash: string, binding: { cookieHash: string; expiresAt: number }): Promise<void>;
  // Atomically remove and return, including expired entries. First submission consumes the code on any result.
  consumeJoin(codeHash: string): Promise<{ cookieHash: string; expiresAt: number } | null>;
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
  endpoint: string; domain: string; authority: BrowserSessionAuthority;
  cookies: BrowserCookieStore; policy: AuthorityPolicy; now: () => number;
  cookieName?: string; sameSite?: 'Lax' | 'None'; cookieLifetimeSeconds?: number;
}) {
  const endpoint = secureUrl(options.endpoint);
  const name = options.cookieName ?? '__Host-poppy-session', sameSite = options.sameSite ?? 'Lax', lifetime = options.cookieLifetimeSeconds ?? 3600;
  if (!/^[A-Za-z0-9_-]+$/.test(name) || !['Lax', 'None'].includes(sameSite) || !Number.isSafeInteger(lifetime) || lifetime < 1 || !/^[a-z0-9.-]+$/i.test(options.domain)) throw new TypeError('browser options');
  if (name === '__Host-poppy_join' || (endpoint.hostname !== options.domain.toLowerCase() && !endpoint.hostname.endsWith(`.${options.domain.toLowerCase()}`))) throw new TypeError('browser options');
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
        if (request.url !== options.endpoint) throw invalid();
        if (request.method === 'GET') {
          const code = randomBytes(32).toString('base64url'), cookie = randomBytes(32).toString('base64url');
          await options.cookies.putJoin(hash(code), { cookieHash: hash(cookie), expiresAt: options.now() + 60000 });
          return new Response(`<!doctype html><title>Connecting</title><form method="post"><input type="hidden" name="code" value="${code}"><input type="text" name="proof"></form>`, { headers: {
            'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
            'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'", 'Cross-Origin-Opener-Policy': 'same-origin',
            'Set-Cookie': '__Host-poppy_join=' + cookie + '; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Strict',
          } });
        }
        if (request.method !== 'POST' || request.headers.get('content-type')?.split(';')[0] !== 'application/x-www-form-urlencoded') throw invalid();
        const fields = new URLSearchParams(await boundedText(request, 16384));
        const codes = fields.getAll('code');
        // Consume every identifiable code before checking cookies, origin, proof or duplicate fields.
        const issued = await Promise.all([...new Set(codes)].map(code => options.cookies.consumeJoin(hash(code))));
        if (codes.length !== 1 || fields.getAll('proof').length !== 1 || [...fields.keys()].some(key => !['code', 'proof'].includes(key))) throw invalid();
        const binding = issued[0];
        const cookies = (request.headers.get('cookie') ?? '').split(';').map(part => part.trim().split('='));
        const matches = cookies.filter(([key]) => key === '__Host-poppy_join');
        if (!binding || binding.expiresAt <= options.now() || matches.length !== 1 || matches[0]!.length !== 2 || hash(matches[0]![1]!) !== binding.cookieHash) throw invalid();
        const origin = request.headers.get('origin'), site = request.headers.get('sec-fetch-site');
        if ((origin !== null && origin !== new URL(options.endpoint).origin) || (site !== null && !['same-origin', 'none'].includes(site))) throw invalid();
        const verified = await verifyDpopProof(fields.get('proof'), { method: 'POST', url: options.endpoint, nowMs: options.now() });
        if (verified.claims.nonce !== codes[0]) throw invalid();
        const session = await options.authority.join(verified.jkt);
        const seconds = Math.floor(Math.min(session.expiresAt - options.now(), lifetime * 1000) / 1000);
        if (seconds < 1) throw invalid();
        const value = randomBytes(32).toString('base64url');
        const { clientId, userId, sessionId, issuerGeneration } = session;
        await options.cookies.put(hash(value), { clientId, userId, sessionId, ...(issuerGeneration === undefined ? {} : { issuerGeneration }), expiresAt: options.now() + seconds * 1000 });
        const headers = new Headers({ Location: new URL('/', options.endpoint).href, 'Set-Cookie': `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${seconds}`, 'Cache-Control': 'no-store' });
        headers.append('Set-Cookie', '__Host-poppy_join=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict');
        return new Response(null, { status: 303, headers });
      } catch { return new Response('Invalid browser session', { status: 400, headers: { 'Cache-Control': 'no-store', 'Content-Type': 'text/plain' } }); }
    },
  };
}
