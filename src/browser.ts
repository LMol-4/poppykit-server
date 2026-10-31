import { createHash, randomBytes } from 'node:crypto';
import { secureUrl } from './network/transport.js';
import { object, parseJson } from './protocol/wire.js';
import type { Principal, AuthorityPolicy, RequestAuthenticator } from './auth/authority.js';
import { AuthorityError } from './auth/authority.js';

export interface BrowserBinding { clientId: string; userId: string; sessionId: string; issuerGeneration?: string; principal?: Principal }
export interface BrowserJoin { cookieHash: string; expiresAt: number; principal?: Principal }
export interface BrowserCookieStore {
  put(hash: string, binding: BrowserBinding & { expiresAt: number }): Promise<void>;
  get(hash: string): Promise<(BrowserBinding & { expiresAt: number }) | null>;
  remove(hash: string): Promise<void>;
  putJoin(codeHash: string, binding: BrowserJoin): Promise<void>;
  /** Atomically authorize an unexpired, never-authorized code. Do not consume it. */
  authorizeJoin(codeHash: string, principal: Principal, at: number): Promise<boolean>;
  /** Atomically remove and return, even when submission will fail. */
  consumeJoin(codeHash: string): Promise<BrowserJoin | null>;
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
  endpoint: string; domain: string; authenticator: RequestAuthenticator;
  cookies: BrowserCookieStore; policy: AuthorityPolicy; now: () => number;
  /** Required for signed-in joins: clear the host's prior login without restoring it later. */
  clearLogin?: (request: Request, headers: Headers) => Promise<void>;
  cookieName?: string; sameSite?: 'Lax' | 'None'; cookieLifetimeSeconds?: number;
}) {
  const endpoint = secureUrl(options.endpoint), name = options.cookieName ?? '__Host-poppy-session';
  const sameSite = options.sameSite ?? 'Lax', lifetime = options.cookieLifetimeSeconds ?? 3600;
  if (!/^[A-Za-z0-9_-]+$/.test(name) || !['Lax', 'None'].includes(sameSite) || !Number.isSafeInteger(lifetime) || lifetime < 1 || !/^[a-z0-9.-]+$/i.test(options.domain)) throw new TypeError('browser options');
  if (name === '__Host-poppy_join' || (endpoint.hostname !== options.domain.toLowerCase() && !endpoint.hostname.endsWith(`.${options.domain.toLowerCase()}`))) throw new TypeError('browser options');
  const failure = new Error('Invalid browser session');
  const invalid = () => failure;
  const authorizationEndpoint=new URL(endpoint);authorizationEndpoint.pathname=endpoint.pathname.replace(/\/$/,'')+'/authorize';
  async function authenticate(request: Request): Promise<Principal> {
    const cookies = (request.headers.get('cookie') ?? '').split(';').map(part => part.trim().split('='));
    const matches = cookies.filter(([key]) => key === name);
    if (matches.length !== 1 || matches[0]!.length !== 2 || !/^[A-Za-z0-9_-]{43}$/.test(matches[0]![1]!)) throw invalid();
    const binding = await options.cookies.get(hash(matches[0]![1]!));
    if (!binding?.principal || binding.expiresAt <= options.now()) throw invalid();
    const principal = binding.principal;
    if (principal.clientId !== binding.clientId || principal.userId !== binding.userId || principal.sessionId !== binding.sessionId) throw invalid();
    return options.policy.withCurrent(principal, [], async () => principal);
  }
  return {
    authenticate,
    async withSession<T>(request: Request, scopes: readonly string[], action: (principal: Principal) => Promise<T>): Promise<T> {
      const principal = await authenticate(request);
      return options.policy.withCurrent(principal, scopes, () => action(principal));
    },
    async authorize(request: Request): Promise<Response> {
      try {
        if (request.url !== authorizationEndpoint.href || request.method !== 'POST' || request.headers.get('content-type')?.split(';')[0] !== 'application/json') throw invalid();
        let value:Record<string,unknown>;
        try{value=object(parseJson(await boundedText(request,4096)));}catch{throw failure;}
        if (typeof value.code !== 'string' || !/^[A-Za-z0-9_-]{1,256}$/.test(value.code)) throw invalid();
        const principal = await options.authenticator.authenticate(request);
        const success = await options.policy.withCurrent(principal, [], () => options.cookies.authorizeJoin(hash(value.code as string), principal, options.now()));
        if (!success) throw invalid();
        return new Response(null, {status:204,headers:{'Cache-Control':'no-store'}});
      } catch (error) {
        if (error instanceof AuthorityError) return error.response();
        if(error!==failure) throw error;
        return Response.json({error:'invalid_request'},{status:400,headers:{'Cache-Control':'no-store'}});
      }
    },
    async join(request: Request): Promise<Response> {
      try {
        if (request.url !== options.endpoint) throw invalid();
        if (request.method === 'GET') {
          const code = randomBytes(32).toString('base64url'), cookie = randomBytes(32).toString('base64url');
          await options.cookies.putJoin(hash(code), {cookieHash:hash(cookie),expiresAt:options.now()+60000});
          return new Response(`<!doctype html><title>Connecting</title><form method="post"><input type="hidden" name="code" value="${code}"><button>Continue</button></form>`, {headers:{
            'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store',
            'Content-Security-Policy':"default-src 'none'; form-action 'self'; frame-ancestors 'none'",'Cross-Origin-Opener-Policy':'same-origin',
            'Set-Cookie':'__Host-poppy_join='+cookie+'; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Strict',
          }});
        }
        if (request.method !== 'POST' || request.headers.get('content-type')?.split(';')[0] !== 'application/x-www-form-urlencoded') throw invalid();
        const fields = new URLSearchParams(await boundedText(request, 16384)), codes = fields.getAll('code');
        const issued: (BrowserJoin|null)[] = [];
        for (const code of new Set(codes)) issued.push(await options.cookies.consumeJoin(hash(code)));
        if (codes.length !== 1 || [...fields.keys()].some(key => key !== 'code')) throw invalid();
        const binding = issued[0];
        const cookies = (request.headers.get('cookie') ?? '').split(';').map(part => part.trim().split('='));
        const matches = cookies.filter(([key]) => key === '__Host-poppy_join');
        if (!binding?.principal || binding.expiresAt <= options.now() || matches.length !== 1 || matches[0]!.length !== 2 || hash(matches[0]![1]!) !== binding.cookieHash) throw invalid();
        const origin = request.headers.get('origin'), site = request.headers.get('sec-fetch-site');
        if ((origin !== null && origin !== endpoint.origin) || (site !== null && !['same-origin','none'].includes(site))) throw invalid();
        const principal = {...binding.principal};
        const seconds = Math.floor(Math.min((principal.sessionExpiresAt ?? principal.tokenExpiresAt)-options.now(), lifetime*1000)/1000);
        if (seconds < 1 || (principal.accountId && !options.clearLogin)) throw invalid();
        principal.tokenExpiresAt = options.now()+seconds*1000;
        const value = randomBytes(32).toString('base64url');
        return await options.policy.withCurrent(principal, [], async () => {
          const headers = new Headers({Location:new URL('/',options.endpoint).href,'Cache-Control':'no-store'});
          if (principal.accountId) await options.clearLogin!(request,headers);
          const previous=cookies.filter(([key])=>key===name);
          if(previous.length>1)throw invalid();
          if(previous[0]?.[1])await options.cookies.remove(hash(previous[0][1]));
          await options.cookies.put(hash(value), {clientId:principal.clientId,userId:principal.userId,sessionId:principal.sessionId,...(principal.issuerGeneration===undefined?{}:{issuerGeneration:principal.issuerGeneration}),principal,expiresAt:principal.tokenExpiresAt});
          headers.append('Set-Cookie',`${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${seconds}`);
          headers.append('Set-Cookie','__Host-poppy_join=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict');
          return new Response(null,{status:303,headers});
        });
      } catch { return new Response('Invalid browser session',{status:400,headers:{'Cache-Control':'no-store','Content-Type':'text/plain'}}); }
    },
  };
}
