import type { RequestAuthenticator, AuthorityPolicy, Principal } from './auth/authority.js';
import { AuthorityError } from './auth/authority.js';
import { object, parseJson } from './protocol/wire.js';
import { boundedText } from './browser.js';
import { secureUrl } from './network/transport.js';
// Untrusted report text is data, including when an application later submits it to a model.
export interface FeedbackReport { kind: string; task: string; description: string }
export function createFeedbackHandler(options: { endpoint: string; authenticator: RequestAuthenticator; policy: AuthorityPolicy; accept(report: Readonly<FeedbackReport>, principal: Principal): Promise<void>; allow?: (principal: Principal) => Promise<boolean> }) {
  secureUrl(options.endpoint);
  return async (request: Request): Promise<Response> => {
    const fail = (status: number, error: string) => Response.json({ error }, { status, headers: { 'Cache-Control': 'no-store' } });
    let principal: Principal;
    try { principal = await options.authenticator.authenticate(request); }
    catch (error) { if (error instanceof AuthorityError) return new Response(null, { status: error.status, headers: error.headers }); throw error; }
    if (request.url !== options.endpoint || request.method !== 'POST' || request.headers.get('content-type')?.split(';')[0] !== 'application/json') return fail(400, 'invalid_request');
    let report: FeedbackReport;
    try {
      const value = object(parseJson(await boundedText(request, 16384)));
      if (typeof value.kind !== 'string' || !value.kind.length || typeof value.task !== 'string' || !value.task.length || [...value.task].length > 200 || typeof value.description !== 'string' || !value.description.length || [...value.description].length > 2000) throw 0;
      report = { kind: value.kind, task: value.task, description: value.description };
    } catch { return fail(400, 'invalid_request'); }
    try {
      return await options.policy.withCurrent(principal, [], async () => {
        if (options.allow && !await options.allow(principal)) return fail(429, 'rate_limited');
        await options.accept(Object.freeze(report), principal);
        return new Response(null, { status: 202 });
      });
    } catch (error) { if (error instanceof AuthorityError) return new Response(null, { status: error.status, headers: error.headers }); throw error; }
  };
}
