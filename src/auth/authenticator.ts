import { secureUrl } from '../network/transport.js';
import { AuthorityError } from './authority.js';
import type { ExternalAuthorityAdapter, RequestAuthenticator, ResourceEndpoint } from './authority.js';
import type { SessionAuthority } from './session.js';
import { verifyDpopProof } from './dpop.js';

export function createRequestAuthenticator(options: {
  authority?: Pick<ExternalAuthorityAdapter, 'introspect'>;
  sessions?: SessionAuthority; endpoints: ResourceEndpoint[]; now: () => number;
}): RequestAuthenticator {
  for (const endpoint of options.endpoints) {
    if (secureUrl(endpoint.origin).origin !== endpoint.origin || !endpoint.pathPrefix.startsWith('/')) throw new TypeError('Invalid resource endpoint');
    if (endpoint.mcp) {
      const resource = secureUrl(endpoint.resource ?? '');
      if (resource.origin !== endpoint.origin || resource.pathname !== endpoint.pathPrefix || secureUrl(endpoint.mcp.metadataUrl).href !== endpoint.mcp.metadataUrl) throw new TypeError('Invalid MCP resource');
    }
  }
  return {
    async authenticate(request) {
      const url = new URL(request.url);
      const endpoint = options.endpoints
        .filter(item => url.origin === item.origin && (url.pathname === item.pathPrefix || (!item.mcp && url.pathname.startsWith(item.pathPrefix.endsWith('/') ? item.pathPrefix : `${item.pathPrefix}/`))))
        .sort((a, b) => b.pathPrefix.length - a.pathPrefix.length)[0];
      if (!endpoint || (endpoint.mcp && request.url !== endpoint.resource)) throw new AuthorityError('invalid_token');
      const authorization = request.headers.get('authorization');
      if (authorization === null) {
        if (!options.sessions) throw new AuthorityError('invalid_session');
        return options.sessions.authenticate(request);
      }
      const credentials = /^(Bearer|DPoP) ([A-Za-z0-9\-._~+/]+=*)$/i.exec(authorization);
      if (!credentials || credentials[2]!.length > 4096 || !options.authority) throw new AuthorityError('invalid_token');
      const token = credentials[2]!, scheme = credentials[1]!.toLowerCase();
      const { principal, dpopJkt } = await options.authority.introspect(token, endpoint.resource);
      if (principal.tokenExpiresAt <= options.now()) throw new AuthorityError('invalid_token');
      if (scheme === 'bearer') {
        if (dpopJkt !== null) throw new AuthorityError('invalid_token');
      } else {
        if (endpoint.mcp && !endpoint.mcp.dpop) throw new AuthorityError('invalid_token');
        const proof = await verifyDpopProof(request.headers.get('dpop'), { method: request.method, url: `${url.origin}${url.pathname}`, nowMs: options.now(), accessToken: token });
        if (dpopJkt !== proof.jkt) throw new AuthorityError('invalid_dpop_proof');
      }
      if (endpoint.mcp && !request.headers.has('poppy-session')) {
        if (!principal.accountId) throw new AuthorityError('invalid_token');
        return { ...principal, userId: '', sessionId: '', sessionVersion: 0 };
      }
      if (!options.sessions) throw new AuthorityError('invalid_session');
      return options.sessions.authenticate(request, { token, principal });
    },
  };
}
