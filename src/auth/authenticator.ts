import { secureUrl } from '../network/transport.js';
import { AuthorityError } from './authority.js';
import type { ExternalAuthorityAdapter, RequestAuthenticator, ResourceEndpoint } from './authority.js';
import { verifyDpopProof } from './dpop.js';

const DPOP_AUTHORIZATION = /^DPoP ([A-Za-z0-9\-._~+/]+=*)$/i;

// Only introspect is used here; the policy half of the adapter is consumed by the conversation service.
export function createRequestAuthenticator(options: {
  authority: Pick<ExternalAuthorityAdapter, 'introspect'>; endpoints: ResourceEndpoint[]; now: () => number;
}): RequestAuthenticator {
  for (const endpoint of options.endpoints) {
    if (secureUrl(endpoint.origin).origin !== endpoint.origin || !endpoint.pathPrefix.startsWith('/')) throw new TypeError('Invalid resource endpoint');
    if (endpoint.mcp && (endpoint.resource !== `${endpoint.origin}${endpoint.pathPrefix}` || secureUrl(endpoint.mcp.metadataUrl).href !== endpoint.mcp.metadataUrl)) throw new TypeError('Invalid MCP resource');
  }
  return {
    async authenticate(request) {
      // The Request URL must already be the trusted public URL; forwarding headers are never read.
      const url = new URL(request.url);
      const endpoint = options.endpoints
        .filter(item => url.origin === item.origin && (url.pathname === item.pathPrefix || (!item.mcp && url.pathname.startsWith(item.pathPrefix.endsWith('/') ? item.pathPrefix : `${item.pathPrefix}/`))))
        .sort((a, b) => b.pathPrefix.length - a.pathPrefix.length)[0];
      if (!endpoint) throw new AuthorityError('invalid_token');
      if (endpoint.mcp && request.url !== endpoint.resource) throw new AuthorityError('invalid_token');
      if (endpoint.mcp && /^Bearer /i.test(request.headers.get('authorization') ?? '')) {
        const bearer = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i.exec(request.headers.get('authorization') ?? '')?.[1];
        if (!bearer || bearer.length > 4096) throw new AuthorityError('invalid_token');
        const { principal, dpopJkt } = await options.authority.introspect(bearer, endpoint.resource);
        // Ordinary MCP issuers return null only for unbound Bearer tokens. A bound token never downgrades.
        if (dpopJkt !== null || principal.tokenExpiresAt <= options.now()) throw new AuthorityError('invalid_token');
        if (!principal.userId && !principal.accountId) throw new AuthorityError('invalid_token');
        return principal;
      }
      if (endpoint.mcp && !endpoint.mcp.dpop) throw new AuthorityError('invalid_token');
      const token = DPOP_AUTHORIZATION.exec(request.headers.get('authorization') ?? '')?.[1];
      if (!token || token.length > 4096) throw new AuthorityError('invalid_token');
      const nowMs = options.now();
      const proof = await verifyDpopProof(request.headers.get('dpop'), { method: request.method, url: `${url.origin}${url.pathname}`, nowMs, accessToken: token });
      const { principal, dpopJkt } = await options.authority.introspect(token, endpoint.resource);
      if (principal.tokenExpiresAt <= nowMs) throw new AuthorityError('invalid_token');
      if (dpopJkt !== proof.jkt) throw new AuthorityError('invalid_dpop_proof');
      return principal;
    }
  };
}
