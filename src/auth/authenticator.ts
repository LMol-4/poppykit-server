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
  }
  return {
    async authenticate(request) {
      // The Request URL must already be the trusted public URL; forwarding headers are never read.
      const url = new URL(request.url);
      const endpoint = options.endpoints
        .filter(item => url.origin === item.origin && (url.pathname === item.pathPrefix || url.pathname.startsWith(item.pathPrefix.endsWith('/') ? item.pathPrefix : `${item.pathPrefix}/`)))
        .sort((a, b) => b.pathPrefix.length - a.pathPrefix.length)[0];
      if (!endpoint) throw new AuthorityError('invalid_token');
      // Bearer scheme, cookies and query tokens are never accepted.
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
