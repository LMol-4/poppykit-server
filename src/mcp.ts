import { secureUrl } from './network/transport.js';
import type { AuthorityError } from './auth/authority.js';
export function mcpResourceMetadata(input: { resource: string; issuer?: string; dpop: boolean }): Record<string, unknown> {
  secureUrl(input.resource); if (input.issuer) secureUrl(input.issuer);
  return { resource: input.resource, authorization_servers: input.issuer ? [input.issuer] : [], bearer_methods_supported: ['header'], ...(input.dpop ? { dpop_signing_alg_values_supported: ['ES256'] } : {}) };
}
export function mcpAuthorizationError(error: AuthorityError, metadataUrl: string, dpop: boolean): Response {
  if (error.code === 'invalid_session' || error.code === 'rate_limited') return error.response();
  secureUrl(metadataUrl); if (/["\x00-\x20\\]/.test(metadataUrl)) throw new TypeError('metadataUrl');
  const scope = error.headers.get('www-authenticate')?.match(/(?:^|[ ,])scope="([^"]*)"/)?.[1];
  const attributes = [...(error.code === 'account_required' ? [] : [`error="${error.code}"`]), ...(scope === undefined ? [] : [`scope="${scope}"`]), `resource_metadata="${metadataUrl}"`];
  const challenge = (scheme: string) => `${scheme} ${attributes.join(', ')}`;
  return new Response(null, { status: error.status, headers: { 'WWW-Authenticate': [challenge('Bearer'), ...(dpop ? [challenge('DPoP')] : [])].join(', '), 'Cache-Control': 'no-store' } });
}
