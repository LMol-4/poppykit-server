import { secureUrl } from './network/transport.js';
import type { AuthorityError } from './auth/authority.js';
export function mcpResourceMetadata(input: { resource: string; issuer: string; dpop: boolean }): Record<string, unknown> {
  secureUrl(input.resource); secureUrl(input.issuer);
  return { resource: input.resource, authorization_servers: [input.issuer], bearer_methods_supported: ['header'], ...(input.dpop ? { dpop_signing_alg_values_supported: ['ES256'] } : {}) };
}
export function mcpAuthorizationError(error: AuthorityError, metadataUrl: string, dpop: boolean): Response {
  secureUrl(metadataUrl); if (/["\x00-\x20\\]/.test(metadataUrl)) throw new TypeError('metadataUrl');
  const scope = error.headers.get('www-authenticate')?.match(/, scope="[^"]*"/)?.[0] ?? '';
  const challenge = (scheme: string) => `${scheme} error="${error.code}"${scope}, resource_metadata="${metadataUrl}"`;
  return new Response(null, { status: error.status, headers: { 'WWW-Authenticate': [challenge('Bearer'), ...(dpop ? [challenge('DPoP')] : [])].join(', '), 'Cache-Control': 'no-store' } });
}
