import { object, string, member, canonical, parseJson, ValidationError } from '../protocol/wire.js';
import type { JsonObject } from '../protocol/wire.js';
import { secureUrl } from './transport.js';
import type { HttpTransport } from './transport.js';
export interface PoppyDocument { protocol_version: '0.2'; organization: { name: string; domain: string }; auth?: { issuer: string; direct?: { scopes: string[] }; device?: { scopes: string[] }; mediated?: { endpoint: string; fields: { name: string; label: string; secret: boolean }[]; scopes: string[] }; custom_scopes?: Record<string, string>; [key: string]: unknown }; agent?: { protocols: { type: string; endpoint: string; resource?: string; [key: string]: unknown }[] }; apis?: { type: string; url: string; description: string; resource?: string; [key: string]: unknown }[]; web?: { browser_session_endpoint?: string; [key: string]: unknown }; feedback?: { endpoint: string; [key: string]: unknown }; extensions?: Record<string, { version: string; endpoint?: string; [key: string]: unknown }>; [key: string]: unknown }
export interface AuthorizationMetadata { issuer: string; token_endpoint: string; revocation_endpoint: string; poppy_domains: string[]; authorization_endpoint?: string; device_authorization_endpoint?: string; dpop_signing_alg_values_supported?: string[]; client_id_metadata_document_supported?: boolean; [key: string]: unknown }
export interface ClientMetadata { client_id: string; client_name: string; jwks_uri: string; redirect_uris: string[]; token_endpoint_auth_method: 'private_key_jwt'; [key: string]: unknown }
export interface CompanyMetadata { document: PoppyDocument; authorization?: AuthorizationMetadata; url: string }
export interface MetadataResolver { resolveCompany(domain: string): Promise<CompanyMetadata>; resolveClient(clientId: string): Promise<ClientMetadata>; resolveJwks(uri: string, options?: { refresh?: boolean }): Promise<JsonObject>; invalidate?(target?: string): void }
function url(value: unknown, field: string): string { const valueString = string(value, field); secureUrl(valueString); return valueString; }
function strings(value: unknown, field: string, allowEmpty = false): string[] { if (!Array.isArray(value) || (!allowEmpty && !value.length)) throw new ValidationError(field); value.forEach(item => string(item, field)); return value; }
function scopes(value: unknown): void { for (const scope of strings(value, 'scopes')) if (!/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope)) throw new ValidationError('scopes'); }
function domain(value: unknown): string { const text = string(value, 'domain'); if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(text) || text.includes('..')) throw new ValidationError('domain'); return text; }
export function authorizationMetadataUrl(issuer: string): string { const parsed = secureUrl(issuer); if (parsed.search) throw new ValidationError('issuer'); return `${parsed.origin}/.well-known/oauth-authorization-server${parsed.pathname === '/' ? '' : parsed.pathname}`; }
export function validateClientId(clientId: string): URL {
  // Backslashes, whitespace and control characters are normalized away by URL parsing, hiding dot segments.
  if (/[\\\s\x00-\x1f]/.test(clientId)) throw new ValidationError('client_id');
  const raw = /^https:\/\/[^/?#]+(\/[^?#]*)(?:\?[^#]*)?$/.exec(clientId);
  if (!raw || raw[1].split('/').some(segment => /^(?:\.|%2e){1,2}$/i.test(segment))) throw new ValidationError('client_id');
  return secureUrl(clientId);
}
export function parsePoppyDocument(value: unknown, servingUrl: string): PoppyDocument {
  const doc = object(value); member(doc.protocol_version, ['0.2'], 'protocol_version');
  const organization = object(doc.organization, 'organization'); string(organization.name, 'organization.name');
  if (domain(organization.domain).toLowerCase() !== secureUrl(servingUrl).hostname.toLowerCase()) throw new ValidationError('organization.domain');
  if (!['agent', 'apis', 'web'].some(key => key in doc)) throw new ValidationError('capabilities');
  const web = 'web' in doc ? object(doc.web, 'web') : undefined;
  if (web && 'browser_session_endpoint' in web) url(web.browser_session_endpoint, 'browser_session_endpoint');
  if (['agent', 'apis', 'feedback'].some(key => key in doc) || (web && 'browser_session_endpoint' in web)) object(doc.auth, 'auth');
  if ('auth' in doc) {
    const auth = object(doc.auth, 'auth'); authorizationMetadataUrl(url(auth.issuer, 'issuer'));
    for (const key of ['direct', 'device']) if (key in auth) scopes(object(auth[key], key).scopes);
    if ('mediated' in auth) {
      const mediated = object(auth.mediated, 'mediated');
      url(mediated.endpoint, 'mediated.endpoint'); scopes(mediated.scopes);
      if (!Array.isArray(mediated.fields) || !mediated.fields.length) throw new ValidationError('mediated.fields');
      for (const field of mediated.fields) {
        const item = object(field);
        string(item.name, 'field.name'); string(item.label, 'field.label'); member(item.secret, [true, false], 'field.secret');
      }
    }
    if ('custom_scopes' in auth) Object.values(object(auth.custom_scopes)).forEach(value => string(value, 'custom_scopes', false));
  }
  if ('agent' in doc) {
    const protocols = object(doc.agent, 'agent').protocols;
    if (!Array.isArray(protocols) || !protocols.length) throw new ValidationError('protocols');
    for (const protocol of protocols) {
      const item = object(protocol);
      string(item.type, 'protocol.type'); url(item.endpoint, 'protocol.endpoint');
      if ('resource' in item) url(item.resource, 'protocol.resource');
    }
  }
  if ('apis' in doc) { if (!Array.isArray(doc.apis)) throw new ValidationError('apis'); for (const api of doc.apis) { const item = object(api); string(item.type, 'api.type'); string(item.description, 'api.description'); url(item.url, 'api.url'); if ('resource' in item) url(item.resource, 'api.resource'); } }
  if ('feedback' in doc) url(object(doc.feedback).endpoint, 'feedback.endpoint');
  if ('extensions' in doc) for (const extension of Object.values(object(doc.extensions))) { const item = object(extension); string(item.version, 'extension.version'); if ('endpoint' in item) url(item.endpoint, 'extension.endpoint'); }
  return doc as unknown as PoppyDocument;
}
export function parseAuthorizationMetadata(value: unknown, document: PoppyDocument): AuthorizationMetadata {
  const metadata = object(value); const auth = document.auth!;
  if (metadata.issuer !== auth.issuer) throw new ValidationError('issuer');
  const domains = strings(metadata.poppy_domains, 'poppy_domains'); domains.forEach(domain);
  if (!domains.some(item => item.toLowerCase() === document.organization.domain.toLowerCase())) throw new ValidationError('poppy_domains');
  for (const key of ['token_endpoint', 'revocation_endpoint']) url(metadata[key], key);
  for (const [key, required] of [['authorization_endpoint', !!auth.direct], ['device_authorization_endpoint', !!auth.device]] as const) if (required || key in metadata) url(metadata[key], key);
  if ('dpop_signing_alg_values_supported' in metadata && !strings(metadata.dpop_signing_alg_values_supported, 'dpop_signing_alg_values_supported').includes('ES256')) throw new ValidationError('dpop_signing_alg_values_supported');
  if ('client_id_metadata_document_supported' in metadata) member(metadata.client_id_metadata_document_supported, [true, false], 'client_id_metadata_document_supported');
  return metadata as unknown as AuthorizationMetadata;
}
export function parseClientMetadata(value: unknown, clientId: string): ClientMetadata {
  const parsed = validateClientId(clientId); const metadata = object(value);
  if (metadata.client_id !== clientId) throw new ValidationError('client_id');
  string(metadata.client_name, 'client_name'); member(metadata.token_endpoint_auth_method, ['private_key_jwt'], 'token_endpoint_auth_method');
  const redirects = strings(metadata.redirect_uris, 'redirect_uris', true);
  for (const endpoint of [url(metadata.jwks_uri, 'jwks_uri'), ...redirects]) if (secureUrl(endpoint).hostname.toLowerCase() !== parsed.hostname.toLowerCase()) throw new ValidationError('client_endpoint_domain');
  if ('logo_uri' in metadata) url(metadata.logo_uri, 'logo_uri');
  return metadata as unknown as ClientMetadata;
}
// Re-insert so Map order is recency, then drop expired entries and finally the oldest until at most `max` remain.
function remember<V>(map: Map<string, V>, key: string, value: V, max: number, expired: (value: V) => boolean): void {
  map.delete(key); map.set(key, value);
  if (map.size <= max) return;
  for (const [k, v] of map) if (expired(v)) map.delete(k);
  for (const k of map.keys()) { if (map.size <= max) break; map.delete(k); }
}
// Defaults: 1000 entries per map; at most 16 cold fetch operations in flight and 120 started per 60 s (excess is rejected, not queued).
// Invariant: maxFetchesPerMinute * 5 (300 s TTL cap) must stay below maxEntries, or a flood can evict live authDocuments/refreshes entries.
// shortcut: limits are global per resolver, not per caller, and cap total cold-fetch throughput; move per-caller limiting to the server HTTP layer before production use.
export function createMetadataResolver(transport: HttpTransport, options: { now?: () => number; maxEntries?: number; maxConcurrentFetches?: number; maxFetchesPerMinute?: number } = {}): MetadataResolver {
  const now = options.now ?? Date.now; const maxEntries = options.maxEntries ?? 1000;
  const maxConcurrent = options.maxConcurrentFetches ?? 16; const maxPerMinute = options.maxFetchesPerMinute ?? 120;
  let epoch = 0, fetching = 0;
  const starts: number[] = [];
  const cache = new Map<string, { value: unknown; url: string; expires: number; etag?: string; modified?: string; control?: string }>();
  const pending = new Map<string, Promise<{ value: unknown; url: string; expires: number; etag?: string; modified?: string; control?: string }>>();
  const refreshes = new Map<string, number>();
  const authDocuments = new Map<string, Map<string, { auth: string; expires: number }>>();
  async function get(target: string, validate: (value: unknown, servedUrl: string) => unknown, mode: 'endpoint' | 'discovery', refresh = false) {
    secureUrl(target); const key = `${mode}:${target}`; const cached = cache.get(key);
    if (!refresh && cached && cached.expires > now()) { validate(cached.value, cached.url); return structuredClone(cached); }
    let task = pending.get(key);
    if (!task) {
      while (starts.length && now() - starts[0] >= 60000) starts.shift();
      if (fetching >= maxConcurrent || starts.length >= maxPerMinute) throw new ValidationError('metadata.rate_limited');
      starts.push(now()); if (refresh) remember(refreshes, target, now(), maxEntries, at => now() - at >= 60000);
      fetching++;
      const startedEpoch = epoch;
      task = (async () => {
        const headers = new Headers(); if (cached?.etag) headers.set('if-none-match', cached.etag); else if (cached?.modified) headers.set('if-modified-since', cached.modified);
        const response = await transport.fetch(new Request(target, { headers }), { mode });
        if (response.status !== 200 && !(response.status === 304 && cached)) throw new ValidationError('metadata.status');
        let value: unknown; try { value = response.status === 304 ? cached!.value : parseJson(await response.text()); } catch { throw new ValidationError('metadata.json'); }
        const servedUrl = response.status === 304 ? cached!.url : response.url || target; validate(value, servedUrl);
        const control = response.headers.get('cache-control') ?? (response.status === 304 ? cached?.control : undefined) ?? ''; const age = Number(response.headers.get('age') ?? 0);
        const seconds = Number(/(?:^|,)\s*max-age=(\d+)/i.exec(control)?.[1] ?? 60); // no max-age: 60 s floor (guide: at least a minute)
        const expires = now() + (/\b(?:no-store|no-cache)\b/i.test(control) ? 0 : Math.max(0, Math.min(300, seconds - (Number.isFinite(age) ? age : 0)))) * 1000;
        const result = { value, control, url: response.status === 304 ? cached!.url : servedUrl, expires, etag: response.headers.get('etag') ?? cached?.etag, modified: response.headers.get('last-modified') ?? cached?.modified }; if (startedEpoch !== epoch) return result; if (!/\bno-store\b/i.test(control)) remember(cache, key, result, maxEntries, entry => entry.expires <= now()); else cache.delete(key);
        return result;
      })().finally(() => { fetching--; }); pending.set(key, task);
    }
    try { const result = await task; validate(result.value, result.url); return structuredClone(result); } finally { if (pending.get(key) === task) pending.delete(key); }
  }
  return {
    invalidate(target?: string) { epoch++; pending.clear(); if (target === undefined) { cache.clear(); authDocuments.clear(); } else { for (const key of cache.keys()) if (key.endsWith(`:${target}`)) cache.delete(key); authDocuments.clear(); } },
    async resolveCompany(input) {
      const startedEpoch = epoch;
      if (!/^[a-z0-9.-]+(?::\d{1,5})?$/i.test(input)) throw new ValidationError('domain');
      const target = `https://${input}/.well-known/poppy.json`;
      const found = await get(target, parsePoppyDocument, 'discovery'); const document = parsePoppyDocument(found.value, found.url);
      if (!document.auth) return { document, url: found.url };
      const auth = await get(authorizationMetadataUrl(document.auth.issuer), value => parseAuthorizationMetadata(value, document), 'discovery');
      if(startedEpoch!==epoch) return {document,authorization:parseAuthorizationMetadata(auth.value,document),url:found.url};
      const entries = authDocuments.get(document.auth.issuer) ?? new Map();
      const spelling = canonical(document.auth); const currentDomain = document.organization.domain.toLowerCase();
      for (const [otherDomain, entry] of entries) if (otherDomain !== currentDomain && entry.expires > now() && entry.auth !== spelling) throw new ValidationError('auth.consistency');
      const expiredEntry = (entry: { auth: string; expires: number }) => entry.expires <= now();
      remember(entries, currentDomain, { auth: spelling, expires: found.expires }, maxEntries, expiredEntry);
      remember(authDocuments, document.auth.issuer, entries, maxEntries, inner => [...inner.values()].every(expiredEntry));
      return { document, authorization: parseAuthorizationMetadata(auth.value, document), url: found.url };
    },
    async resolveClient(clientId) { validateClientId(clientId); const found = await get(clientId, value => parseClientMetadata(value, clientId), 'endpoint'); return parseClientMetadata(found.value, clientId); },
    async resolveJwks(uri, settings = {}) {
      const validate = (value: unknown) => {
        const jwks = object(value);
        if (!Array.isArray(jwks.keys) || jwks.keys.length > 100) throw new ValidationError('jwks.keys');
        for (const key of jwks.keys) {
          const item = object(key);
          string(item.kty, 'jwk.kty');
          for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) if (secret in item) throw new ValidationError('jwk.private');
        }
      };
      if (settings.refresh) { const last = refreshes.get(uri); if (last !== undefined && now() - last < 60000) throw new ValidationError('jwks.refresh_limited'); }
      const found = await get(uri, validate, 'discovery', settings.refresh); return found.value as JsonObject;
    }
  };
}
