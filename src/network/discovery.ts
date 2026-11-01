import { validRedirect } from './redirect.js';
import { object, string, member, parseJson, ValidationError } from '../protocol/wire.js';
import type { JsonObject } from '../protocol/wire.js';
import { secureUrl } from './transport.js';
import type { HttpTransport } from './transport.js';
import { parseExcludedTasks } from './tasks.js';
import type { ExcludedTask } from './tasks.js';
export interface ScopeHint { changes: 'none' | 'reversible' | 'irreversible'; personal_data: boolean }
export interface PoppyDocument { protocol_version: '0.3'; organization: { name: string; domain: string }; auth?: { issuer?: string; scopes?: Record<string, string>; scope_hints?: Record<string, ScopeHint>; [key: string]: unknown }; agent?: { protocols: { type: string; endpoint: string; [key: string]: unknown }[] }; apis?: { type: string; url: string; description: string; [key: string]: unknown }[]; web?: { browser_session_endpoint?: string; [key: string]: unknown }; excluded_tasks?: { url: string }; feedback?: { endpoint: string; [key: string]: unknown }; extensions?: Record<string, { version: string; endpoint?: string; [key: string]: unknown }>; [key: string]: unknown }
export interface AuthorizationMetadata { issuer: string; token_endpoint: string; revocation_endpoint: string; protected_resources: string[]; grant_types_supported: string[]; scopes_supported?: string[]; authorization_endpoint?: string; device_authorization_endpoint?: string; dpop_signing_alg_values_supported?: string[]; client_id_metadata_document_supported?: boolean; [key: string]: unknown }
export interface ClientMetadata { client_id: string; client_name: string; jwks_uri: string; redirect_uris?: string[]; token_endpoint_auth_method: 'private_key_jwt'; extensions?: Record<string, { version: string; [key: string]: unknown }>; [key: string]: unknown }
export interface CompanyMetadata { document: PoppyDocument; authorization?: AuthorizationMetadata; url: string }
export interface MetadataResolver { resolveCompany(domain: string): Promise<CompanyMetadata>; resolveResource?(resource: string, options?: { metadataUrl?: string; refresh?: boolean }): Promise<ProtectedResourceMetadata | null>; resolveClient(clientId: string): Promise<ClientMetadata>; resolveJwks(uri: string, options?: { refresh?: boolean }): Promise<JsonObject>; resolveExcludedTasks?(document: PoppyDocument): Promise<ExcludedTask[]>; invalidate?(target?: string): void }
function url(value: unknown, field: string): string { const valueString = string(value, field); secureUrl(valueString); return valueString; }
function strings(value: unknown, field: string, allowEmpty = false): string[] { if (!Array.isArray(value) || (!allowEmpty && !value.length)) throw new ValidationError(field); value.forEach(item => string(item, field)); return value; }
export function companyScopes(value: unknown, allowEmpty = false): string[] {
  const result = strings(value, 'scopes', allowEmpty);
  for (const scope of result) if (!/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope)) throw new ValidationError('scopes');
  return result;
}
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
  const doc = object(value); member(doc.protocol_version, ['0.3'], 'protocol_version');
  const served = secureUrl(servingUrl);
  if (served.pathname !== '/.well-known/poppy.json' || servingUrl.includes('?')) throw new ValidationError('discovery.url');
  const organization = object(doc.organization, 'organization'); string(organization.name, 'organization.name');
  if (domain(organization.domain).toLowerCase() !== secureUrl(servingUrl).hostname.toLowerCase()) throw new ValidationError('organization.domain');
  if (!['agent', 'apis', 'web'].some(key => key in doc)) throw new ValidationError('capabilities');
  const web = 'web' in doc ? object(doc.web, 'web') : undefined;
  if (web && 'browser_session_endpoint' in web) url(web.browser_session_endpoint, 'browser_session_endpoint');
  if ('auth' in doc) {
    const auth = object(doc.auth, 'auth'); if ('issuer' in auth) authorizationMetadataUrl(url(auth.issuer, 'issuer'));
    if ('scope_hints' in auth) {
      const hints = object(auth.scope_hints, 'scope_hints');
      for (const [scope, value] of Object.entries(hints)) {
        companyScopes([scope]); const hint = object(value, 'scope_hint');
        string(hint.changes, 'changes'); member(hint.personal_data, [true, false], 'personal_data');
        hints[scope] = { changes: ['none', 'reversible', 'irreversible'].includes(hint.changes as string) ? hint.changes : 'irreversible', personal_data: hint.personal_data };
      }
    }
    if ('scopes' in auth) for (const [scope, description] of Object.entries(object(auth.scopes, 'auth.scopes'))) { companyScopes([scope]); string(description, 'auth.scopes'); }
  }
  if ('agent' in doc) {
    const protocols = object(doc.agent, 'agent').protocols;
    if (!Array.isArray(protocols) || !protocols.length) throw new ValidationError('protocols');
    for (const protocol of protocols) {
      const item = object(protocol);
      string(item.type, 'protocol.type'); url(item.endpoint, 'protocol.endpoint');
      if (item.type === 'poppy' && 'access' in item) string(item.access, 'protocol.access');
    }
  }
  if ('apis' in doc) { if (!Array.isArray(doc.apis)) throw new ValidationError('apis'); for (const api of doc.apis) { const item = object(api); string(item.type, 'api.type'); string(item.description, 'api.description'); url(item.url, 'api.url'); } }
  if ('excluded_tasks' in doc) url(object(doc.excluded_tasks).url, 'excluded_tasks.url');
  if ('feedback' in doc) url(object(doc.feedback).endpoint, 'feedback.endpoint');
  if ('extensions' in doc) for (const extension of Object.values(object(doc.extensions))) { const item = object(extension); string(item.version, 'extension.version'); if ('endpoint' in item) url(item.endpoint, 'extension.endpoint'); }
  const mediated = (doc.extensions as Record<string, unknown> | undefined)?.['mediated-sign-in'];
  if (mediated && object(mediated).version === '1') parseMediatedSignIn(mediated);
  return doc as unknown as PoppyDocument;
}
export function parseAuthorizationMetadata(value: unknown, document: PoppyDocument, issuer = document.auth?.issuer): AuthorizationMetadata {
  const metadata = object(value);
  if (!issuer || metadata.issuer !== issuer) throw new ValidationError('issuer');
  const resources = strings(metadata.protected_resources, 'protected_resources'); resources.forEach(value => url(value, 'protected_resources'));
  if (!resources.some(value => /^https:\/\/[^/:?#]+$/.test(value) && value.slice(8).toLowerCase() === document.organization.domain.toLowerCase())) throw new ValidationError('protected_resources');
  const grants = strings(metadata.grant_types_supported, 'grant_types_supported');
  if (!grants.includes('refresh_token')) throw new ValidationError('grant_types_supported');
  for (const key of ['token_endpoint', 'revocation_endpoint']) url(metadata[key], key);
  for (const [key, grant] of [['authorization_endpoint', 'authorization_code'], ['device_authorization_endpoint', 'urn:ietf:params:oauth:grant-type:device_code']] as const) if (grants.includes(grant) || key in metadata) url(metadata[key], key);
  if ('pushed_authorization_request_endpoint' in metadata) url(metadata.pushed_authorization_request_endpoint, 'pushed_authorization_request_endpoint');
  if ('scopes_supported' in metadata) companyScopes(metadata.scopes_supported, true);
  const mediated = mediatedSignIn(document);
  if (mediated && !grants.includes(MEDIATED_GRANT)) throw new ValidationError('mediated.grant');
  if ('dpop_signing_alg_values_supported' in metadata) strings(metadata.dpop_signing_alg_values_supported, 'dpop_signing_alg_values_supported');
  if ('client_id_metadata_document_supported' in metadata) member(metadata.client_id_metadata_document_supported, [true, false], 'client_id_metadata_document_supported');
  return metadata as unknown as AuthorizationMetadata;
}
export function signInMethods(metadata: CompanyMetadata): { method: 'direct' | 'device' | 'mediated'; scopes: string[] }[] {
  const auth = metadata.authorization, methods: ReturnType<typeof signInMethods> = [];
  if (!auth) return methods;
  if (auth.grant_types_supported.includes('authorization_code') && auth.authorization_endpoint) methods.push({ method: 'direct', scopes: [...auth.scopes_supported ?? []] });
  if (auth.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:device_code') && auth.device_authorization_endpoint) methods.push({ method: 'device', scopes: [...auth.scopes_supported ?? []] });
  const mediated = mediatedSignIn(metadata.document);
  if (mediated && auth.grant_types_supported.includes(MEDIATED_GRANT)) methods.push({ method: 'mediated', scopes: [...mediated.scopes] });
  return methods;
}

export const MEDIATED_GRANT = 'https://personalagentprotocol.org/grant/mediated-sign-in';
export interface MediatedSignIn { version: '1'; fields: { name: string; label: string; secret: boolean }[]; scopes: string[] }
export function parseMediatedSignIn(value: unknown): MediatedSignIn {
  const extension = object(value, 'mediated-sign-in');
  member(extension.version, ['1'], 'mediated.version'); companyScopes(extension.scopes);
  if (!Array.isArray(extension.fields) || !extension.fields.length) throw new ValidationError('mediated.fields');
  const names = new Set<string>();
  const reserved = new Set(['grant_type', 'scope', 'resource', 'client_id', 'client_secret', 'client_assertion', 'client_assertion_type', 'sign_in_id', 'one_time_code']);
  for (const value of extension.fields) {
    const field = object(value); const name = string(field.name, 'field.name');
    if (reserved.has(name) || names.has(name)) throw new ValidationError('field.name');
    names.add(name); string(field.label, 'field.label'); member(field.secret, [true, false], 'field.secret');
  }
  return extension as unknown as MediatedSignIn;
}
export function mediatedSignIn(document: PoppyDocument): MediatedSignIn | undefined {
  const extension = document.extensions?.['mediated-sign-in'];
  return extension?.version === '1' ? parseMediatedSignIn(extension) : undefined;
}
export function companyIdentifier(metadata: CompanyMetadata): string {
  return metadata.authorization?.issuer ?? `https://${metadata.document.organization.domain.toLowerCase()}`;
}
export interface ProtectedResourceMetadata { resource: string; authorization_servers?: string[]; dpop_signing_alg_values_supported?: string[]; [key: string]: unknown }
export function protectedResourceMetadataUrl(resource: string): string {
  const parsed = secureUrl(resource);
  return `${parsed.origin}/.well-known/oauth-protected-resource${parsed.pathname === '/' ? '' : parsed.pathname}${parsed.search}`;
}
export function parseProtectedResourceMetadata(value: unknown): ProtectedResourceMetadata {
  const metadata = object(value, 'resource_metadata'); url(metadata.resource, 'resource');
  if ('authorization_servers' in metadata) strings(metadata.authorization_servers, 'authorization_servers', true).forEach(value => authorizationMetadataUrl(url(value, 'authorization_servers')));
  if ('bearer_methods_supported' in metadata) strings(metadata.bearer_methods_supported, 'bearer_methods_supported', true);
  if ('dpop_signing_alg_values_supported' in metadata) strings(metadata.dpop_signing_alg_values_supported, 'dpop_signing_alg_values_supported', true);
  return metadata as unknown as ProtectedResourceMetadata;
}

export function parseClientMetadata(value: unknown, clientId: string): ClientMetadata {
  const parsed = validateClientId(clientId); const metadata = object(value);
  if (metadata.client_id !== clientId) throw new ValidationError('client_id');
  string(metadata.client_name, 'client_name'); member(metadata.token_endpoint_auth_method, ['private_key_jwt'], 'token_endpoint_auth_method');
  const redirects = 'redirect_uris' in metadata ? strings(metadata.redirect_uris, 'redirect_uris', true) : [];
  if (secureUrl(url(metadata.jwks_uri, 'jwks_uri')).hostname !== parsed.hostname || redirects.some(endpoint => !validRedirect(endpoint, clientId))) throw new ValidationError('client_endpoint_domain');
  if ('extensions' in metadata) for (const extension of Object.values(object(metadata.extensions))) string(object(extension).version, 'extension.version');
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
// Refresh throttling entries share the same bound as metadata cache entries.
// shortcut: limits are global per resolver, not per caller, and cap total cold-fetch throughput; move per-caller limiting to the server HTTP layer before production use.
export function createMetadataResolver(transport: HttpTransport, options: { now?: () => number; maxEntries?: number; maxConcurrentFetches?: number; maxFetchesPerMinute?: number } = {}): MetadataResolver {
  const now = options.now ?? Date.now; const maxEntries = options.maxEntries ?? 1000;
  const maxConcurrent = options.maxConcurrentFetches ?? 16; const maxPerMinute = options.maxFetchesPerMinute ?? 120;
  let epoch = 0, fetching = 0;
  const starts: number[] = [];
  const cache = new Map<string, { value: unknown; url: string; expires: number; etag?: string; modified?: string; control?: string; missing?: boolean }>();
  const pending = new Map<string, Promise<{ value: unknown; url: string; expires: number; etag?: string; modified?: string; control?: string; missing?: boolean }>>();
  const refreshes = new Map<string, number>();
  async function get(target: string, validate: (value: unknown, servedUrl: string, missing?: boolean) => unknown, mode: 'endpoint' | 'discovery', refresh = false, allowMissing = false) {
    secureUrl(target); const key = `${mode}:${target}`; const cached = cache.get(key);
    if (!refresh && cached && cached.expires > now()) { validate(cached.value, cached.url, cached.missing); return structuredClone(cached); }
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
        if (response.status !== 200 && !(allowMissing && response.status === 404) && !(response.status === 304 && cached)) throw new ValidationError('metadata.status');
        let value: unknown; try { value = response.status === 304 ? cached!.value : response.status === 404 ? null : parseJson(await response.text()); } catch { throw new ValidationError('metadata.json'); }
        const missing = response.status === 404 || (response.status === 304 && cached?.missing === true);
        const servedUrl = response.url || (response.status === 304 ? cached!.url : target); validate(value, servedUrl, missing);
        if (response.status === 304) validate(value, cached!.url, missing);
        const control = response.headers.get('cache-control') ?? (response.status === 304 ? cached?.control : undefined) ?? ''; const age = Number(response.headers.get('age') ?? 0);
        const seconds = Number(/(?:^|,)\s*max-age=(\d+)/i.exec(control)?.[1] ?? 60); // no max-age: 60 s floor (guide: at least a minute)
        const expires = now() + (/\b(?:no-store|no-cache)\b/i.test(control) ? 0 : Math.max(0, Math.min(300, seconds - (Number.isFinite(age) ? age : 0)))) * 1000;
        const result = { value, control, missing, url: servedUrl, expires, etag: response.headers.get('etag') ?? cached?.etag, modified: response.headers.get('last-modified') ?? cached?.modified }; if (startedEpoch !== epoch) return result; if (!/\bno-store\b/i.test(control)) remember(cache, key, result, maxEntries, entry => entry.expires <= now()); else cache.delete(key);
        return result;
      })().finally(() => { fetching--; }); pending.set(key, task);
    }
    try { const result = await task; validate(result.value, result.url, result.missing); return structuredClone(result); } finally { if (pending.get(key) === task) pending.delete(key); }
  }
  return {
    invalidate(target?: string) { epoch++; pending.clear(); if (target === undefined) { cache.clear(); } else { for (const key of cache.keys()) if (key.endsWith(`:${target}`)) cache.delete(key); } },
    async resolveCompany(input) {
      if (!/^[a-z0-9.-]+(?::\d{1,5})?$/i.test(input)) throw new ValidationError('domain');
      const target = `https://${input}/.well-known/poppy.json`;
      const found = await get(target, parsePoppyDocument, 'discovery');
      const document = parsePoppyDocument(found.value, found.url);
      const resource = `https://${document.organization.domain.toLowerCase()}`;
      const protectedMetadata = await get(protectedResourceMetadataUrl(resource), (value, _servedUrl, missing) => {
        if (!missing) { const metadata = parseProtectedResourceMetadata(value); if (!/^https:\/\/[^/:?#]+$/.test(metadata.resource) || metadata.resource.slice(8).toLowerCase() !== document.organization.domain.toLowerCase()) throw new ValidationError('resource'); }
      }, 'discovery', false, true);
      const servers = protectedMetadata.missing ? [] : parseProtectedResourceMetadata(protectedMetadata.value).authorization_servers ?? [];
      const selected = document.auth?.issuer;
      if (!servers.length) {
        if (selected || mediatedSignIn(document) || document.agent?.protocols.some(item => item.type === 'poppy' && item.access === 'signed_in')) throw new ValidationError('issuer');
        return { document, url: found.url };
      }
      const issuer = selected ?? (servers.length === 1 ? servers[0] : undefined);
      if (!issuer || !servers.includes(issuer)) throw new ValidationError('issuer');
      const auth = await get(authorizationMetadataUrl(issuer), value => parseAuthorizationMetadata(value, document, issuer), 'discovery');
      return { document, authorization: parseAuthorizationMetadata(auth.value, document, issuer), url: found.url };
    },
    async resolveResource(resource, settings = {}) {
      const target = settings.metadataUrl ?? protectedResourceMetadataUrl(resource);
      const found = await get(target, (value, _servedUrl, missing) => { if (!missing) parseProtectedResourceMetadata(value); }, 'discovery', settings.refresh, true);
      return found.missing ? null : parseProtectedResourceMetadata(found.value);
    },
    async resolveExcludedTasks(document) {
      if (!document.excluded_tasks) return [];
      const found = await get(document.excluded_tasks.url, value => parseExcludedTasks(value, document), 'discovery');
      return parseExcludedTasks(found.value, document);
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
