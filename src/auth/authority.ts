export interface Principal {
  issuer: string; clientId: string; userId: string; sessionId: string;
  accountId?: string; grantId?: string; scopes: string[];
  tokenExpiresAt: number; // Unix milliseconds
  sessionVersion: number;
  issuerGeneration?: string;
  agentId?: string; sessionGeneration?: string; sessionInstanceId?: string; sessionExpiresAt?: number;
}
export type WorkRevocationPolicy = 'stop-account-work' | 'allow-accepted-work-to-finish';
export interface AcceptedAuthority { principal: Principal; acceptedAt: number; revocationPolicy: WorkRevocationPolicy }
export interface AuthorityCoordinator { run<T>(action: () => Promise<T>): Promise<T> }
export interface AuthorityPolicy {
  withCurrent<T>(principal: Principal, scopes: readonly string[], action: () => Promise<T>): Promise<T>;
  withAccepted<T>(authority: AcceptedAuthority, scopes: readonly string[], action: () => Promise<T>): Promise<T>;
}
export interface RequestAuthenticator { authenticate(request: Request): Promise<Principal> }
export interface ResourceEndpoint { origin: string; pathPrefix: string; resource?: string; mcp?: { dpop: boolean; metadataUrl: string } }
export interface ExternalAuthorityAdapter {
  issuer: string;
  revocationVisibility: string; // explicit latency and ordering guarantee
  introspect(token: string, resource?: string): Promise<{ principal: Principal; dpopJkt: string | null }>;
  policy: AuthorityPolicy;
}

export type AuthorityErrorCode = 'invalid_token' | 'invalid_dpop_proof' | 'use_dpop_nonce' | 'invalid_session' | 'account_required' | 'rate_limited' | 'insufficient_scope';
// Resource-side error (spec section 6): carried in WWW-Authenticate, never echoing tokens or peer values.
export class AuthorityError extends Error {
  readonly status: 400 | 401 | 403 | 429;
  readonly headers: Headers;
  constructor(readonly code: AuthorityErrorCode, options: { scope?: string; retryAfter?: number } = {}) {
    super(`Authorization failed: ${code}`);
    this.name = 'AuthorityError';
    this.status = code === 'rate_limited' ? 429 : code === 'invalid_session' ? 400 : code === 'insufficient_scope' ? 403 : 401;
    if (options.scope !== undefined && !/^[\x21\x23-\x5B\x5D-\x7E ]*$/.test(options.scope)) throw new TypeError('scope');
    const scope = options.scope === undefined ? '' : `, scope="${options.scope}"`;
    if (options.retryAfter !== undefined && (!Number.isSafeInteger(options.retryAfter) || options.retryAfter < 1)) throw new TypeError('retryAfter');
    this.headers = code === 'rate_limited' ? new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Retry-After': String(options.retryAfter ?? 60) }) : code === 'invalid_session' ? new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }) : new Headers({ 'WWW-Authenticate': code === 'account_required' ? `Bearer${scope ? ' ' + scope.slice(2) : ''}, DPoP${scope ? ' ' + scope.slice(2) : ''}` : `DPoP error="${code}"${scope}, algs="ES256", Bearer error="${code}"${scope}` });
  }
  response(): Response {
    return new Response(this.code === 'invalid_session' || this.code === 'rate_limited' ? JSON.stringify({ error: this.code }) : null, { status: this.status, headers: this.headers });
  }
}
