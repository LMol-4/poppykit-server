export interface Principal {
  issuer: string; clientId: string; userId: string; sessionId: string;
  accountId?: string; grantId?: string; scopes: string[];
  tokenExpiresAt: number; // Unix milliseconds
  sessionVersion: number;
  issuerGeneration?: string;
}
export type WorkRevocationPolicy = 'stop-account-work' | 'allow-accepted-work-to-finish';
export interface AcceptedAuthority { principal: Principal; acceptedAt: number; revocationPolicy: WorkRevocationPolicy }
export interface AuthorityCoordinator { run<T>(action: () => Promise<T>): Promise<T> }
export interface AuthorityPolicy {
  withCurrent<T>(principal: Principal, scopes: readonly string[], action: () => Promise<T>): Promise<T>;
  withAccepted<T>(authority: AcceptedAuthority, scopes: readonly string[], action: () => Promise<T>): Promise<T>;
}
export interface RequestAuthenticator { authenticate(request: Request): Promise<Principal> }
export interface ResourceEndpoint { origin: string; pathPrefix: string; resource?: string }
export interface ExternalAuthorityAdapter {
  issuer: string;
  revocationVisibility: string; // explicit latency and ordering guarantee
  introspect(token: string, resource?: string): Promise<{ principal: Principal; dpopJkt: string }>;
  policy: AuthorityPolicy;
}

export type AuthorityErrorCode = 'invalid_token' | 'invalid_dpop_proof' | 'use_dpop_nonce' | 'sign_in_required' | 'insufficient_scope';
// Resource-side error (spec section 6): carried in WWW-Authenticate, never echoing tokens or peer values.
export class AuthorityError extends Error {
  readonly status: 401 | 403;
  readonly headers: Headers;
  constructor(readonly code: AuthorityErrorCode, options: { scope?: string } = {}) {
    super(`Authorization failed: ${code}`);
    this.name = 'AuthorityError';
    this.status = code === 'sign_in_required' || code === 'insufficient_scope' ? 403 : 401;
    if (options.scope !== undefined && !/^[\x21\x23-\x5B\x5D-\x7E ]*$/.test(options.scope)) throw new TypeError('scope');
    const scope = options.scope === undefined ? '' : `, scope="${options.scope}"`;
    this.headers = new Headers({ 'WWW-Authenticate': `DPoP error="${code}"${scope}, algs="ES256"` });
  }
}
