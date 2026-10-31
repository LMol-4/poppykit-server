import { createHash } from 'node:crypto';
import { calculateJwkThumbprint, compactVerify, createLocalJWKSet, decodeProtectedHeader, errors, importJWK } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { id, object, parseJson, string, ValidationError } from './wire.js';
import type { MetadataResolver } from '../network/discovery.js';
import { validateClientId } from '../network/discovery.js';
import { secureUrl } from '../network/transport.js';

export interface SessionClaims {
  iss: string; aud: string; sid: string; sub: string; agent_id?: string;
  htm: string; htu: string; iat: number; jti: string; ath?: string;
}
export interface VerifiedSession extends SessionClaims { delegationExpiresAt: number }
const COMPACT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const PRIVATE = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
function unique(jwt: string): void {
  if (!COMPACT.test(jwt)) throw new ValidationError('session.jwt');
  for (const segment of jwt.split('.').slice(0, 2)) parseJson(Buffer.from(segment, 'base64url').toString('utf8'));
}
function timestamp(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new ValidationError('session.time');
  return value as number;
}
function bounded(value: unknown, field: string): string {
  const result = string(value, field); if (result.length > 256) throw new ValidationError(field); return result;
}
export function sessionRequestUrl(value: string): string {
  const url = secureUrl(value); return `${url.origin}${url.pathname}`;
}
export function parseSessionClaims(value: unknown): SessionClaims {
  const claims = object(value, 'session');
  validateClientId(string(claims.iss, 'session.iss')); secureUrl(string(claims.aud, 'session.aud'));
  id(claims.sid, 'session.sid'); bounded(claims.sub, 'session.sub');
  if ('agent_id' in claims) bounded(claims.agent_id, 'session.agent_id');
  string(claims.htm, 'session.htm'); const htu = string(claims.htu, 'session.htu');
  if (htu.includes('?') || htu.includes('#')) throw new ValidationError('session.htu');
  secureUrl(htu); timestamp(claims.iat);
  const jti = bounded(claims.jti, 'session.jti'); if (jti.length < 16) throw new ValidationError('session.jti');
  if ('ath' in claims) string(claims.ath, 'session.ath');
  return claims as unknown as SessionClaims;
}

/** Verifies identity only. The resource must separately admit/continue the client_id + sid under its store fence. */
export async function verifySessionJwt(jwt: string | null, expected: {
  companyId: string; method: string; url: string; nowMs: number; metadata: MetadataResolver;
  accessToken?: string; tokenClientId?: string;
}): Promise<VerifiedSession> {
  if (!jwt || jwt.length > 32768) throw new ValidationError('session.jwt');
  unique(jwt);
  const header = decodeProtectedHeader(jwt);
  if (header.typ !== 'poppy-session+jwt' || header.alg !== 'ES256' || typeof header.kid !== 'string' || typeof header.pap_dlg !== 'string') throw new ValidationError('session.header');
  const claims = parseSessionClaims(parseJson(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8')));
  const delegation = header.pap_dlg; unique(delegation);
  const delegatedHeader = decodeProtectedHeader(delegation);
  if (delegatedHeader.typ !== 'pap-delegation+jwt' || typeof delegatedHeader.alg !== 'string' || !['ES256', 'PS384'].includes(delegatedHeader.alg) || typeof delegatedHeader.kid !== 'string') throw new ValidationError('delegation.header');
  const client = await expected.metadata.resolveClient(claims.iss);
  let jwks = await expected.metadata.resolveJwks(client.jwks_uri) as unknown as JSONWebKeySet;
  let verified;
  try { verified = await compactVerify(delegation, createLocalJWKSet(jwks), { algorithms: ['ES256', 'PS384'] }); }
  catch (error) {
    if (!(error instanceof errors.JWKSNoMatchingKey)) throw error;
    jwks = await expected.metadata.resolveJwks(client.jwks_uri, { refresh: true }) as unknown as JSONWebKeySet;
    verified = await compactVerify(delegation, createLocalJWKSet(jwks), { algorithms: ['ES256', 'PS384'] });
  }
  const delegated = object(parseJson(new TextDecoder().decode(verified.payload)), 'delegation');
  const issued = timestamp(delegated.iat), expires = timestamp(delegated.exp), at = expected.nowMs / 1000;
  bounded(delegated.jti, 'delegation.jti');
  if ((delegated.jti as string).length < 16 || delegated.iss !== claims.iss || expires <= issued || expires - issued > 86400 || expires <= at || issued > at + 30) throw new ValidationError('delegation.claims');
  const key = object(object(delegated.cnf, 'delegation.cnf').jwk, 'delegation.key');
  if (key.kty !== 'EC' || key.crv !== 'P-256' || PRIVATE.some(name => name in key) || typeof key.x !== 'string' || typeof key.y !== 'string') throw new ValidationError('delegation.key');
  if (header.kid !== await calculateJwkThumbprint(key) || claims.iat > expires) throw new ValidationError('session.key');
  await compactVerify(jwt, await importJWK(key, 'ES256'), { algorithms: ['ES256'] });
  if (claims.aud !== expected.companyId || claims.htm !== expected.method || sessionRequestUrl(claims.htu) !== sessionRequestUrl(expected.url) || claims.iat < at - 60 || claims.iat > at + 30) throw new ValidationError('session.binding');
  if (expected.accessToken === undefined ? 'ath' in claims : claims.ath !== hash(expected.accessToken) || expected.tokenClientId !== claims.iss) throw new ValidationError('session.token');
  return { ...claims, delegationExpiresAt: expires * 1000 };
}
