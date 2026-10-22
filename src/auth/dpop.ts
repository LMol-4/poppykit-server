import { createHash } from 'node:crypto';
import { calculateJwkThumbprint, compactVerify, decodeProtectedHeader, importJWK } from 'jose';
import { parseDpopClaims } from '../protocol/wire.js';
import type { DpopClaims } from '../protocol/wire.js';
import { AuthorityError } from './authority.js';

export const PROOF_WINDOW_SECONDS = 60;
export const CLOCK_SKEW_SECONDS = 30;
const COMPACT_JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export function base64urlSha256(value: string): string { return createHash('sha256').update(value).digest('base64url'); }
// Origin plus path: the htu form RFC 9449 compares (no query or fragment).
export function canonicalHtu(url: string): string { const parsed = new URL(url); return `${parsed.origin}${parsed.pathname}`; }

// RFC 9449 section 4.3 checks except nonce and replay, which only the token endpoint enforces.
// accessToken absent means a token-endpoint proof, which must not carry ath.
export async function verifyDpopProof(proof: string | null, expected: { method: string; url: string; nowMs: number; accessToken?: string }): Promise<{ claims: DpopClaims; jkt: string }> {
  const invalid = () => new AuthorityError('invalid_dpop_proof');
  // Several DPoP headers arrive joined by ", ", which fails the compact-JWT pattern.
  if (!proof || proof.length > 8192 || !COMPACT_JWT.test(proof)) throw invalid();
  let claims: DpopClaims; let jkt: string; let htu: string;
  try {
    const header = decodeProtectedHeader(proof); const jwk = header.jwk;
    if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk) throw invalid();
    const { payload } = await compactVerify(proof, await importJWK(jwk, 'ES256'), { algorithms: ['ES256'] });
    claims = parseDpopClaims(JSON.parse(new TextDecoder().decode(payload)));
    htu = canonicalHtu(claims.htu); jkt = await calculateJwkThumbprint(jwk);
  } catch { throw invalid(); }
  const nowSeconds = expected.nowMs / 1000;
  // jti is retained by the token-endpoint replay store, so bound it here (parseDpopClaims does not).
  if (claims.jti.length > 256 || (claims.nonce?.length ?? 0) > 256) throw invalid();
  if (claims.htm !== expected.method || htu !== canonicalHtu(expected.url)) throw invalid();
  if (claims.iat > nowSeconds + CLOCK_SKEW_SECONDS || claims.iat < nowSeconds - PROOF_WINDOW_SECONDS) throw invalid();
  if (expected.accessToken === undefined ? 'ath' in claims : claims.ath !== base64urlSha256(expected.accessToken)) throw invalid();
  return { claims, jkt };
}
