import assert from 'node:assert/strict';
import {jsonObject} from '../../test-support/assertions.mjs';
import type {JWTPayload,JWK,ProtectedHeaderParameters} from 'jose';
import { createHash, randomUUID } from 'node:crypto';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

export const NOW = 1_790_900_000_000;
export async function keyPair(alg = 'ES256') {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const jwk=jsonObject(await exportJWK(publicKey));assert.ok(typeof jwk.kty==='string');return {privateKey,publicKey,jwk:{...jwk,kty:jwk.kty},privateJwk:jsonObject(await exportJWK(privateKey))};
}
export const ath = (token:string) => createHash('sha256').update(token).digest('base64url');
// Builds a DPoP proof; header/claims overrides let tests break one property at a time.
export async function proof(key:Awaited<ReturnType<typeof keyPair>>, { htm = 'POST', htu, iat = NOW / 1000, token, nonce, jti = randomUUID(), claims = {}, header = {}, signWith }: {htm?:string;htu?:string;iat?:number;token?:string;nonce?:string|null;jti?:string;claims?:JWTPayload;header?:ProtectedHeaderParameters;signWith?:Awaited<ReturnType<typeof keyPair>>} = {}) {
  const payload = { jti, htm, htu, iat, ...(token === undefined ? {} : { ath: ath(token) }), ...(nonce === undefined ? {} : { nonce }), ...claims };
  return new SignJWT(payload).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk, ...header }).sign((signWith ?? key).privateKey);
}
