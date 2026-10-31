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

// Independently construct the resource identity carried beside optional OAuth credentials.
export async function sessionJwt(root:Awaited<ReturnType<typeof keyPair>>, input:{issuer:string;clientId:string;url:string;method?:string;token?:string;sid?:string;sub?:string;at?:number}) {
  const delegated=await keyPair(),iat=Math.floor((input.at??NOW)/1000),url=new URL(input.url);url.search='';url.hash='';
  const delegation=await new SignJWT({iss:input.clientId,cnf:{jwk:delegated.jwk},iat,exp:iat+3600,jti:randomUUID()}).setProtectedHeader({alg:'ES256',typ:'pap-delegation+jwt',kid:'k1'}).sign(root.privateKey);
  return new SignJWT({iss:input.clientId,aud:input.issuer,sid:input.sid??'resource-session',sub:input.sub??'pairwise-user',htm:input.method??'POST',htu:url.href,iat,jti:randomUUID(),...(input.token?{ath:ath(input.token)}:{})}).setProtectedHeader({alg:'ES256',typ:'poppy-session+jwt',kid:await (await import('jose')).calculateJwkThumbprint(delegated.jwk),pap_dlg:delegation}).sign(delegated.privateKey);
}
export function memorySessionStore(): import('../../dist/auth/session.js').SessionStore {
  const generation=randomUUID(),rows=new Map<string,import('../../dist/auth/session.js').SessionRecord>();
  return {
    async read(clientId,sid) {return structuredClone({version:1 as const,generation,record:rows.get(JSON.stringify([clientId,sid]))??null});},
    async transaction(clientId,sid,at,change) {
      const live=[...rows.values()].filter(row=>row.clientId===clientId&&!row.ended&&row.expiresAt>at);
      const state:import('../../dist/auth/session.js').SessionAdmission={version:1,generation,record:structuredClone(rows.get(JSON.stringify([clientId,sid]))??null),activeCount:live.length,earliestExpiry:live.length?Math.min(...live.map(row=>row.expiresAt)):null};
      const result=change(state);if(state.record)rows.set(JSON.stringify([clientId,sid]),structuredClone(state.record));return structuredClone(result);
    },
  };
}
