import {jsonObject} from '../../test-support/assertions.mjs';
import type {IssuerState,ReferenceIssuerOptions} from '../../dist/reference-auth/index.js';
import type {IssuerSelection} from '../../dist/reference-auth/store.js';
import type {MetadataResolver} from '../../dist/network/discovery.js';
import type {JWTPayload,ProtectedHeaderParameters,JSONWebKeySet} from 'jose';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { createReferenceIssuer, initialIssuerState } from '../../dist/reference-auth/index.js';
import { NOW, keyPair, proof } from './support.mjs';
import { memoryCoordinator } from '../conversation/support.mjs';
import { resultCipher } from '../../test-support/result-cipher.mjs';

// Reference issuer test environment: one agent client, fake metadata resolver, injected clock.
export const ISSUER = 'https://auth.shop.test';
export const TOKEN_ENDPOINT = 'https://auth.shop.test/oauth/token';
export const CLIENT = 'https://agent.test/agent.json';
export const JWKS_URI = 'https://agent.test/jwks.json';
export const RESOURCE = 'https://api.shop.test/special';
export const API = 'https://api.shop.test/poppy/conversations';
export const OTHER_CLIENT = 'https://agent.test/other.json'; // shares the agent's keys
export const REDIRECT = 'https://agent.test/oauth/callback';

export function memoryStore(initial:IssuerState) {
  let state = structuredClone(initial);
  return {
    async read() { return structuredClone(state); },
    async transaction<T>(selection:IssuerSelection|((state:IssuerState)=>T),change?:(state:IssuerState)=>T) { const mutate=typeof selection==='function'?selection:change;assert.ok(mutate);const draft = structuredClone(state); const result = mutate(draft); state = draft; return structuredClone(result); },
    get state() { return state; },
    set state(value) { state = value; },
  };
}


type KeyPair=Awaited<ReturnType<typeof keyPair>>;
type AssertionOptions={key?:KeyPair;header?:ProtectedHeaderParameters};
type ProofOptions=NonNullable<Parameters<typeof proof>[1]>&{key?:KeyPair};
export interface Reply {sessionId?:string;signedIn?:boolean;status:number;headers:Headers;body:Record<string,unknown> & {access_token?:string;refresh_token?:string;session_id?:string;scope?:string;error?:string}}
export interface Environment {
 identity:KeyPair;dpopKey:KeyPair;clock:{now:number};store:ReturnType<typeof memoryStore>;calls:{client:number;jwks:number;refresh:number};
 jwks:{keys:({kty:string}&ReturnType<typeof jsonObject>)[]};refreshedJwks:{keys:({kty:string}&ReturnType<typeof jsonObject>)[]};metadata:MetadataResolver;issuer:ReturnType<typeof createReferenceIssuer>;
 onClient?:()=>void|Promise<void>;onJwks?:()=>void|Promise<void>;nonce?:string|null;
 assertion(claims?:JWTPayload,options?:AssertionOptions):Promise<string>;
 clientAssertion(claims?:JWTPayload,options?:AssertionOptions):Promise<string>;
 proof(options?:ProofOptions):Promise<string>;
 send(fields?:Record<string,string|undefined>,options?:{dpop?:string|null;url?:string;headers?:Record<string,string>}):Promise<Reply>;
 challenge():Promise<Reply>;
}

export async function setup(overrides:Partial<ReferenceIssuerOptions> = {}) {
  const identity = await keyPair(); const dpopKey = await keyPair();
  const clock = { now: NOW };
  const jwk=(kp:Awaited<ReturnType<typeof keyPair>>)=>{const value=jsonObject(kp.jwk);assert.ok(typeof value.kty==='string');return {...value,kty:value.kty,kid:'k1',alg:'ES256',use:'sig'};};
  const env:Environment={identity,dpopKey,clock,store:memoryStore(initialIssuerState()),calls:{client:0,jwks:0,refresh:0},jwks:{keys:[]},refreshedJwks:{keys:[]},metadata:undefined!,issuer:undefined!,assertion:undefined!,clientAssertion:undefined!,proof:undefined!,send:undefined!,challenge:undefined!};
  env.jwks = { keys: [jwk(identity)] }; env.refreshedJwks = env.jwks;
  env.metadata = {async resolveCompany(){throw new Error('unexpected company metadata');},
    async resolveClient(id) { env.calls.client++; await env.onClient?.(); if (id !== CLIENT && id !== OTHER_CLIENT) throw new Error('unknown client'); return { client_id: id, client_name: 'Agent', jwks_uri: JWKS_URI, redirect_uris: [REDIRECT], token_endpoint_auth_method: 'private_key_jwt' as const }; },
    async resolveJwks(uri, settings = {}) { assert.equal(uri, JWKS_URI); if (settings.refresh) { env.calls.refresh++; return structuredClone(env.refreshedJwks); } env.calls.jwks++; await env.onJwks?.(); return structuredClone(env.jwks); },
  };
  env.issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, protectedResources: ['https://shop.test'], supportedScopes: ['orders:read', 'orders:write'], resources: [RESOURCE], metadata: env.metadata, store: env.store, coordinator: memoryCoordinator(), now: () => clock.now, authorizationResultCipher: resultCipher(), ...overrides });
  env.assertion = (claims = {}, { key = identity, header = {} } = {}) => {
    const iat = Math.floor(clock.now / 1000);
    return new SignJWT({ iss: CLIENT, sub: 'usr_1', aud: ISSUER, iat, exp: iat + 60, jti: randomUUID(), ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'k1', ...header }).sign(key.privateKey);
  };
  env.clientAssertion = (claims = {}, options) => env.assertion({ sub: CLIENT, ...claims }, options);
  env.proof = (options = {}) => proof(options.key ?? dpopKey, { htu: TOKEN_ENDPOINT, iat: Math.floor(clock.now / 1000), nonce: env.nonce, ...options });
  // Sends a token request; fields override the defaults, undefined deletes one.
  env.send = async (fields = {}, { dpop, url = TOKEN_ENDPOINT, headers = {} } = {}) => {
    const form = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: await env.assertion(), client_id: CLIENT, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await env.clientAssertion(), ...fields };
    const body = new URLSearchParams(Object.entries(form).filter((entry):entry is [string,string]=>entry[1]!==undefined));
    const response = await env.issuer.token(new Request(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...(dpop === null ? {} : { dpop: dpop ?? await env.proof() }), ...headers }, body }));
    const result = { status: response.status, headers: response.headers, body: await response.json() };
    // Internal authority is separate from the protocol response, which has no Session ID/sign-in fields.
    if (result.status === 200 && result.body.access_token) {
      try {const { principal } = await env.issuer.authority.introspect(result.body.access_token, fields.resource);
      return { ...result, sessionId: principal.sessionId, signedIn: !!principal.accountId };}catch(error){if(!(error instanceof Error)||!('code' in error)||error.code!=='invalid_token')throw error;}
    }
    return result;
  };
  env.challenge = async () => { const response = await env.send(); assert.equal(response.body.error, 'use_dpop_nonce'); env.nonce = response.headers.get('dpop-nonce'); return response; };
  return env;
}
export const expectError = (response:Reply,error:string, status = error === 'invalid_client' ? 401 : 400) => {
  assert.deepEqual(response.body, { error }); assert.equal(response.status, status); assert.equal(response.headers.get('cache-control'), 'no-store');
};
