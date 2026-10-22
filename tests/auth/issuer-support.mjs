import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { createReferenceIssuer, initialIssuerState } from '../../dist/reference-auth/index.js';
import { NOW, keyPair, proof } from './support.mjs';
import { memoryCoordinator } from '../conversation/support.mjs';

// Reference issuer test environment: one agent client, fake metadata resolver, injected clock.
export const ISSUER = 'https://auth.shop.test';
export const TOKEN_ENDPOINT = 'https://auth.shop.test/oauth/token';
export const CLIENT = 'https://agent.test/agent.json';
export const JWKS_URI = 'https://agent.test/jwks.json';
export const RESOURCE = 'https://api.shop.test/special';
export const API = 'https://api.shop.test/poppy/conversations';
export const OTHER_CLIENT = 'https://agent.test/other.json'; // shares the agent's keys
export const REDIRECT = 'https://agent.test/oauth/callback';

export function memoryStore(initial) {
  let state = structuredClone(initial);
  return {
    async read() { return structuredClone(state); },
    async transaction(selection, change = selection) { const draft = structuredClone(state); const result = change(draft); state = draft; return structuredClone(result); },
    get state() { return state; },
    set state(value) { state = value; },
  };
}

export async function setup(overrides = {}) {
  const identity = await keyPair(); const dpopKey = await keyPair();
  const clock = { now: NOW };
  const jwk = kp => ({ ...kp.jwk, kid: 'k1', alg: 'ES256', use: 'sig' });
  const env = { identity, dpopKey, clock, store: memoryStore(initialIssuerState()), calls: { client: 0, jwks: 0, refresh: 0 } };
  env.jwks = { keys: [jwk(identity)] }; env.refreshedJwks = env.jwks;
  env.metadata = {
    async resolveClient(id) { env.calls.client++; await env.onClient?.(); if (id !== CLIENT && id !== OTHER_CLIENT) throw new Error('unknown client'); return { client_id: id, client_name: 'Agent', jwks_uri: JWKS_URI, redirect_uris: [REDIRECT], token_endpoint_auth_method: 'private_key_jwt' }; },
    async resolveJwks(uri, settings = {}) { assert.equal(uri, JWKS_URI); if (settings.refresh) { env.calls.refresh++; return structuredClone(env.refreshedJwks); } env.calls.jwks++; await env.onJwks?.(); return structuredClone(env.jwks); },
  };
  env.issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, poppyDomains: ['shop.test'], directScopes: ['poppy:read', 'poppy:write'], resources: [RESOURCE], metadata: env.metadata, store: env.store, coordinator: memoryCoordinator(), now: () => clock.now, ...overrides });
  env.assertion = (claims = {}, { key = identity, header = {} } = {}) => {
    const iat = Math.floor(clock.now / 1000);
    return new SignJWT({ iss: CLIENT, sub: 'usr_1', aud: ISSUER, iat, exp: iat + 60, jti: randomUUID(), ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'k1', ...header }).sign(key.privateKey);
  };
  env.clientAssertion = (claims = {}, options) => env.assertion({ sub: CLIENT, ...claims }, options);
  env.proof = (options = {}) => proof(options.key ?? dpopKey, { htu: TOKEN_ENDPOINT, iat: Math.floor(clock.now / 1000), nonce: env.nonce, ...options });
  // Sends a token request; fields override the defaults, undefined deletes one.
  env.send = async (fields = {}, { dpop, url = TOKEN_ENDPOINT, headers = {} } = {}) => {
    const form = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: await env.assertion(), client_id: CLIENT, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await env.clientAssertion(), ...fields };
    const body = new URLSearchParams(Object.entries(form).filter(([, value]) => value !== undefined));
    const response = await env.issuer.token(new Request(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...(dpop === null ? {} : { dpop: dpop ?? await env.proof() }), ...headers }, body }));
    return { status: response.status, headers: response.headers, body: await response.json() };
  };
  env.challenge = async () => { const response = await env.send(); assert.equal(response.body.error, 'use_dpop_nonce'); env.nonce = response.headers.get('dpop-nonce'); return response; };
  return env;
}
export const expectError = (response, error, status = error === 'invalid_client' ? 401 : 400) => {
  assert.deepEqual(response.body, { error }); assert.equal(response.status, status); assert.equal(response.headers.get('cache-control'), 'no-store');
};

