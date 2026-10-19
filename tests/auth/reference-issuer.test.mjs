import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { createReferenceIssuer, initialIssuerState } from '../../dist/reference-auth/index.js';
import { createRequestAuthenticator } from '../../dist/index.js';
import { NOW, keyPair, proof } from './support.mjs';
import { memoryCoordinator } from '../conversation/support.mjs';

const ISSUER = 'https://auth.shop.test';
const TOKEN_ENDPOINT = 'https://auth.shop.test/oauth/token';
const CLIENT = 'https://agent.test/agent.json';
const JWKS_URI = 'https://agent.test/jwks.json';
const RESOURCE = 'https://api.shop.test/special';
const API = 'https://api.shop.test/poppy/conversations';

function memoryStore(initial) {
  let state = structuredClone(initial);
  return {
    async read() { return structuredClone(state); },
    async transaction(change) { const draft = structuredClone(state); const result = change(draft); state = draft; return structuredClone(result); },
    get state() { return state; },
    set state(value) { state = value; },
  };
}

async function setup(overrides = {}) {
  const identity = await keyPair(); const dpopKey = await keyPair();
  const clock = { now: NOW };
  const jwk = kp => ({ ...kp.jwk, kid: 'k1', alg: 'ES256', use: 'sig' });
  const env = { identity, dpopKey, clock, store: memoryStore(initialIssuerState()), calls: { client: 0, jwks: 0, refresh: 0 } };
  env.jwks = { keys: [jwk(identity)] }; env.refreshedJwks = env.jwks;
  env.metadata = {
    async resolveClient(id) { env.calls.client++; if (id !== CLIENT) throw new Error('unknown client'); return { client_id: CLIENT, client_name: 'Agent', jwks_uri: JWKS_URI, redirect_uris: [], token_endpoint_auth_method: 'private_key_jwt' }; },
    async resolveJwks(uri, settings = {}) { assert.equal(uri, JWKS_URI); if (settings.refresh) { env.calls.refresh++; return structuredClone(env.refreshedJwks); } env.calls.jwks++; await env.onJwks?.(); return structuredClone(env.jwks); },
  };
  env.issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, poppyDomains: ['shop.test'], resources: [RESOURCE], metadata: env.metadata, store: env.store, coordinator: memoryCoordinator(), now: () => clock.now, ...overrides });
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
const expectError = (response, error, status = error === 'invalid_client' ? 401 : 400) => {
  assert.deepEqual(response.body, { error }); assert.equal(response.status, status); assert.equal(response.headers.get('cache-control'), 'no-store');
};

test('issues and renews a signed-out DPoP session after a nonce challenge', async () => {
  const env = await setup();
  const challenge = await env.challenge();
  assert.equal(challenge.status, 400); assert.equal(challenge.headers.get('cache-control'), 'no-store'); assert.ok(env.nonce.length >= 16);
  const first = await env.send();
  assert.equal(first.status, 200); assert.equal(first.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Object.keys(first.body).sort(), ['access_token', 'expires_in', 'scope', 'session_id', 'signed_in', 'token_type']);
  assert.equal(first.body.token_type, 'DPoP'); assert.equal(first.body.expires_in, 3600); assert.equal(first.body.scope, ''); assert.equal(first.body.signed_in, false);
  assert.ok(Buffer.from(first.body.access_token, 'base64url').length >= 32);
  assert.ok(!JSON.stringify(env.store.state).includes(first.body.access_token), 'plaintext token is not persisted');
  const renewed = await env.send({ session_id: first.body.session_id });
  assert.equal(renewed.status, 200); assert.equal(renewed.body.session_id, first.body.session_id); assert.notEqual(renewed.body.access_token, first.body.access_token);

  const authenticator = createRequestAuthenticator({ authority: env.issuer.authority, endpoints: [{ origin: 'https://api.shop.test', pathPrefix: '/poppy' }], now: () => env.clock.now });
  const resourceProof = await proof(env.dpopKey, { htu: API, iat: NOW / 1000, token: renewed.body.access_token });
  const principal = await authenticator.authenticate(new Request(API, { method: 'POST', headers: { authorization: `DPoP ${renewed.body.access_token}`, dpop: resourceProof } }));
  assert.deepEqual(principal, { issuer: ISSUER, clientId: CLIENT, userId: 'usr_1', sessionId: first.body.session_id, scopes: [], tokenExpiresAt: NOW + 3600_000, sessionVersion: 1, issuerGeneration: env.store.state.generation });
  assert.deepEqual(env.issuer.authorizationMetadata(), { issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT, revocation_endpoint: `${ISSUER}/oauth/revoke`, dpop_signing_alg_values_supported: ['ES256'], client_id_metadata_document_supported: true, poppy_domains: ['shop.test'] });
});

test('nonce challenge precedes network fetches and replay consumption, and nonce state stays bounded', async () => {
  const env = await setup();
  const assertion = await env.assertion(); const clientAssertion = await env.clientAssertion();
  const missing = await env.send({ assertion, client_assertion: clientAssertion });
  expectError(missing, 'use_dpop_nonce'); env.nonce = missing.headers.get('dpop-nonce');
  assert.deepEqual(env.calls, { client: 0, jwks: 0, refresh: 0 }); assert.deepEqual(env.store.state.replay, {});
  assert.equal((await env.send({ assertion, client_assertion: clientAssertion })).status, 200, 'same assertions usable after the challenge');
  const wrong = await env.send({}, { dpop: await env.proof({ nonce: 'not-issued-by-us-0000' }) });
  expectError(wrong, 'use_dpop_nonce'); assert.equal(wrong.headers.get('dpop-nonce'), env.nonce, 'current nonce is reused');
  env.clock.now += 301_000;
  const expired = await env.send(); expectError(expired, 'use_dpop_nonce'); assert.notEqual(expired.headers.get('dpop-nonce'), env.nonce);
  for (let i = 0; i < 5; i++) { env.clock.now += 200_000; await env.send({}, { dpop: await env.proof({ nonce: undefined }) }); }
  assert.ok(env.store.state.nonces.length <= 2);
  const noNonce = await setup({ requireDpopNonce: false });
  assert.equal((await noNonce.send()).status, 200);
});

test('client assertion defects are invalid_client', async () => {
  const env = await setup(); await env.challenge(); const other = await keyPair(); const now = Math.floor(NOW / 1000);
  const cases = {
    signature: await env.clientAssertion({}, { key: other }),
    audienceEndpoint: await env.clientAssertion({ aud: TOKEN_ENDPOINT }),
    audienceArray: await env.clientAssertion({ aud: [ISSUER] }),
    audienceOtherIssuer: await env.clientAssertion({ aud: 'https://auth.other.test' }),
    lifetimeTooLong: await env.clientAssertion({ iat: now, exp: now + 301 }),
    expired: await env.clientAssertion({ iat: now - 120, exp: now - 60 }),
    futureIat: await env.clientAssertion({ iat: now + 30, exp: now + 90 }),
    issuer: await env.clientAssertion({ iss: 'https://agent.test/other.json' }),
    subject: await env.clientAssertion({ sub: 'usr_1' }),
    shortJti: await env.clientAssertion({ jti: 'short' }),
    hmac: await new SignJWT({ iss: CLIENT, sub: CLIENT, aud: ISSUER, iat: now, exp: now + 60, jti: randomUUID() }).setProtectedHeader({ alg: 'HS256', kid: 'k1' }).sign(new Uint8Array(32)),
  };
  for (const [name, client_assertion] of Object.entries(cases)) await assert.doesNotReject(async () => expectError(await env.send({ client_assertion }), 'invalid_client'), name);
  expectError(await env.send({ client_id: 'https://agent.test/unknown.json' }), 'invalid_client');
  expectError(await env.send({ client_assertion_type: 'urn:other' }), 'invalid_client');
  assert.equal((await env.send()).status, 200, 'a valid request still succeeds');
  expectError(await env.send({ client_assertion: undefined }), 'invalid_client');
});

test('session assertion defects, reuse and cross-role jti reuse are invalid_grant', async () => {
  const env = await setup(); await env.challenge(); const other = await keyPair(); const now = Math.floor(NOW / 1000);
  const cases = {
    signature: await env.assertion({}, { key: other }),
    audience: await env.assertion({ aud: TOKEN_ENDPOINT }),
    issuer: await env.assertion({ iss: 'https://agent.test/other.json' }),
    expired: await env.assertion({ iat: now - 120, exp: now - 1 }),
    lifetimeTooLong: await env.assertion({ iat: now, exp: now + 301 }),
    longSubject: await env.assertion({ sub: 'u'.repeat(257) }),
  };
  for (const [name, assertion] of Object.entries(cases)) await assert.doesNotReject(async () => expectError(await env.send({ assertion }), 'invalid_grant'), name);
  expectError(await env.send({ assertion: undefined }), 'invalid_grant');
  expectError(await env.send({ assertion: await env.assertion({}, { header: { typ: 'poppy-browser+jwt' } }) }), 'invalid_grant');
  expectError(await env.send({ client_assertion: await env.clientAssertion({}, { header: { typ: 'poppy-browser+jwt' } }) }), 'invalid_client');
  for (const typ of ['application/poppy-browser+jwt', 'Poppy-Browser+JWT', 'APPLICATION/poppy-browser+jwt']) {
    expectError(await env.send({ assertion: await env.assertion({}, { header: { typ } }) }), 'invalid_grant');
  }
  assert.equal((await env.send({ client_assertion: await env.clientAssertion({}, { header: { typ: 'client-authentication+jwt' } }) })).status, 200);
  const sameJti = randomUUID();
  expectError(await env.send({ assertion: await env.assertion({ jti: sameJti }), client_assertion: await env.clientAssertion({ jti: sameJti }) }), 'invalid_grant');
  const assertion = await env.assertion(); const clientJti = randomUUID();
  assert.equal((await env.send({ assertion, client_assertion: await env.clientAssertion({ jti: clientJti }) })).status, 200);
  expectError(await env.send({ assertion }), 'invalid_grant');
  expectError(await env.send({ assertion: await env.assertion({ jti: clientJti }) }), 'invalid_grant');
  const reusedClient = await env.clientAssertion();
  assert.equal((await env.send({ client_assertion: reusedClient })).status, 200);
  expectError(await env.send({ client_assertion: reusedClient }), 'invalid_grant');
  assert.equal(Object.keys(env.store.state.sessions).length, 3);
});

test('replay retention survives a restart and expires with the assertion', async () => {
  const env = await setup(); await env.challenge();
  const assertion = await env.assertion();
  assert.equal((await env.send({ assertion })).status, 200);
  const restarted = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, poppyDomains: ['shop.test'], metadata: env.metadata, store: env.store, coordinator: memoryCoordinator(), now: () => env.clock.now });
  env.issuer = restarted;
  expectError(await env.send({ assertion }), 'invalid_grant');
  env.clock.now += 61_000; env.nonce = undefined; await env.challenge();
  assert.equal((await env.send()).status, 200);
  assert.ok(Object.values(env.store.state.replay).every(until => until >= env.clock.now), 'expired replay entries are pruned');
});

test('freshness is rechecked at commit when the clock advances during the JWKS fetch', async () => {
  const env = await setup(); await env.challenge(); const t0 = Math.floor(NOW / 1000);
  const long = { iat: t0 + 50, exp: t0 + 350 };
  const replayed = await env.proof();
  assert.equal((await env.send({}, { dpop: replayed })).status, 200);
  env.clock.now = NOW + 59_000; env.onJwks = () => { env.clock.now += 2_000; };
  expectError(await env.send({ assertion: await env.assertion(long), client_assertion: await env.clientAssertion(long) }, { dpop: replayed }), 'invalid_dpop_proof');
  env.clock.now = NOW + 59_000;
  expectError(await env.send({ assertion: await env.assertion(long), client_assertion: await env.clientAssertion({ iat: t0, exp: t0 + 60 }) }), 'invalid_client');
  env.clock.now = NOW + 59_000;
  expectError(await env.send({ assertion: await env.assertion({ iat: t0, exp: t0 + 60 }), client_assertion: await env.clientAssertion(long) }), 'invalid_grant');
  assert.equal(Object.keys(env.store.state.sessions).length, 1);
});

test('token-endpoint DPoP proofs are verified against the configured URL with replay and key separation', async () => {
  const env = await setup(); await env.challenge();
  const replayed = await env.proof();
  assert.equal((await env.send({}, { dpop: replayed })).status, 200);
  expectError(await env.send({}, { dpop: replayed }), 'invalid_dpop_proof');
  const internal = 'https://10.0.0.5:8443/oauth/token';
  expectError(await env.send({}, { url: internal, dpop: await env.proof({ htu: internal }), headers: { 'x-forwarded-host': 'auth.shop.test', forwarded: 'host=auth.shop.test;proto=https' } }), 'invalid_dpop_proof');
  assert.equal((await env.send({}, { url: internal })).status, 200, 'htu is the configured endpoint regardless of the Request URL');
  const cases = {
    missing: null,
    method: await env.proof({ htm: 'GET' }),
    url: await env.proof({ htu: `${ISSUER}/oauth/other` }),
    ath: await env.proof({ token: 'some-token' }),
    old: await env.proof({ iat: NOW / 1000 - 61 }),
    identityKeyAsDpopKey: await env.proof({ key: env.identity }),
    privateJwk: await env.proof({ header: { jwk: env.dpopKey.privateJwk } }),
    longJti: await env.proof({ jti: 'j'.repeat(257) }),
  };
  for (const [name, dpop] of Object.entries(cases)) await assert.doesNotReject(async () => expectError(await env.send({}, { dpop }), 'invalid_dpop_proof'), name);
});

test('unknown kid triggers exactly one JWKS refresh', async () => {
  const env = await setup(); await env.challenge();
  const rotated = await keyPair(); env.refreshedJwks = { keys: [{ ...rotated.jwk, kid: 'k2', alg: 'ES256' }] };
  const signed = async (sub) => env.assertion({ sub }, { key: rotated, header: { kid: 'k2' } });
  assert.equal((await env.send({ assertion: await signed('usr_1'), client_assertion: await signed(CLIENT) })).status, 200);
  assert.equal(env.calls.refresh, 1);
  expectError(await env.send({ client_assertion: await env.clientAssertion({}, { key: rotated, header: { kid: 'k9' } }) }), 'invalid_client');
  assert.equal(env.calls.refresh, 2, 'one refresh per request, and the resolver bounds repeats');
});

test('session, scope, resource and request shape checks', async () => {
  const env = await setup(); await env.challenge();
  const first = await env.send();
  expectError(await env.send({ session_id: first.body.session_id, assertion: await env.assertion({ sub: 'usr_2' }) }), 'invalid_session');
  expectError(await env.send({ session_id: 'ses_missing' }), 'invalid_session');
  expectError(await env.send({ session_id: '__proto__' }), 'invalid_session');
  expectError(await env.send({ scope: 'poppy:read' }), 'invalid_scope');
  expectError(await env.send({ resource: 'https://api.shop.test/other' }), 'invalid_target');
  expectError(await env.send({ grant_type: 'password' }), 'unsupported_grant_type');
  expectError(await env.send({ grant_type: undefined }), 'invalid_request');
  const duplicated = await env.issuer.token(new Request(TOKEN_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', dpop: await env.proof() }, body: 'grant_type=a&grant_type=b' }));
  assert.equal(duplicated.status, 400); assert.deepEqual(await duplicated.json(), { error: 'invalid_request' });
  const json = await env.issuer.token(new Request(TOKEN_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }));
  assert.equal(json.status, 400);
  // Rejected before reading: the unread body stream is cancelled, not left open.
  for (const [contentType, length] of [['application/json', undefined], ['application/x-www-form-urlencoded', '65537']]) {
    let cancelled = false;
    const body = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(1)); }, cancel() { cancelled = true; } });
    const rejected = await env.issuer.token(new Request(TOKEN_ENDPOINT, { method: 'POST', headers: { 'content-type': contentType, ...(length ? { 'content-length': length } : {}) }, body, duplex: 'half' }));
    assert.equal(rejected.status, 400); assert.ok(cancelled, contentType);
  }

  const declared = await env.issuer.token(new Request(TOKEN_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': '65537' }, body: 'grant_type=x' }));
  assert.equal(declared.status, 400); assert.deepEqual(await declared.json(), { error: 'invalid_request' });
  let pulled = 0; // endless stream: the reader must stop on its own once the limit is passed
  const endless = new ReadableStream({ pull(controller) { pulled++; controller.enqueue(new Uint8Array(16384).fill(97)); } });
  const streamed = await env.issuer.token(new Request(TOKEN_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: endless, duplex: 'half' }));
  assert.equal(streamed.status, 400); assert.deepEqual(await streamed.json(), { error: 'invalid_request' }); assert.ok(pulled <= 6);
  const multibyte = await env.issuer.token(new Request(TOKEN_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'é'.repeat(40000) }));
  assert.equal(multibyte.status, 400, 'limit counts bytes, not UTF-16 units');

  const scoped = await env.send({ resource: RESOURCE });
  assert.equal(scoped.status, 200);
  const authority = env.issuer.authority;
  assert.equal((await authority.introspect(scoped.body.access_token, RESOURCE)).principal.sessionId, scoped.body.session_id);
  await assert.rejects(authority.introspect(scoped.body.access_token), { code: 'invalid_token' });
  await assert.rejects(authority.introspect(first.body.access_token, RESOURCE), { code: 'invalid_token' });
  await assert.rejects(authority.introspect('unknown'), { code: 'invalid_token' });
  env.clock.now += 3600_000;
  await assert.rejects(authority.introspect(first.body.access_token), { code: 'invalid_token' });
});

test('a reset between verification and commit fails issuance without recreating state', async () => {
  const env = await setup(); await env.challenge();
  env.onJwks = () => { env.store.state = initialIssuerState(); };
  expectError(await env.send(), 'invalid_grant');
  assert.deepEqual(env.store.state.sessions, {}); assert.deepEqual(env.store.state.replay, {});
});

test('store failures propagate instead of becoming protocol errors', async () => {
  const env = await setup({ requireDpopNonce: false });
  env.store.transaction = async () => { throw new Error('disk full'); };
  await assert.rejects(env.send(), /disk full/);
});

test('the core entry point does not load the reference issuer module', async () => {
  const { readFile } = await import('node:fs/promises');
  const { fileURLToPath } = await import('node:url');
  const seen = new Set(); const queue = [new URL('../../dist/index.js', import.meta.url)];
  while (queue.length) {
    const file = queue.pop(); if (seen.has(file.href)) continue; seen.add(file.href);
    const source = await readFile(fileURLToPath(file), 'utf8');
    for (const [, specifier] of source.matchAll(/(?:from|import)\s*\(?\s*'(\.[^']+)'/g)) queue.push(new URL(specifier, file));
  }
  assert.ok(seen.size > 3);
  assert.ok([...seen].every(href => !href.includes('reference-auth')));
});
