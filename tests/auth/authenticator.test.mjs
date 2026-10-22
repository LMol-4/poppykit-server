import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateJwkThumbprint } from 'jose';
import { createRequestAuthenticator, AuthorityError } from '../../dist/index.js';
import { NOW, keyPair, proof } from './support.mjs';

const ENDPOINT = 'https://api.shop.test/poppy/conversations';
const TOKEN = 'opaque-session-token';
const principal = { issuer: 'https://auth.shop.test', clientId: 'https://agent.test/agent.json', userId: 'usr_1', sessionId: 'ses_1', scopes: [], tokenExpiresAt: NOW + 3600_000, sessionVersion: 1 };

async function setup({ endpoints = [{ origin: 'https://api.shop.test', pathPrefix: '/poppy' }], expiresAt = principal.tokenExpiresAt } = {}) {
  const key = await keyPair(); const jkt = await calculateJwkThumbprint(key.jwk); const calls = [];
  const authority = { async introspect(token, resource) { calls.push({ token, resource }); if (token !== TOKEN) throw new AuthorityError('invalid_token'); return { principal: { ...principal, tokenExpiresAt: expiresAt }, dpopJkt: jkt }; } };
  return { key, calls, authenticator: createRequestAuthenticator({ authority, endpoints, now: () => NOW }) };
}
const request = (url, headers, method = 'POST') => new Request(url, { method, headers });
async function rejects(promise, code) {
  await assert.rejects(promise, error => error instanceof AuthorityError && error.code === code && error.headers.get('www-authenticate').startsWith(`DPoP error="${code}"`) && !error.headers.get('www-authenticate').includes(TOKEN));
}

test('accepts a DPoP-bound token at a configured endpoint and passes the endpoint resource', async () => {
  const { key, calls, authenticator } = await setup({ endpoints: [{ origin: 'https://api.shop.test', pathPrefix: '/poppy' }, { origin: 'https://api.shop.test', pathPrefix: '/poppy/special', resource: 'https://api.shop.test/special' }] });
  const result = await authenticator.authenticate(request(`${ENDPOINT}?wait=5`, { authorization: `DPoP ${TOKEN}`, dpop: await proof(key, { htu: ENDPOINT, token: TOKEN }) }));
  assert.deepEqual(result, principal); assert.deepEqual(calls, [{ token: TOKEN, resource: undefined }]);
  const get = await proof(key, { htm: 'GET', htu: 'https://api.shop.test/poppy/special/c1', token: TOKEN });
  await authenticator.authenticate(request('https://api.shop.test/poppy/special/c1', { authorization: `dpop ${TOKEN}`, dpop: get }, 'GET'));
  assert.equal(calls[1].resource, 'https://api.shop.test/special');
});

test('rejects missing, Bearer, query and duplicated credentials as invalid_token', async () => {
  const { key, authenticator, calls } = await setup(); const dpop = await proof(key, { htu: ENDPOINT, token: TOKEN });
  await rejects(authenticator.authenticate(request(ENDPOINT, { dpop })), 'invalid_token');
  await rejects(authenticator.authenticate(request(ENDPOINT, { authorization: `Bearer ${TOKEN}`, dpop })), 'invalid_token');
  await rejects(authenticator.authenticate(request(`${ENDPOINT}?access_token=${TOKEN}`, { dpop, cookie: `token=${TOKEN}` })), 'invalid_token');
  const twice = new Headers({ dpop }); twice.append('authorization', `DPoP ${TOKEN}`); twice.append('authorization', `DPoP ${TOKEN}`);
  await rejects(authenticator.authenticate(new Request(ENDPOINT, { method: 'POST', headers: twice })), 'invalid_token');
  assert.equal(calls.length, 0);
  const error = await authenticator.authenticate(request(ENDPOINT, {})).catch(e => e); assert.equal(error.status, 401);
});

test('rejects unknown or expired tokens from the authority', async () => {
  const { key, authenticator } = await setup();
  await rejects(authenticator.authenticate(request(ENDPOINT, { authorization: 'DPoP other', dpop: await proof(key, { htu: ENDPOINT, token: 'other' }) })), 'invalid_token');
  const expired = await setup({ expiresAt: NOW });
  await rejects(expired.authenticator.authenticate(request(ENDPOINT, { authorization: `DPoP ${TOKEN}`, dpop: await proof(expired.key, { htu: ENDPOINT, token: TOKEN }) })), 'invalid_token');
});

test('URL matching uses exact configured origin and path boundary; forwarding headers are ignored', async () => {
  const { key, authenticator, calls } = await setup();
  for (const url of ['https://api.shop.test/poppyx', 'https://internal:8443/poppy/conversations', 'http://api.shop.test/poppy/conversations', 'https://evil.test/poppy/conversations']) {
    const headers = { authorization: `DPoP ${TOKEN}`, dpop: await proof(key, { htu: ENDPOINT, token: TOKEN }), 'x-forwarded-host': 'api.shop.test', 'x-forwarded-proto': 'https', forwarded: 'host=api.shop.test;proto=https' };
    await rejects(authenticator.authenticate(request(url, headers)), 'invalid_token');
  }
  assert.equal(calls.length, 0);
  assert.throws(() => createRequestAuthenticator({ authority: {}, endpoints: [{ origin: 'https://api.shop.test/', pathPrefix: '/' }], now: () => NOW }));
  assert.throws(() => createRequestAuthenticator({ authority: {}, endpoints: [{ origin: 'http://api.shop.test', pathPrefix: '/' }], now: () => NOW }));
});

test('each DPoP proof defect is rejected as invalid_dpop_proof', async () => {
  const { key, authenticator } = await setup(); const other = await keyPair();
  const cases = {
    missing: undefined,
    signature: await proof(key, { htu: ENDPOINT, token: TOKEN, signWith: other }),
    method: await proof(key, { htm: 'GET', htu: ENDPOINT, token: TOKEN }),
    url: await proof(key, { htu: 'https://api.shop.test/poppy/other', token: TOKEN }),
    host: await proof(key, { htu: 'https://evil.test/poppy/conversations', token: TOKEN }),
    hash: await proof(key, { htu: ENDPOINT, token: 'different' }),
    noHash: await proof(key, { htu: ENDPOINT }),
    old: await proof(key, { htu: ENDPOINT, token: TOKEN, iat: NOW / 1000 - 61 }),
    future: await proof(key, { htu: ENDPOINT, token: TOKEN, iat: NOW / 1000 + 31 }),
    typ: await proof(key, { htu: ENDPOINT, token: TOKEN, header: { typ: 'JWT' } }),
    privateKey: await proof(key, { htu: ENDPOINT, token: TOKEN, header: { jwk: key.privateJwk } }),
    longJti: await proof(key, { htu: ENDPOINT, token: TOKEN, jti: 'x'.repeat(257) }),
    query: await proof(key, { htu: `${ENDPOINT}?wait=5`, token: TOKEN }),
    unboundKey: await proof(other, { htu: ENDPOINT, token: TOKEN }),
    malformed: 'not-a-jwt',
  };
  for (const [name, dpop] of Object.entries(cases)) {
    const headers = { authorization: `DPoP ${TOKEN}`, ...(dpop ? { dpop } : {}) };
    await rejects(authenticator.authenticate(request(ENDPOINT, headers)), 'invalid_dpop_proof').catch(error => { throw new Error(name, { cause: error }); });
  }
  // 30 s of skew is allowed (the boundary), 31 s is not (cases above).
  await authenticator.authenticate(request(ENDPOINT, { authorization: `DPoP ${TOKEN}`, dpop: await proof(key, { htu: ENDPOINT, token: TOKEN, iat: NOW / 1000 + 30 }) }));
  const two = new Headers({ authorization: `DPoP ${TOKEN}` }); const good = await proof(key, { htu: ENDPOINT, token: TOKEN }); two.append('dpop', good); two.append('dpop', good);
  await rejects(authenticator.authenticate(new Request(ENDPOINT, { method: 'POST', headers: two })), 'invalid_dpop_proof');
});

test('AuthorityError maps codes to status and quoted challenge', () => {
  const error = new AuthorityError('insufficient_scope', { scope: 'poppy:read poppy:write' });
  assert.equal(error.status, 403); assert.equal(error.headers.get('www-authenticate'), 'DPoP error="insufficient_scope", scope="poppy:read poppy:write", algs="ES256"');
  assert.equal(new AuthorityError('sign_in_required').status, 403);
  assert.throws(() => new AuthorityError('insufficient_scope', { scope: 'a" b' }));
});
