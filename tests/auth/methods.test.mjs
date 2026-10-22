import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SqliteCompanyDatabase } from '../../dist/sqlite.js';
import { createReferenceIssuer } from '../../dist/reference-auth/index.js';
import { setup, ISSUER, CLIENT, OTHER_CLIENT, TOKEN_ENDPOINT } from './issuer-support.mjs';

const DEVICE = `${ISSUER}/device`, VERIFY = `${ISSUER}/verify`, MEDIATED = `${ISSUER}/sign-in`;
const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const BROWSER = 'trusted-browser-session-binding-123456';
const read = async response => ({ status: response.status, headers: response.headers, body: await response.json() });
async function startDevice(env, scopes = 'poppy:read poppy:write') {
  return read(await env.issuer.deviceAuthorization(new Request(DEVICE, { method: 'POST', body: new URLSearchParams({ scope: scopes, client_id: CLIENT, client_assertion_type: TYPE, client_assertion: await env.clientAssertion() }) })));
}
const pollDevice = (env, deviceCode, sessionId, extra = {}) => env.send({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', assertion: undefined, device_code: deviceCode, session_id: sessionId, ...extra });
async function mediated(env, token, input, id = '') {
  const endpoint = MEDIATED + (id ? `/${id}` : '');
  return read(await env.issuer.mediatedSignIn(new Request(endpoint, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `DPoP ${token}`, dpop: await env.proof({ htu: endpoint, token, nonce: undefined }) }, body: JSON.stringify(input) })));
}
async function environment(t, durable, extra = {}) {
  const dir = durable ? await mkdtemp(join(tmpdir(), 'poppy-methods-')) : undefined;
  const db = durable ? new SqliteCompanyDatabase(join(dir, 'issuer.db')) : undefined;
  if (db) t.after(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });
  const seen = [], config = { endpoint: MEDIATED, scopes: ['poppy:read', 'poppy:write'], fields: [{ name: 'password', label: 'Password', secret: true }],
    authenticate: async credentials => { seen.push(credentials); return credentials.password === 'private-password' ? { accountId: 'acct_1' } : null; }, verifyCode: async ({ code }) => code === '123456', ...extra };
  const env = await setup({ requireDpopNonce: false, device: { endpoint: DEVICE, verificationUri: VERIFY, scopes: ['poppy:read', 'poppy:write'] }, mediated: config,
    ...(db ? { store: db.issuer(ISSUER), coordinator: db } : {}) });
  const reopen = () => createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, poppyDomains: ['shop.test'], directScopes: [], metadata: env.metadata,
    store: db ? db.issuer(ISSUER) : env.store, coordinator: db ?? { run: action => action() }, now: () => env.clock.now, requireDpopNonce: false,
    device: { endpoint: DEVICE, verificationUri: VERIFY, scopes: ['poppy:read', 'poppy:write'] }, mediated: config });
  return Object.assign(env, { db, seen, config, reopen });
}

for (const durable of [false, true]) {
  test(`Device approval/partial consent, interval, one-use code and revocation (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable), session = (await env.send()).body;
    const start = await startDevice(env); assert.equal(start.status, 200); assert.equal(start.headers.get('cache-control'), 'no-store');
    env.issuer = env.reopen();
    assert.equal(new URL(start.body.verification_uri).host, new URL(ISSUER).host);
    const view = await env.issuer.beginDeviceAuthorization(start.body.user_code, BROWSER);
    assert.deepEqual(view.scopes, ['poppy:read', 'poppy:write']);
    assert.equal((await pollDevice(env, start.body.device_code, session.session_id)).body.error, 'slow_down');
    await env.issuer.completeDeviceAuthorization(start.body.user_code, BROWSER, { accountId: 'acct_1', scopes: ['poppy:read'] });
    env.clock.now += 10000;
    const grant = await pollDevice(env, start.body.device_code, session.session_id);
    assert.equal(grant.status, 200); assert.equal(grant.body.scope, 'poppy:read'); assert.ok(grant.body.refresh_token);
    assert.equal((await pollDevice(env, start.body.device_code, session.session_id)).body.error, 'invalid_grant');
    const principal = await env.issuer.authority.introspect(grant.body.access_token); assert.equal(principal.principal.accountId, 'acct_1');
    await env.issuer.disconnect(CLIENT, 'acct_1'); await assert.rejects(env.issuer.authority.introspect(grant.body.access_token), { code: 'invalid_token' });
    assert.equal(env.issuer.authorizationMetadata().device_authorization_endpoint, DEVICE);
  });
  test(`Device pending, denial, expiry, wrong client and account mismatch (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable), session = (await env.send()).body;
    const start = (await startDevice(env)).body; env.clock.now += 5000;
    assert.equal((await pollDevice(env, start.device_code, session.session_id)).body.error, 'authorization_pending');
    assert.equal((await pollDevice(env, start.device_code, session.session_id, { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }) })).body.error, 'invalid_grant');
    await env.issuer.beginDeviceAuthorization(start.user_code, BROWSER);
    await assert.rejects(env.issuer.completeDeviceAuthorization(start.user_code, 'wrong-browser-binding-000000', { denied: true }));
    await env.issuer.completeDeviceAuthorization(start.user_code, BROWSER, { denied: true });
    assert.equal((await pollDevice(env, start.device_code, session.session_id)).body.error, 'access_denied');
    const expired = (await startDevice(env)).body; env.clock.now += 601000;
    assert.equal((await pollDevice(env, expired.device_code, session.session_id)).body.error, 'expired_token');
    for (const accountId of ['acct_1', 'acct_2']) {
      const next = (await startDevice(env)).body; await env.issuer.beginDeviceAuthorization(next.user_code, BROWSER);
      await env.issuer.completeDeviceAuthorization(next.user_code, BROWSER, { accountId, scopes: ['poppy:read'] }); env.clock.now += 5000;
      const result = await pollDevice(env, next.device_code, session.session_id);
      assert.equal(result.status, accountId === 'acct_1' ? 200 : 400);
      if (accountId === 'acct_2') assert.equal(result.body.error, 'account_mismatch');
    }
  });
  test(`Mediated completion, credential disposal, requested scopes and same-account binding (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable, { authenticate: async credentials => { env.seen.push(credentials); return { accountId: credentials.password === 'other-account' ? 'acct_2' : 'acct_1', scopes: ['poppy:read'] }; } });
    const session = (await env.send()).body;
    const grant = await mediated(env, session.access_token, { scope: 'poppy:read poppy:write', credentials: { password: 'private-password' } });
    assert.equal(grant.status, 200); assert.equal(grant.body.status, 'complete'); assert.equal(grant.body.scope, 'poppy:read');
    assert.equal(JSON.stringify(grant.body).includes('private-password'), false); assert.ok(env.seen.every(value => Object.keys(value).length === 0));
    const mismatch = await mediated(env, grant.body.access_token, { scope: 'poppy:read', credentials: { password: 'other-account' } });
    assert.equal(mismatch.body.error, 'account_mismatch');
    await env.issuer.disconnect(CLIENT, 'acct_1');
    assert.equal((await mediated(env, grant.body.access_token, { scope: 'poppy:read', credentials: { password: 'private-password' } })).body.error, 'invalid_token');
  });
  test(`Mediated challenge/session correlation, wrong-code bound and terminal tombstones (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable, { maxCodeAttempts: 2, authenticate: async () => ({ accountId: 'acct_1', challenge: { id: 'host-challenge', sentTo: 'Your phone' } }) });
    const a = (await env.send()).body, b = (await env.send()).body;
    const first = await mediated(env, a.access_token, { scope: 'poppy:read', credentials: { password: 'private-password' } });
    assert.equal(first.body.status, 'code_required'); const id = first.body.sign_in_id;
    assert.equal((await mediated(env, b.access_token, { code: '123456' }, id)).body.error, 'sign_in_not_found');
    assert.equal((await mediated(env, b.access_token, { code: '123456' }, 'unknown')).body.error, 'sign_in_not_found');
    assert.equal((await mediated(env, a.access_token, { code: 'wrong' }, id)).body.status, 'code_required');
    assert.equal((await mediated(env, a.access_token, { code: 'wrong' }, id)).body.status, 'failed');
    assert.equal((await mediated(env, a.access_token, { code: '123456' }, id)).body.status, 'failed');
    const next = await mediated(env, a.access_token, { scope: 'poppy:read', credentials: { password: 'private-password' } });
    env.clock.now += 601000;
    assert.equal((await mediated(env, a.access_token, { code: '123456' }, next.body.sign_in_id)).body.status, 'expired');
    assert.equal((await mediated(env, a.access_token, { code: '123456' }, next.body.sign_in_id)).body.status, 'expired');
  });
}

test('Mediated attempt windows persist across issuer reconstruction and do not leak hook errors', async t => {
  const env = await environment(t, true, { maxAttemptsPerMinute: 2, authenticate: async () => null });
  const session = (await env.send()).body, input = { scope: 'poppy:read', credentials: { password: 'never-log-this' } };
  assert.equal((await mediated(env, session.access_token, input)).body.status, 'failed');
  assert.equal((await mediated(env, session.access_token, input)).body.status, 'failed');
  env.issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, poppyDomains: ['shop.test'], directScopes: [], metadata: env.metadata,
    store: env.db.issuer(ISSUER), coordinator: env.db, now: () => env.clock.now, requireDpopNonce: false, mediated: env.config });
  const limited = await mediated(env, session.access_token, input);
  assert.equal(limited.status, 429); assert.equal(limited.headers.get('retry-after'), '60');
  env.clock.now += 60000; assert.equal((await mediated(env, session.access_token, input)).body.status, 'failed');
  env.config.authenticate = async () => { throw new Error('never-log-this'); };
  const failed = await mediated(env, session.access_token, input);
  assert.equal(failed.status, 503); assert.deepEqual(failed.body, { error: 'temporarily_unavailable' });
});

for (const durable of [false, true]) test(`disconnect cancels delayed credential checks and completed account tombstones (${durable ? 'SQLite' : 'memory'})`, async t => {
  let deliver, waiting;
  const ready = new Promise(resolve => { waiting = resolve; });
  const env = await environment(t, durable, { authenticate: async () => { waiting(); return new Promise(resolve => { deliver = resolve; }); } });
  const session = (await env.send()).body;
  const active = mediated(env, session.access_token, { scope: 'poppy:read', credentials: { password: 'private-password' } });
  await ready; await env.issuer.disconnect(CLIENT, 'acct_1'); deliver({ accountId: 'acct_1' });
  const result = await active; assert.equal(result.body.error, 'invalid_grant'); assert.equal(result.status, 400);
  if (durable) assert.equal((await env.db.issuer(ISSUER).read({ kind: 'principal', sessionId: session.session_id })).sessions[session.session_id].grantId, null);
  else assert.deepEqual(env.store.state.grants, {});
});

for (const durable of [false, true]) test(`terminal method records do not consume pending quota (${durable ? 'SQLite' : 'memory'})`, async t => {
  const env = await environment(t, durable);
  const options = { issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, poppyDomains: ['shop.test'], directScopes: [], metadata: env.metadata,
    store: env.db ? env.db.issuer(ISSUER) : env.store, coordinator: env.db ?? { run: action => action() }, now: () => env.clock.now, requireDpopNonce: false, maxPendingAuthorizations: 1,
    device: { endpoint: DEVICE, verificationUri: VERIFY, scopes: ['poppy:read'] }, mediated: env.config };
  env.issuer = createReferenceIssuer(options);
  const start = (await startDevice(env, 'poppy:read')).body;
  assert.equal((await startDevice(env, 'poppy:read')).status, 429);
  await env.issuer.beginDeviceAuthorization(start.user_code, BROWSER); await env.issuer.completeDeviceAuthorization(start.user_code, BROWSER, { denied: true });
  const next = await startDevice(env, 'poppy:read'); assert.equal(next.status, 200);
  await env.issuer.beginDeviceAuthorization(next.body.user_code, BROWSER); await env.issuer.completeDeviceAuthorization(next.body.user_code, BROWSER, { denied: true });
  const session = (await env.send()).body;
  assert.equal((await mediated(env, session.access_token, { scope: 'poppy:read', credentials: { password: 'private-password' } })).body.status, 'complete');
  assert.equal((await mediated(env, session.access_token, { scope: 'poppy:read', credentials: { password: 'private-password' } })).body.status, 'complete');
});

test('Mediated challenge verifies once under concurrency and rejects non-boolean host decisions', async t => {
  let deliver, waiting; const ready = new Promise(resolve => { waiting = resolve; });
  const env = await environment(t, true, { authenticate: async () => ({ accountId: 'acct_1', challenge: { id: 'host-id', sentTo: 'Your phone' } }), verifyCode: async () => { waiting(); return new Promise(resolve => { deliver = resolve; }); } });
  const session = (await env.send()).body, first = await mediated(env, session.access_token, { scope: 'poppy:read', credentials: { password: 'private-password' } });
  const active = mediated(env, session.access_token, { code: '123456' }, first.body.sign_in_id); await ready;
  assert.equal((await mediated(env, session.access_token, { code: '123456' }, first.body.sign_in_id)).status, 429);
  deliver('false'); const invalid = await active; assert.equal(invalid.status, 503); assert.equal(invalid.body.error, 'temporarily_unavailable');
  assert.equal((await env.db.issuer(ISSUER).read({ kind: 'principal', sessionId: session.session_id })).sessions[session.session_id].grantId, null);
});

for (const durable of [false, true]) test(`account-specific disconnect fences preserve unrelated pending users (${durable ? 'SQLite' : 'memory'})`, async t => {
  const env = await environment(t, durable);
  const deviceA = (await startDevice(env)).body, deviceB = (await startDevice(env)).body;
  await env.issuer.beginDeviceAuthorization(deviceA.user_code, BROWSER); await env.issuer.beginDeviceAuthorization(deviceB.user_code, BROWSER);
  await env.issuer.disconnect(CLIENT, 'acct_A'); env.issuer = env.reopen();
  await assert.rejects(env.issuer.completeDeviceAuthorization(deviceA.user_code, BROWSER, { accountId: 'acct_A', scopes: ['poppy:read'] }));
  await env.issuer.completeDeviceAuthorization(deviceB.user_code, BROWSER, { accountId: 'acct_B', scopes: ['poppy:read'] });
  const sessionB = (await env.send()).body; env.clock.now += 5000;
  assert.equal((await pollDevice(env, deviceB.device_code, sessionB.session_id)).status, 200);
  // New explicit consent after disconnect captures the new revision.
  const fresh = (await startDevice(env)).body; await env.issuer.beginDeviceAuthorization(fresh.user_code, BROWSER);
  await env.issuer.completeDeviceAuthorization(fresh.user_code, BROWSER, { accountId: 'acct_A', scopes: ['poppy:read'] });
});

for (const durable of [false, true]) test(`delayed Mediated checks resolving other accounts survive disconnect (${durable ? 'SQLite' : 'memory'})`, async t => {
  const pending = new Map(); let waiting; const ready = new Promise(resolve => { waiting = resolve; });
  const env = await environment(t, durable, { authenticate: async credentials => new Promise(resolve => { pending.set(credentials.password, resolve); if (pending.size === 2) waiting(); }) });
  const a = (await env.send()).body, b = (await env.send()).body;
  const activeA = mediated(env, a.access_token, { scope: 'poppy:read', credentials: { password: 'A' } });
  const activeB = mediated(env, b.access_token, { scope: 'poppy:read', credentials: { password: 'B' } });
  await ready; await env.issuer.disconnect(CLIENT, 'acct_A'); env.issuer = env.reopen();
  pending.get('A')({ accountId: 'acct_A' }); pending.get('B')({ accountId: 'acct_B' });
  assert.equal((await activeA).body.error, 'invalid_grant'); assert.equal((await activeB).body.status, 'complete');
});

test('Device nonce challenge uses fresh assertions and proof before consuming the code', async t => {
  const env = await environment(t, true);
  env.issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, poppyDomains: ['shop.test'], directScopes: [], metadata: env.metadata,
    store: env.db.issuer(ISSUER), coordinator: env.db, now: () => env.clock.now, device: { endpoint: DEVICE, verificationUri: VERIFY, scopes: ['poppy:read'] } });
  await env.challenge(); const session = (await env.send()).body, start = (await startDevice(env, 'poppy:read')).body;
  await env.issuer.beginDeviceAuthorization(start.user_code, BROWSER); await env.issuer.completeDeviceAuthorization(start.user_code, BROWSER, { accountId: 'acct_1', scopes: ['poppy:read'] });
  env.clock.now += 5000;
  const challenge = await env.send({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', assertion: undefined, device_code: start.device_code, session_id: session.session_id }, { dpop: await env.proof({ nonce: undefined }) });
  assert.equal(challenge.body.error, 'use_dpop_nonce');
  assert.equal((await pollDevice(env, start.device_code, session.session_id)).status, 200);
});
