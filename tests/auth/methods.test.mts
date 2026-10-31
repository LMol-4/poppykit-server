import type {Environment} from './issuer-support.mjs';
import type {MediatedOptions} from '../../dist/reference-auth/index.js';
import { expectValue } from '../../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SqliteCompanyDatabase } from '../../dist/sqlite.js';
import { createReferenceIssuer } from '../../dist/reference-auth/index.js';
import { setup, ISSUER, CLIENT, OTHER_CLIENT, TOKEN_ENDPOINT } from './issuer-support.mjs';
import { keyPair } from './support.mjs';
import { calculateJwkThumbprint } from 'jose';

for (const durable of [false, true]) test(`Device client ownership and poll races survive approval and reconstruction (${durable ? 'SQLite' : 'memory'})`, async t => {
  const env=await environment(t,durable),other=await keyPair(),start=(await startDevice(env)).body;env.clock.now+=5000;
  const fields={grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:start.device_code};
  const results=await Promise.all([env.send(fields),env.send(fields,{dpop:await env.proof({key:other})})]);
  assert.deepEqual(results.map(result=>result.body.error).sort(),['authorization_pending','slow_down']);
  env.issuer=env.reopen();await env.issuer.beginDeviceAuthorization(start.user_code,BROWSER);
  await env.issuer.completeDeviceAuthorization(start.user_code,BROWSER,{accountId:'account',scopes:['orders:read']});env.clock.now+=10000;
  assert.equal((await env.send({...fields,client_id:OTHER_CLIENT,client_assertion:await env.clientAssertion({iss:OTHER_CLIENT,sub:OTHER_CLIENT})})).body.error,'invalid_grant');
  const signed=await env.send(fields,{dpop:await env.proof({key:other})});assert.equal(signed.status,200);
  const principal=(await env.issuer.authority.introspect(expectValue(signed.body.access_token))).principal;
  assert.equal(principal.accountId,'account');assert.deepEqual(principal.scopes,['orders:read']);assert.equal(principal.sessionId,'');
  assert.equal((await env.send(fields)).body.error,'invalid_grant');
});
test('Device legacy pending records without client ownership cannot acquire a binding', async t => {
  const env = await environment(t, false);
  const start = (await startDevice(env)).body;
  const row = Object.values(env.store.state.signIns).find(row => row.kind === 'device')!;
  delete (row as { clientId?: string }).clientId;
  env.clock.now += 5000;
  assert.equal((await pollDevice(env, start.device_code, undefined)).body.error, 'invalid_grant');
  assert.deepEqual(env.store.state.grants, {});
});

const DEVICE = `${ISSUER}/device`, VERIFY = `${ISSUER}/verify`, MEDIATED = `${ISSUER}/sign-in`;
const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const BROWSER = 'trusted-browser-session-binding-123456';
const read = async (response:Response) => ({ status: response.status, headers: response.headers, body: await response.json() });
async function startDevice(env:Environment, scopes = 'orders:read orders:write') {
  return read(await env.issuer.deviceAuthorization(new Request(DEVICE, { method: 'POST', body: new URLSearchParams({ scope: scopes, client_id: CLIENT, client_assertion_type: TYPE, client_assertion: await env.clientAssertion() }) })));
}
const pollDevice = (env:Environment,deviceCode:string,sessionId:string|undefined,extra:Record<string,string>={}) => env.send({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', assertion: undefined, device_code: deviceCode, ...extra });
async function mediated(env:Environment,clientId:string|undefined,input:unknown,id='',key?:Awaited<ReturnType<typeof keyPair>>) {
  const value=input as {scope?:string;credentials?:Record<string,string>;code?:string};
  const client=clientId??CLIENT;
  return env.send({grant_type:'https://personalagentprotocol.org/grant/mediated-sign-in',client_id:client,client_assertion:await env.clientAssertion({iss:client,sub:client}),...(id?{sign_in_id:id,one_time_code:value.code}:{scope:value.scope,...value.credentials})},{dpop:await env.proof(key?{key}:{})});
}
async function environment(t: test.TestContext, durable: boolean, extra:Partial<MediatedOptions> = {}) {
  const dir = durable ? await mkdtemp(join(tmpdir(), 'poppy-methods-')) : undefined;
  const db = durable ? new SqliteCompanyDatabase(join(expectValue(dir), 'issuer.db')) : undefined;
  if (db) t.after(async () => { db.close(); await rm(expectValue(dir), { recursive: true, force: true }); });
  const seen:Readonly<Record<string,string>>[] = [],config:MediatedOptions = {endpoint:MEDIATED,scopes:['orders:read','orders:write'],fields:[{name:'password',label:'Password',secret:true}],
    authenticate: async credentials => { seen.push(credentials); return credentials.password === 'private-password' ? { accountId: 'acct_1' } : null; }, verifyCode: async ({ code }) => code === '123456', ...extra };
  const env = await setup({ requireDpopNonce: false, device: { endpoint: DEVICE, verificationUri: VERIFY }, mediated: config,
    ...(db ? { store: db.issuer(ISSUER), coordinator: db } : {}) });
  const reopen = () => createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, protectedResources: ['https://shop.test'], supportedScopes: ['orders:read', 'orders:write'], metadata: env.metadata,
    store: db ? db.issuer(ISSUER) : env.store, coordinator: db ?? { run: action => action() }, now: () => env.clock.now, requireDpopNonce: false,
    device: { endpoint: DEVICE, verificationUri: VERIFY }, mediated: config });
  return Object.assign(env, { db, seen, config, reopen });
}

for (const durable of [false, true]) {
  test(`Device approval/partial consent, interval, one-use code and revocation (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable), session = {clientId:CLIENT};
    const start = await startDevice(env); assert.equal(start.status, 200); assert.equal(start.headers.get('cache-control'), 'no-store');
    env.issuer = env.reopen();
    assert.equal(new URL(start.body.verification_uri).host, new URL(ISSUER).host);
    const view = await env.issuer.beginDeviceAuthorization(start.body.user_code, BROWSER);
    assert.deepEqual(view.scopes, ['orders:read', 'orders:write']);
    assert.equal((await pollDevice(env, start.body.device_code, undefined)).body.error, 'slow_down');
    await env.issuer.completeDeviceAuthorization(start.body.user_code, BROWSER, { accountId: 'acct_1', scopes: ['orders:read'] });
    env.clock.now += 10000;
    const grant = await pollDevice(env, start.body.device_code, undefined);
    assert.equal(grant.status, 200); assert.equal(grant.body.scope, 'orders:read'); assert.ok(grant.body.refresh_token);
    assert.equal((await pollDevice(env, start.body.device_code, undefined)).body.error, 'invalid_grant');
    const principal = await env.issuer.authority.introspect(expectValue(grant.body.access_token)); assert.equal(principal.principal.accountId, 'acct_1');
    await env.issuer.disconnect(CLIENT, 'acct_1'); await assert.rejects(env.issuer.authority.introspect(expectValue(grant.body.access_token)), { code: 'invalid_token' });
    assert.equal(env.issuer.authorizationMetadata().device_authorization_endpoint, DEVICE);
  });
  test(`Device pending, denial, expiry, wrong client and account mismatch (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable), session = {clientId:CLIENT};
    const start = (await startDevice(env)).body; env.clock.now += 5000;
    assert.equal((await pollDevice(env, start.device_code, undefined)).body.error, 'authorization_pending');
    assert.equal((await pollDevice(env, start.device_code, undefined, { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }) })).body.error, 'invalid_grant');
    await env.issuer.beginDeviceAuthorization(start.user_code, BROWSER);
    await assert.rejects(env.issuer.completeDeviceAuthorization(start.user_code, 'wrong-browser-binding-000000', { denied: true }));
    await env.issuer.completeDeviceAuthorization(start.user_code, BROWSER, { denied: true });
    assert.equal((await pollDevice(env, start.device_code, undefined)).body.error, 'access_denied');
    const expired = (await startDevice(env)).body; env.clock.now += 601000;
    assert.equal((await pollDevice(env, expired.device_code, undefined)).body.error, 'expired_token');
    for (const accountId of ['acct_1', 'acct_2']) {
      const next = (await startDevice(env)).body; await env.issuer.beginDeviceAuthorization(next.user_code, BROWSER);
      await env.issuer.completeDeviceAuthorization(next.user_code, BROWSER, { accountId, scopes: ['orders:read'] }); env.clock.now += 5000;
      const result = await pollDevice(env, next.device_code, undefined);
      assert.equal(result.status, 200);
      assert.equal((await env.issuer.authority.introspect(expectValue(result.body.access_token))).principal.accountId, accountId);
    }
  });
  test(`Mediated completion, credential disposal, requested scopes and same-account binding (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable, { authenticate: async (credentials: { password: string; }) => { env.seen.push(credentials); return { accountId: credentials.password === 'other-account' ? 'acct_2' : 'acct_1', scopes: ['orders:read'] }; } });
    const session = {clientId:CLIENT};
    const grant = await mediated(env, session.clientId, { scope: 'orders:read orders:write', credentials: { password: 'private-password' } });
    assert.equal(grant.status, 200); assert.equal(grant.body.error, undefined); assert.equal(grant.body.scope, 'orders:read');
    assert.equal(JSON.stringify(grant.body).includes('private-password'), false); assert.ok(env.seen.every(value => Object.keys(value).length === 0));
    const mismatch = await mediated(env, CLIENT, { scope: 'orders:read', credentials: { password: 'other-account' } });
    assert.equal(mismatch.status, 200); assert.equal((await env.issuer.authority.introspect(expectValue(mismatch.body.access_token))).principal.accountId, 'acct_2');
    await env.issuer.disconnect(CLIENT, 'acct_1');
    assert.equal((await mediated(env, CLIENT, { scope: 'orders:read', credentials: { password: 'private-password' } })).status, 200, 'fresh authenticated credential checks are independent of revoked grants');
  });
  test(`Mediated challenge/session correlation, wrong-code bound and terminal tombstones (${durable ? 'SQLite' : 'memory'})`, async t => {
    const env = await environment(t, durable, { maxCodeAttempts: 2, authenticate: async () => ({ accountId: 'acct_1', challenge: { id: 'host-challenge', sentTo: 'Your phone' } }) });
    const a = {clientId:CLIENT}, other=await keyPair(), b = {clientId:OTHER_CLIENT};
    const first = await mediated(env, a.clientId, { scope: 'orders:read', credentials: { password: 'private-password' } });
    assert.equal(first.body.error, 'code_required'); const id = first.body.sign_in_id;
    assert.equal((await mediated(env, b.clientId, { code: '123456' }, id, other)).body.error, 'invalid_grant');
    assert.equal((await mediated(env, b.clientId, { code: '123456' }, 'unknown', other)).body.error, 'invalid_grant');
    assert.equal((await mediated(env, a.clientId, { code: 'wrong' }, id)).body.error, 'code_required');
    assert.equal((await mediated(env, a.clientId, { code: 'wrong' }, id)).body.error, 'invalid_grant');
    assert.equal((await mediated(env, a.clientId, { code: '123456' }, id)).body.error, 'invalid_grant');
    const successful = await mediated(env, a.clientId, { scope: 'orders:read', credentials: { password: 'private-password' } });
    env.issuer = env.reopen();
    assert.equal((await mediated(env, a.clientId, { code: '123456' }, successful.body.sign_in_id)).status, 200);
    const next = await mediated(env, a.clientId, { scope: 'orders:read', credentials: { password: 'private-password' } });
    env.clock.now += 601000;
    assert.equal((await mediated(env, a.clientId, { code: '123456' }, next.body.sign_in_id)).body.error, 'expired_token');
    assert.equal((await mediated(env, a.clientId, { code: '123456' }, next.body.sign_in_id)).body.error, 'expired_token');
  });
}

test('Mediated attempt windows persist across issuer reconstruction and do not leak hook errors', async t => {
  const env = await environment(t, true, { maxAttemptsPerMinute: 2, authenticate: async () => null });
  const session = {clientId:CLIENT}, input = { scope: 'orders:read', credentials: { password: 'never-log-this' } };
  assert.equal((await mediated(env, session.clientId, input)).body.error, 'invalid_grant');
  assert.equal((await mediated(env, session.clientId, input)).body.error, 'invalid_grant');
  env.issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, protectedResources: ['https://shop.test'], supportedScopes: ['orders:read', 'orders:write'], metadata: env.metadata,
    store: expectValue(env.db).issuer(ISSUER), coordinator: expectValue(env.db), now: () => env.clock.now, requireDpopNonce: false, mediated: env.config });
  const limited = await mediated(env, session.clientId, input);
  assert.equal(limited.status, 429); assert.equal(limited.headers.get('retry-after'), '60');
  env.clock.now += 60000; assert.equal((await mediated(env, session.clientId, input)).body.error, 'invalid_grant');
  env.config.authenticate = async () => { throw new Error('never-log-this'); };
  const failed = await mediated(env, session.clientId, input);
  assert.equal(failed.status, 503); assert.deepEqual(failed.body, { error: 'temporarily_unavailable' });
});

for (const durable of [false, true]) test(`disconnect cancels delayed credential checks and completed account tombstones (${durable ? 'SQLite' : 'memory'})`, async t => {
  let deliver!:(value:{accountId:string}|null)=>void,waiting!:()=>void;
  const ready = new Promise<void>(resolve => { waiting = resolve; });
  const env = await environment(t, durable, { authenticate: async () => { waiting(); return new Promise(resolve => { deliver = resolve; }); } });
  const session = {clientId:CLIENT};
  const active = mediated(env, session.clientId, { scope: 'orders:read', credentials: { password: 'private-password' } });
  await ready; await env.issuer.disconnect(CLIENT, 'acct_1'); expectValue(deliver)({ accountId: 'acct_1' });
  const result = await active; assert.equal(result.body.error, 'invalid_grant'); assert.equal(result.status, 400);
  const state = durable ? await expectValue(env.db).issuer(ISSUER).read({kind:'metadata'}) : env.store.state;
  assert.deepEqual(state.sessions, {});
});

for (const durable of [false, true]) test(`terminal method records do not consume pending quota (${durable ? 'SQLite' : 'memory'})`, async t => {
  const env = await environment(t, durable);
  const options = { issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, protectedResources: ['https://shop.test'], supportedScopes: ['orders:read', 'orders:write'], metadata: env.metadata,
    store: env.db ? env.db.issuer(ISSUER) : env.store, coordinator:env.db ?? { run: action => action() }, now: () => env.clock.now, requireDpopNonce: false, maxPendingAuthorizations: 1,
    device: { endpoint: DEVICE, verificationUri: VERIFY }, mediated: env.config };
  env.issuer = createReferenceIssuer(options);
  const start = (await startDevice(env, 'orders:read')).body;
  assert.equal((await startDevice(env, 'orders:read')).status, 429);
  await env.issuer.beginDeviceAuthorization(start.user_code, BROWSER); await env.issuer.completeDeviceAuthorization(start.user_code, BROWSER, { denied: true });
  const next = await startDevice(env, 'orders:read'); assert.equal(next.status, 200);
  await env.issuer.beginDeviceAuthorization(next.body.user_code, BROWSER); await env.issuer.completeDeviceAuthorization(next.body.user_code, BROWSER, { denied: true });
  const session = {clientId:CLIENT};
  assert.equal((await mediated(env, session.clientId, { scope: 'orders:read', credentials: { password: 'private-password' } })).status, 200);
  assert.equal((await mediated(env, session.clientId, { scope: 'orders:read', credentials: { password: 'private-password' } })).status, 200);
});

test('Mediated challenge verifies once under concurrency and rejects non-boolean host decisions', async t => {
  let deliver!:(value:boolean)=>void,waiting!:()=>void; const ready = new Promise<void>(resolve => { waiting = resolve; });
  const env = await environment(t, true, { authenticate: async () => ({ accountId: 'acct_1', challenge: { id: 'host-id', sentTo: 'Your phone' } }), verifyCode: async () => { waiting(); return new Promise(resolve => { deliver = resolve; }); } });
  const session = {clientId:CLIENT}, first = await mediated(env, session.clientId, { scope: 'orders:read', credentials: { password: 'private-password' } });
  const active = mediated(env, session.clientId, { code: '123456' }, first.body.sign_in_id); await ready;
  const busy = await mediated(env, session.clientId, { code: '123456' }, first.body.sign_in_id);
  assert.equal(busy.status, 503); assert.equal(busy.headers.get('retry-after'), '5');
  // @ts-expect-error Host deliberately violates the boolean decision contract.
  expectValue(deliver)('false'); const invalid = await active; assert.equal(invalid.status, 503); assert.equal(invalid.body.error, 'temporarily_unavailable');
  assert.deepEqual((await expectValue(env.db).issuer(ISSUER).read({kind:'metadata'})).sessions, {});
});

for (const durable of [false, true]) test(`account-specific disconnect fences preserve unrelated pending users (${durable ? 'SQLite' : 'memory'})`, async t => {
  const env = await environment(t, durable);
  const deviceA = (await startDevice(env)).body, deviceB = (await startDevice(env)).body;
  await env.issuer.beginDeviceAuthorization(deviceA.user_code, BROWSER); await env.issuer.beginDeviceAuthorization(deviceB.user_code, BROWSER);
  await env.issuer.disconnect(CLIENT, 'acct_A'); env.issuer = env.reopen();
  await assert.rejects(env.issuer.completeDeviceAuthorization(deviceA.user_code, BROWSER, { accountId: 'acct_A', scopes: ['orders:read'] }));
  await env.issuer.completeDeviceAuthorization(deviceB.user_code, BROWSER, { accountId: 'acct_B', scopes: ['orders:read'] });
  const sessionB = {clientId:CLIENT}; env.clock.now += 5000;
  assert.equal((await pollDevice(env, deviceB.device_code, undefined)).status, 200);
  // New explicit consent after disconnect captures the new revision.
  const fresh = (await startDevice(env)).body; await env.issuer.beginDeviceAuthorization(fresh.user_code, BROWSER);
  await env.issuer.completeDeviceAuthorization(fresh.user_code, BROWSER, { accountId: 'acct_A', scopes: ['orders:read'] });
});

for (const durable of [false, true]) test(`delayed Mediated checks resolving other accounts survive disconnect (${durable ? 'SQLite' : 'memory'})`, async t => {
  const pending=new Map<string,(value:{accountId:string})=>void>();let waiting!:()=>void; const ready = new Promise<void>(resolve => { waiting = resolve; });
  const env = await environment(t, durable, { authenticate: async credentials => new Promise<{accountId:string}>(resolve => { pending.set(credentials.password, resolve); if (pending.size === 2) waiting(); }) });
  const a = {clientId:CLIENT}, b = {clientId:CLIENT};
  const activeA = mediated(env, a.clientId, { scope: 'orders:read', credentials: { password: 'A' } });
  const activeB = mediated(env, b.clientId, { scope: 'orders:read', credentials: { password: 'B' } });
  await ready; await env.issuer.disconnect(CLIENT, 'acct_A'); env.issuer = env.reopen();
  expectValue(pending.get('A'))({ accountId: 'acct_A' }); expectValue(pending.get('B'))({ accountId: 'acct_B' });
  assert.equal((await activeA).body.error, 'invalid_grant'); assert.equal((await activeB).status, 200);
});

test('Device nonce challenge uses fresh assertions and proof before consuming the code', async t => {
  const env = await environment(t, true);
  env.issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, revocationEndpoint: `${ISSUER}/oauth/revoke`, protectedResources: ['https://shop.test'], supportedScopes: ['orders:read', 'orders:write'], metadata: env.metadata,
    store: expectValue(env.db).issuer(ISSUER), coordinator:expectValue(env.db), now: () => env.clock.now, device: { endpoint: DEVICE, verificationUri: VERIFY } });
  await env.challenge(); const session = {clientId:CLIENT}, start = (await startDevice(env, 'orders:read')).body;
  await env.issuer.beginDeviceAuthorization(start.user_code, BROWSER); await env.issuer.completeDeviceAuthorization(start.user_code, BROWSER, { accountId: 'acct_1', scopes: ['orders:read'] });
  env.clock.now += 5000;
  const challenge = await env.send({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', assertion: undefined, device_code: start.device_code, session_id: undefined }, { dpop: await env.proof({ nonce: undefined }) });
  assert.equal(challenge.body.error, 'use_dpop_nonce');
  assert.equal((await pollDevice(env, start.device_code, undefined)).status, 200);
});
