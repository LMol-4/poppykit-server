import type {WorkRef} from '../dist/conversation/service.js';
import type {ConversationState} from '../dist/protocol/wire.js';
import type {SpawnOptions} from 'node:child_process';
import { expectValue,optionalMessage } from '../test-support/assertions.mjs';
import baseTest, { after } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { PostgresCompanyDatabase } from '../dist/postgres.js';
import { testPool } from '../test-support/postgres.mjs';
const pool = process.env.D1_POSTGRES === '1' ? testPool() : undefined;
const test = pool ? baseTest : baseTest.skip;
after(async()=>{await pool?.end();});
function database(path: string) {
 const db=new PostgresCompanyDatabase(pool!);
 return { close:()=>db.close(),run:db.run.bind(db),withTransaction:db.withTransaction.bind(db),metrics:db.metrics,cleanup:(ns:string,at:number,limit?:number)=>db.cleanup(path+':'+ns,at,limit),conversations:(ns:string)=>db.conversations(path+':'+ns),issuer:(ns:string)=>db.issuer(path+':'+ns) };
}
import { setup, hello } from './conversation/support.mjs';
import { setup as issuerSetup, CLIENT, ISSUER, REDIRECT } from './auth/issuer-support.mjs';
import { effect } from '../test-support/synthetic-effect.mjs';
import { keyPair } from './auth/support.mjs';
import { initialIssuerState, createReferenceIssuer } from '../dist/reference-auth/index.js';
import { calculateJwkThumbprint } from 'jose';
const directories: string[] = [];
after(async () => { for (const dir of directories) await rm(dir, { recursive: true, force: true }); });
async function fixture() { const dir = await mkdtemp(join(tmpdir(), 'poppy-company-')); directories.push(dir); return join(dir, (process.env.D1_NAMESPACE ?? 'd1') + '-state.db'); }

test('Session Key upgrade preserves grant lineage and internal IDs; independent writers create one Session', async t => {
  const path = await fixture(), namespace = path + ':upgrade';
  const env = await issuerSetup({ requireDpopNonce: false });
  const jkt = await calculateJwkThumbprint(env.dpopKey.jwk), hash = (s: string) => createHash('sha256').update(s).digest('base64url');
  const legacy = initialIssuerState(); legacy.version = 3;
  legacy.sessions.old = { clientId: CLIENT, userId: 'usr_1', version: 1, createdAt: env.clock.now, expiresAt: env.clock.now + 86400000, accountId: 'account', grantId: 'grant' };
  legacy.sessions.other = { ...legacy.sessions.old, userId: 'usr_other', accountId: null, grantId: null };
  legacy.grants.grant = { clientId: CLIENT, userId: 'usr_1', accountId: 'account', scopes: ['orders:read'], expiresAt: env.clock.now + 86400000, revoked: false, refreshHash: hash('old-account-token'), previousHash: '' };
  legacy.refreshTokens[hash('old-account-token')] = 'grant';
  legacy.accessTokens[hash('old-access-token')] = { sessionId: 'old', grantId: 'grant', scopes: ['orders:read'], resource: null, jkt, expiresAt: env.clock.now + 3600000 };
  legacy.accessTokens[hash('other-old-token')] = { ...legacy.accessTokens[hash('old-access-token')], sessionId: 'other', grantId: null };
  await pool!.query('INSERT INTO poppy_server.records VALUES ($1,$2,$3,$4)', [namespace, 'issuer_meta', 'meta', JSON.stringify({ version: 3, generation: legacy.generation, nonces: [] })]);
  for (const kind of ['sessions', 'grants', 'refreshTokens', 'accessTokens'] as const) for (const [id, row] of Object.entries(legacy[kind])) await pool!.query('INSERT INTO poppy_server.records VALUES ($1,$2,$3,$4)', [namespace, kind, id, JSON.stringify(row)]);
  const a = database(path), b = database(path); t.after(() => { a.close(); b.close(); });
  const make = (db: ReturnType<typeof database>) => createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: `${ISSUER}/oauth/token`, revocationEndpoint: `${ISSUER}/oauth/revoke`, protectedResources: ['https://shop.test'], supportedScopes: ['orders:read'], metadata: env.metadata, now: () => env.clock.now, requireDpopNonce: false, coordinator: db, store: db.issuer('upgrade') });
  const one = make(a), two = make(b), state = await a.issuer('upgrade').read({ kind: 'principal', sessionId: 'old', grantId: 'grant' });
  assert.equal(state.version, 4); assert.equal(state.sessions.old.accountId, 'account'); assert.equal(state.sessions.old.expiresAt, 0);
  assert.equal(state.grants.grant.refreshHash, hash('old-account-token'));
  await assert.rejects(one.authority.introspect('old-access-token'), { code: 'invalid_token' });
  const send = async (issuer: typeof one, key = env.dpopKey, refresh?: string) => {
    const body = new URLSearchParams({ client_id: CLIENT, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await env.clientAssertion(), ...(refresh ? { grant_type: 'refresh_token', refresh_token: refresh } : { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: await env.assertion() }) });
    return issuer.token(new Request(`${ISSUER}/oauth/token`, { method: 'POST', body, headers: { dpop: await env.proof({ key }) } }));
  };
  assert.deepEqual(await (await send(one)).json(), { error: 'invalid_grant' });
  const key = await keyPair(), responses = await Promise.all([send(one, key), send(two, key)]);
  const principals = await Promise.all(responses.map(async r => { assert.equal(r.status, 200); const token = await r.json(); assert.equal('session_id' in token, false); return (await one.authority.introspect(token.access_token)).principal; }));
  assert.equal(principals[0].sessionId, principals[1].sessionId);
  const signed = await send(two, key, 'old-account-token'); assert.equal(signed.status, 200);
  const token = await signed.json(), principal = (await one.authority.introspect(token.access_token)).principal;
  assert.deepEqual([principal.userId, principal.accountId, principal.grantId, principal.sessionId], ['usr_1', 'account', 'grant', principals[0].sessionId]);
  const reopened = database(path); t.after(() => reopened.close());
  assert.equal((await make(reopened).authority.introspect(token.access_token)).principal.sessionId, principal.sessionId);
  assert.equal(Number((await pool!.query("SELECT count(*) AS n FROM poppy_server.records WHERE ns=$1 AND kind='sessionKeys'", [namespace])).rows[0].n), 2);
});

interface Packets {accept:{receipt:ConversationState};'after-commit':{receipt:ConversationState};'before-commit':{ready:true};effect:{work:WorkRef};'effect-contract':{work:WorkRef;result:string};rotate:{status:number;error?:string};revoke:{status:number;error?:string}}
function assertPacket<M extends keyof Packets>(mode:M,value:unknown):asserts value is Packets[M]{
 assert.ok(value&&typeof value==='object');
 if(mode==='accept'||mode==='after-commit'){assert.ok('receipt' in value&&value.receipt&&typeof value.receipt==='object'&&'conversation_id' in value.receipt&&typeof value.receipt.conversation_id==='string');}
 else if(mode==='effect'||mode==='effect-contract'){assert.ok('work' in value&&value.work&&typeof value.work==='object'&&'workId' in value.work&&typeof value.work.workId==='string'&&'fence' in value.work&&typeof value.work.fence==='string');if(mode==='effect-contract')assert.ok('result' in value&&typeof value.result==='string');}
 else if(mode==='before-commit')assert.ok('ready' in value&&value.ready===true);
 else assert.ok('status' in value&&typeof value.status==='number');
}

function worker<M extends keyof Packets>(t:import('node:test').TestContext,mode:M,path:string) {
  const options:SpawnOptions={windowsHide:true,stdio:['ignore','ignore','pipe','ipc']};const child=fork(new URL('../test-support/storage-worker.mjs',import.meta.url),[mode,path],options);
  const exited = once(child, 'exit'); let errors = ''; expectValue(child.stderr).on('data', b => { errors += b; });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill(); await exited; } });
  const message = new Promise<Packets[M]>((resolve,reject)=>{child.once('message',value=>{try{assertPacket(mode,value);resolve(value);}catch(error){reject(error);}}); child.once('error', reject); child.once('exit', code => { if (code) reject(new Error(errors)); }); });
  return { child, exited, message };
}
test('two processes accept one message and crash after commit preserves receipt/work', { timeout: 15000 }, async t => {
  const path = await fixture(), a = worker(t, 'accept', path), b = worker(t, 'after-commit', path);
  const [one, two] = await Promise.all([a.message, b.message]);
  assert.deepEqual(one.receipt, two.receipt);
  b.child.kill(); await Promise.all([a.exited, b.exited]);
  const db = database(path); t.after(async () => { await db.close(); });
  const store = db.conversations('test'), service = setup({ store });
  assert.deepEqual((await service.start(hello)).body, one.receipt);
  const state = await store.read({ conversationId: one.receipt.conversation_id });
  assert.equal(state.work.length, 1); assert.equal(state.conversations[one.receipt.conversation_id].events.length, 2);
  assert.equal((await service.start({ ...hello, text: 'different' })).body.error, 'message_id_conflict');
});
test('kill before commit rolls back acceptance, events, receipt and work together', { timeout: 15000 }, async t => {
  const path = await fixture(), a = worker(t, 'before-commit', path);
  await a.message; a.child.kill(); await a.exited;
  for (const table of ['records','events']) assert.equal(Number((await pool!.query('SELECT count(*) AS n FROM poppy_server.'+table+' WHERE ns=$1',[path+':test'])).rows[0].n),0);
});
test('death after an external side effect needs application idempotency, and stale worker cannot publish', { timeout: 15000 }, async t => {
  const path = await fixture(), accept = worker(t, 'accept', path); const receipt = await accept.message; await accept.exited;
  const first = worker(t, 'effect', path); const old = await first.message; first.child.kill(); await first.exited;
  const db = database(path); const store = db.conversations('test'); const current = setup({ store, leaseMs: 1 });
  current.clock.advance(2000);
  const fresh = await current.service.claim(); assert.equal(expectValue(fresh).workId, old.work.workId); assert.notEqual(expectValue(fresh).fence, old.work.fence);
  await assert.rejects(current.service.reply(old.work, 'output', { id: 'reply', sender: 'agent', text: 'done' }), { code: 'stale_work' });
  const external = new DatabaseSync(path + '.external');
  external.prepare('INSERT OR IGNORE INTO effects VALUES (?)').run(expectValue(fresh).workId);
  assert.equal(expectValue(external.prepare('SELECT count(*) AS n FROM effects').get()).n, 1); external.close();
  await current.service.reply(expectValue(fresh), 'output', { id: 'reply', sender: 'agent', text: 'done' });
  await current.service.reply(expectValue(fresh), 'output', { id: 'reply', sender: 'agent', text: 'done' });
  const state = await store.read({ conversationId: receipt.receipt.conversation_id });
  assert.equal(state.conversations[receipt.receipt.conversation_id].events.filter(e => optionalMessage(e.message)?.id === 'reply').length, 1);
  db.close();
});
test('process death, competing recovery and retention preserve the application effect contract', {timeout:15000},async t=>{
  const path=await fixture(),accepted=worker(t,'accept',path),receipt=await accepted.message;await accepted.exited;
  const child=worker(t,'effect-contract',path),old=await child.message;
  const a=database(path),b=database(path);t.after(async()=>{await a.close();await b.close();});
  const one=setup({store:a.conversations('test'),leaseMs:1}),two=setup({store:b.conversations('test'),leaseMs:1});
  assert.equal(await expectValue(a.conversations('test').pruneEvents).call(a.conversations('test'), receipt.receipt.conversation_id, one.clock.now()+1e6, 100),0,'active claimed work pins its history');
  child.child.kill();await child.exited;
  one.clock.advance(2000);two.clock.advance(2000);
  const claims=(await Promise.all([one.service.claim(),two.service.claim()])).filter(Boolean);assert.equal(claims.length,1);
  const fresh=claims[0];assert.notEqual(expectValue(fresh).fence,old.work.fence);
  await assert.rejects(one.service.reply(old.work,'result',{id:'stale',sender:'agent',text:'must not publish'}),{code:'stale_work'});
  const payload={record:'opaque-17',value:1};
  assert.equal(effect(path+'.contract','tenant-a',expectValue(fresh).workId,payload),old.result,'recovered execution uses its own retained effect receipt');
  assert.throws(()=>effect(path+'.contract','tenant-a',expectValue(fresh).workId,{...payload,value:2}),/effect_payload_conflict/);
  effect(path+'.contract','tenant-b',expectValue(fresh).workId,payload);
  const external=new DatabaseSync(path+'.contract');assert.equal(expectValue(external.prepare('SELECT count(*) AS n FROM effects').get()).n,2);external.close();
  await one.service.reply(expectValue(fresh),'result',{id:'recovered_result',sender:'agent',text:old.result});await one.service.finish(expectValue(fresh),'completed');
  const id=receipt.receipt.conversation_id,cursor=(await one.read(id)).body.cursor;
  await expectValue(a.conversations('test').pruneEvents).call(a.conversations('test'), id, one.clock.now()+1, 100);
  const [retry,read]=await Promise.all([two.start(hello),two.read(id,{query:'?cursor='+cursor})]);
  assert.deepEqual(retry.body,receipt.receipt,'acceptance retry survives history retention');assert.ok([200,410].includes(read.status));
  assert.equal((await two.start({...hello,text:'conflicting bytes'})).body.error,'message_id_conflict');
});

test('targeted reads and writes do not grow with unrelated conversations', async t => {
  const db = database(await fixture()); t.after(() => db.close());
  const store = db.conversations('test'), service = setup({ store });
  const first = (await service.start(hello)).body.conversation_id;
  db.metrics.rowsRead = 0; await service.read(first); const baseline = db.metrics.rowsRead;
  for (let i = 0; i < 100; i++) await service.start({ ...hello, id: 'unrelated_' + i });
  db.metrics.rowsRead = 0; await service.read(first); assert.equal(db.metrics.rowsRead, baseline);
  const before = await store.read({ conversationId: first });
  before.conversations[first].context.mutated = true;
  assert.deepEqual((await store.read({ conversationId: first })).conversations[first].context, {});
  await assert.rejects(store.transaction({ conversationId: first }, state => { state.conversations[first].context.x = true; throw new Error('rollback'); }), /rollback/);
  assert.deepEqual((await store.read({ conversationId: first })).conversations[first].context, {});
  await db.run(async () => {
    await assert.rejects(store.transaction({ conversationId: first }, state => {
      state.conversations[first].context.x = true;
      Object.assign(state.bindings[state.conversations[first].bindingId],{invalid:undefined});
    }), /non-JSON/);
    assert.deepEqual((await store.read({ conversationId: first })).conversations[first].context, {});
    await store.read({ conversationId: first }); await store.read({ conversationId: first });
  });
});
test('bounded Postgres cleanup isolates namespaces and retains grants, work, receipts and events', async t => {
  const path = await fixture(), db = database(path); t.after(() => db.close());
  const namespace = 'maintenance', other = 'other-company', at = 1000000;
  const seed = async (name: string) => {
    await setup({ store: db.conversations(name) }).start(hello);
    await db.issuer(name).transaction({ kind: 'authorize', clientId: CLIENT, at }, state => {
      const authorization = { clientId: CLIENT, redirectUri: REDIRECT, state: 'state', codeChallenge: 'challenge', scopes: [], browserHash: 'browser', expiresAt: at, revision: 0 };
      state.authorizations.expired = authorization;
      state.authorizations.future = { ...authorization, expiresAt: at + 1 };
      state.codes.expired = { clientId: CLIENT, redirectUri: REDIRECT, codeChallenge: 'challenge', accountId: 'account', scopes: [], expiresAt: at, grantId: null, revision: 0 };
      state.signIns.expired = { kind: 'attempts', clientId: CLIENT, expiresAt: at - 30001, count: 1 };
      state.signIns.grace = { kind: 'attempts', clientId: CLIENT, expiresAt: at - 30000, count: 1 };
      state.signIns.revision = { kind: 'revision', clientId: CLIENT, expiresAt: Number.MAX_SAFE_INTEGER, revision: 1 };
      state.accessTokens.expired = { sessionId: 'session', grantId: null, scopes: [], resource: null, jkt: 'key', expiresAt: at };
      state.replay.expired = at - 1; state.replay.boundary = at;
      state.grants.retained = { clientId: CLIENT, userId: 'user', accountId: 'account', scopes: [], expiresAt: at - 1, revoked: true, refreshHash: 'refresh', previousHash: '' };
      state.refreshTokens.refresh = 'retained';
      state.grants.active = { ...state.grants.retained, expiresAt: at + 1000, revoked: false, refreshHash: 'current', previousHash: 'previous' };
      for (const hash of ['oldest', 'previous', 'current']) state.refreshTokens[hash] = 'active';
    });
  };
  await seed(namespace); await seed(other);

  const records = async (name: string) => (await pool!.query('SELECT kind,id,body FROM poppy_server.records WHERE ns=$1 ORDER BY kind,id',[path+':'+name])).rows;
  const before = await records(namespace), untouched = await records(other), events = (await pool!.query('SELECT * FROM poppy_server.events WHERE ns=$1 ORDER BY conversation,seq',[path+':'+namespace])).rows;
  const expired = new Set(['authorizations:expired', 'codes:expired', 'signIns:expired', 'accessTokens:expired', 'replay:expired', 'refreshTokens:refresh']);
  for (const limit of [0, 1.5, 1001]) assert.throws(() => db.cleanup(namespace, at, limit), /cleanup limit/);
  assert.deepEqual(await records(namespace), before);
  assert.equal(await db.cleanup(namespace, at, 1), 1);
  assert.equal((await records(namespace)).length, before.length - 1);
  assert.equal(await db.cleanup(namespace, at, 100), 5);
  assert.equal(await db.cleanup(namespace, at, 100), 0);
  assert.deepEqual(await records(namespace), before.filter(row => !expired.has(row.kind + ':' + row.id)));
  assert.deepEqual(await records(other), untouched);
  await db.cleanup(namespace, at + 1000, 100);
  assert.ok(!(await records(namespace)).some(row => row.kind === 'refreshTokens'), 'all expired ancestor hashes are collected');
  assert.deepEqual(await records(other), untouched);
  assert.deepEqual((await pool!.query('SELECT * FROM poppy_server.events WHERE ns=$1 ORDER BY conversation,seq',[path+':'+namespace])).rows, events);
});

test('durable issuer rotates and revokes atomically; authority and conversation mutation share one transaction', async t => {
  const path = await fixture(), db = database(path); t.after(() => db.close());
  const env = await issuerSetup({ store: db.issuer(ISSUER), coordinator: db, requireDpopNonce: false });
  const start = await env.send(); assert.equal(start.status, 200);
  const verifier = 'v'.repeat(43), url = new URL(ISSUER + '/authorize');
  const fields = { response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'orders:read', state: 'state', code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url') };
  for (const [name, value] of Object.entries(fields)) url.searchParams.set(name, value);
  const view = await env.issuer.beginAuthorization(new Request(url), 'binding');
  const callback = await env.issuer.completeAuthorization(view.id, 'binding', { accountId: 'account', scopes: ['orders:read'] });
  const signed = await env.send({ grant_type: 'authorization_code', assertion: undefined, code:expectValue(callback.searchParams.get('code')), redirect_uri: REDIRECT, code_verifier: verifier, session_id: start.body.session_id });
  assert.equal(signed.status, 200, JSON.stringify(signed.body));
  const { principal } = await env.issuer.authority.introspect(expectValue(signed.body.access_token));
  const rotation = worker(t, 'rotate', path), revocation = worker(t, 'revoke', path);
  const input = { refreshToken: signed.body.refresh_token, sessionId:expectValue(start.body.session_id) };
  rotation.child.send(input); revocation.child.send(input);
  const [rotatedResult, revokedResult] = await Promise.all([rotation.message, revocation.message]);
  await Promise.all([rotation.exited, revocation.exited]);
  assert.ok([200, 400].includes(rotatedResult.status));
  if (rotatedResult.status === 400) assert.equal(rotatedResult.error, 'invalid_grant');
  assert.equal(revokedResult.status, 200);
  await assert.rejects(env.issuer.authority.introspect(expectValue(signed.body.access_token)), { code: 'invalid_token' });
  // Start a new grant to test the policy/transaction ordering separately.
  const view2 = await env.issuer.beginAuthorization(new Request(url), 'binding2');
  const callback2 = await env.issuer.completeAuthorization(view2.id, 'binding2', { accountId: 'account', scopes: ['orders:read'] });
  const signed2 = await env.send({ grant_type: 'authorization_code', assertion: undefined, code:expectValue(callback2.searchParams.get('code')), redirect_uri: REDIRECT, code_verifier: verifier, session_id: start.body.session_id });
  const currentPrincipal = (await env.issuer.authority.introspect(expectValue(signed2.body.access_token))).principal;
  const conversations = setup({ store: db.conversations(ISSUER), policy: env.issuer.authority.policy, authenticator: { authenticate: async () => currentPrincipal } });
  let entered!:()=>void; const gate=new Promise<void>(r=>{entered=r;});let release!:()=>void;const hold=new Promise<void>(r=>{release=r;});
  const accepted = env.issuer.authority.policy.withCurrent(currentPrincipal, ['orders:read'], async () => { entered(); await hold; return conversations.start(hello); });
  await gate;
  const revoked = env.issuer.disconnect(CLIENT, 'account');
  expectValue(release)(); const receipt = await accepted; assert.equal(receipt.status, 201); await revoked;
  assert.equal((await conversations.read(receipt.body.conversation_id)).status, 401);
  await assert.rejects(env.issuer.authority.policy.withCurrent(currentPrincipal, [], async () => { throw new Error('must not run'); }), { code: 'invalid_token' });
  const rotated = await env.send({ grant_type: 'refresh_token', assertion: undefined, refresh_token: signed.body.refresh_token, session_id: start.body.session_id });
  assert.equal(rotated.body.error, 'invalid_grant');
  assert.deepEqual((await db.issuer('https://other.test').read({ kind: 'principal', sessionId:expectValue(start.body.session_id) })).sessions, {});
});
