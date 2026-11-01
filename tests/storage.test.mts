import { PostgresCompanyDatabase } from '../dist/postgres.js';
import { testPool } from '../test-support/postgres.mjs';
import type {WorkRef} from '../dist/conversation/service.js';
import type {ConversationState} from '../dist/protocol/wire.js';
import type {SpawnOptions} from 'node:child_process';
import { expectValue,optionalMessage } from '../test-support/assertions.mjs';
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { SqliteCompanyDatabase } from '../dist/sqlite.js';
import { setup, hello } from './conversation/support.mjs';
import { setup as issuerSetup, CLIENT, ISSUER, REDIRECT } from './auth/issuer-support.mjs';
import { effect } from '../test-support/synthetic-effect.mjs';
import { keyPair } from './auth/support.mjs';
import { initialIssuerState, createReferenceIssuer } from '../dist/reference-auth/index.js';
import { calculateJwkThumbprint } from 'jose';
const directories: string[] = [];
after(async () => { for (const dir of directories) await rm(dir, { recursive: true, force: true }); });
async function fixture() { const dir = await mkdtemp(join(tmpdir(), 'poppy-company-')); directories.push(dir); return join(dir, 'state.db'); }

test('draft 0.3 refuses old conversation namespaces until an explicit data reset',async t=>{
  const path=await fixture(),first=new SqliteCompanyDatabase(path);first.close();
  const raw=new DatabaseSync(path);raw.prepare('INSERT INTO records VALUES (?,?,?,?)').run('old','conversation_meta','meta',JSON.stringify({version:1,generation:'old'}));raw.close();
  const db=new SqliteCompanyDatabase(path);t.after(()=>db.close());
  await assert.rejects(db.conversations('old').read({}),/conversation reset required/);
  const fresh=await db.conversations('fresh').read({});assert.equal(fresh.version,2);
});

for (const engine of ['SQLite', ...(process.env.D1_POSTGRES === '1' ? ['Postgres'] : [])]) for (const version of [3,4] as const) test(`OAuth record v${version} upgrade preserves pending work, authority and recovery references (${engine})`, async t => {
  const path=await fixture(),namespace=`migration-${version}-${path}`,pool=engine==='Postgres'?testPool():undefined;
  const bootstrap=pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(path);await bootstrap.close();
  const legacy=initialIssuerState();legacy.version=version;
  legacy.sessions.old={clientId:CLIENT,userId:'pairwise-user',version:1,createdAt:1,expiresAt:9000000,accountId:'account',grantId:'grant'};
  legacy.sessionKeys['legacy-proof-key']='old';
  legacy.grants.grant={clientId:CLIENT,userId:'pairwise-user',accountId:'account',scopes:['orders:read'],expiresAt:9000000,revoked:false,refreshHash:'current-hash',previousHash:'ancestor-hash'};
  legacy.refreshTokens['current-hash']='grant';legacy.refreshTokens['ancestor-hash']='grant';
  legacy.accessTokens.known={sessionId:'old',grantId:'grant',scopes:['orders:read'],resource:null,jkt:'legacy-proof-key',expiresAt:8000000};
  legacy.accessTokens.unknown={sessionId:'missing-session',grantId:null,scopes:[],resource:null,jkt:'unknown-key',expiresAt:8000000};
  legacy.authorizations.pending={sessionKey:'legacy-proof-key',clientId:CLIENT,redirectUri:REDIRECT,state:'callback-state',codeChallenge:'pkce-hash',scopes:['orders:read'],browserHash:'browser-hash',expiresAt:8000000,revision:4,completion:{decisionHash:'decision',callback:'encrypted-callback-reference'}};
  legacy.codes.pending={sessionKey:'legacy-proof-key',clientId:CLIENT,redirectUri:REDIRECT,codeChallenge:'pkce-hash',accountId:'account',scopes:['orders:read'],expiresAt:8000000,grantId:null,revision:4};
  legacy.signIns.uncertain={kind:'mediated',clientId:CLIENT,userId:'pairwise-user',sessionId:'old',scopes:['orders:read'],expiresAt:8000000,status:'verifying',attempts:1,executionId:'dispatched-remote-hook',revision:4};
  legacy.replay['consumed-assertion']=8000000;legacy.nonces=[{value:'retained-nonce',expiresAt:8000000}];
  const kinds=['sessions','sessionKeys','grants','refreshTokens','authorizations','codes','signIns','accessTokens','replay'] as const;
  const meta={version,generation:legacy.generation,nonces:legacy.nonces};
  if(pool){
    await pool.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[namespace,'issuer_meta','meta',JSON.stringify(meta)]);
    for(const kind of kinds)for(const[id,row]of Object.entries(legacy[kind]))await pool.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[namespace,kind,id,JSON.stringify(row)]);
  }else{
    const raw=new DatabaseSync(path);try{
      const put=raw.prepare('INSERT INTO records(ns,kind,id,body) VALUES(?,?,?,?)');put.run(namespace,'issuer_meta','meta',JSON.stringify(meta));
      for(const kind of kinds)for(const[id,row]of Object.entries(legacy[kind]))put.run(namespace,kind,id,JSON.stringify(row));
    }finally{raw.close();}
  }
  const open=()=>pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(path),one=open(),two=open();t.after(async()=>{await one.close();await two.close();await pool?.end();});
  const results=await Promise.all([one.issuer(namespace).read({kind:'metadata'}),two.issuer(namespace).read({kind:'metadata'})]);
  assert.ok(results.every(state=>state.version===5));assert.ok(results.every(state=>state.generation===legacy.generation));
  let rows:{kind:string;id:string;body:string}[];
  if(pool)rows=(await pool.query('SELECT kind,id,body FROM poppy_server.records WHERE ns=$1',[namespace])).rows;
  else{const raw=new DatabaseSync(path);try{rows=raw.prepare('SELECT kind,id,body FROM records WHERE ns=?').all(namespace) as unknown as typeof rows;}finally{raw.close();}}
  const snapshot={...legacy,version:5,accessTokens:{...legacy.accessTokens,known:{...legacy.accessTokens.known,clientId:CLIENT,accountId:'account'}}};
  assert.equal(rows.length,1+kinds.reduce((count,kind)=>count+Object.keys(legacy[kind]).length,0),'no pending record or recovery fence was deleted');
  for(const kind of kinds)for(const[id,row]of Object.entries(snapshot[kind]))assert.deepEqual(JSON.parse(rows.find(value=>value.kind===kind&&value.id===id)!.body),row,kind+':'+id);
  assert.deepEqual(JSON.parse(rows.find(row=>row.kind==='issuer_meta')!.body),{...meta,version:5});
  const reopened=open();try{assert.equal((await reopened.issuer(namespace).read({kind:'metadata'})).version,5);}finally{await reopened.close();}
});

interface Packets {accept:{receipt:ConversationState};'after-commit':{receipt:ConversationState};'before-commit':{ready:true};effect:{work:WorkRef};'effect-contract':{work:WorkRef;result:string};rotate:{status:number;error?:string};revoke:{status:number;error?:string}}
function assertPacket<M extends keyof Packets>(mode:M,value:unknown):asserts value is Packets[M]{
 assert.ok(value&&typeof value==='object');
 if(mode==='accept'||mode==='after-commit'){assert.ok('receipt' in value&&value.receipt&&typeof value.receipt==='object'&&'conversation_id' in value.receipt&&typeof value.receipt.conversation_id==='string');}
 else if(mode==='effect'||mode==='effect-contract'){assert.ok('work' in value&&value.work&&typeof value.work==='object'&&'workId' in value.work&&typeof value.work.workId==='string'&&'fence' in value.work&&typeof value.work.fence==='string');if(mode==='effect-contract')assert.ok('result' in value&&typeof value.result==='string');}
 else if(mode==='before-commit')assert.ok('ready' in value&&value.ready===true);
 else assert.ok('status' in value&&typeof value.status==='number');
}

function worker<M extends keyof Packets>(t:test.TestContext,mode:M,path:string) {
  const options:SpawnOptions={windowsHide:true,stdio:['ignore','ignore','pipe','ipc'],env:{...process.env,D1_POSTGRES:'0'}};const child=fork(new URL('../test-support/storage-worker.mjs',import.meta.url),[mode,path],options);
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
  const db = new SqliteCompanyDatabase(path); t.after(() => db.close());
  const store = db.conversations('test'), service = setup({ store });
  assert.deepEqual((await service.start(hello)).body, one.receipt);
  const state = await store.read({ conversationId: one.receipt.conversation_id });
  assert.equal(state.work.length, 1); assert.equal(state.conversations[one.receipt.conversation_id].events.length, 2);
  assert.equal((await service.start({ ...hello, text: 'different' })).body.error, 'message_id_conflict');
});
test('kill before commit rolls back acceptance, events, receipt and work together', { timeout: 15000 }, async t => {
  const path = await fixture(), a = worker(t, 'before-commit', path);
  await a.message; a.child.kill(); await a.exited;
  const raw = new DatabaseSync(path);
  assert.equal(expectValue(raw.prepare('SELECT count(*) AS n FROM records').get()).n, 0);
  assert.equal(expectValue(raw.prepare('SELECT count(*) AS n FROM events').get()).n, 0); raw.close();
});
test('death after an external side effect needs application idempotency, and stale worker cannot publish', { timeout: 15000 }, async t => {
  const path = await fixture(), accept = worker(t, 'accept', path); const receipt = await accept.message; await accept.exited;
  const first = worker(t, 'effect', path); const old = await first.message; first.child.kill(); await first.exited;
  const db = new SqliteCompanyDatabase(path); const store = db.conversations('test'); const current = setup({ store, leaseMs: 1 });
  current.clock.advance(2000);
  const fresh = await current.service.claim(); assert.equal(expectValue(fresh).workId, old.work.workId); assert.notEqual(expectValue(fresh).fence, old.work.fence);
  await assert.rejects(current.service.reply(old.work, 'output', { id: 'reply', author: { type: 'agent' }, text: 'done' }), { code: 'stale_work' });
  const external = new DatabaseSync(path + '.external');
  external.prepare('INSERT OR IGNORE INTO effects VALUES (?)').run(expectValue(fresh).workId);
  assert.equal(expectValue(external.prepare('SELECT count(*) AS n FROM effects').get()).n, 1); external.close();
  await current.service.reply(expectValue(fresh), 'output', { id: 'reply', author: { type: 'agent' }, text: 'done' });
  await current.service.reply(expectValue(fresh), 'output', { id: 'reply', author: { type: 'agent' }, text: 'done' });
  const state = await store.read({ conversationId: receipt.receipt.conversation_id });
  assert.equal(state.conversations[receipt.receipt.conversation_id].events.filter(e => optionalMessage(e.message)?.id === 'reply').length, 1);
  db.close();
});
test('process death, competing recovery and retention preserve the application effect contract', {timeout:15000},async t=>{
  const path=await fixture(),accepted=worker(t,'accept',path),receipt=await accepted.message;await accepted.exited;
  const child=worker(t,'effect-contract',path),old=await child.message;
  const a=new SqliteCompanyDatabase(path),b=new SqliteCompanyDatabase(path);t.after(()=>{a.close();b.close();});
  const one=setup({store:a.conversations('test'),leaseMs:1}),two=setup({store:b.conversations('test'),leaseMs:1});
  assert.equal(await expectValue(a.conversations('test').pruneEvents).call(a.conversations('test'), receipt.receipt.conversation_id, one.clock.now()+1e6, 100),0,'active claimed work pins its history');
  child.child.kill();await child.exited;
  one.clock.advance(2000);two.clock.advance(2000);
  const claims=(await Promise.all([one.service.claim(),two.service.claim()])).filter(Boolean);assert.equal(claims.length,1);
  const fresh=claims[0];assert.notEqual(expectValue(fresh).fence,old.work.fence);
  await assert.rejects(one.service.reply(old.work,'result',{id:'stale',author: { type: 'agent' },text:'must not publish'}),{code:'stale_work'});
  const payload={record:'opaque-17',value:1};
  assert.equal(effect(path+'.contract','tenant-a',expectValue(fresh).workId,payload),old.result,'recovered execution uses its own retained effect receipt');
  assert.throws(()=>effect(path+'.contract','tenant-a',expectValue(fresh).workId,{...payload,value:2}),/effect_payload_conflict/);
  effect(path+'.contract','tenant-b',expectValue(fresh).workId,payload);
  const external=new DatabaseSync(path+'.contract');assert.equal(expectValue(external.prepare('SELECT count(*) AS n FROM effects').get()).n,2);external.close();
  await one.service.reply(expectValue(fresh),'result',{id:'recovered_result',author: { type: 'agent' },text:old.result});await one.service.finish(expectValue(fresh),'completed');
  const id=receipt.receipt.conversation_id,cursor=(await one.read(id)).body.cursor;
  await expectValue(a.conversations('test').pruneEvents).call(a.conversations('test'), id, one.clock.now()+1, 100);
  const [retry,read]=await Promise.all([two.start(hello),two.read(id,{query:'?cursor='+cursor})]);
  assert.deepEqual(retry.body,receipt.receipt,'acceptance retry survives history retention');assert.ok([200,410].includes(read.status));
  assert.equal((await two.start({...hello,text:'conflicting bytes'})).body.error,'message_id_conflict');
});

test('targeted reads and writes do not grow with unrelated conversations', async t => {
  const db = new SqliteCompanyDatabase(await fixture()); t.after(() => db.close());
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
    const reading = store.read({ conversationId: first });
    await assert.rejects(store.read({ conversationId: first }), /concurrent nested/);
    await reading;
  });
});
test('bounded SQLite cleanup isolates namespaces and retains grants, work, receipts and events', async t => {
  const path = await fixture(), db = new SqliteCompanyDatabase(path); t.after(() => db.close());
  const namespace = 'maintenance', other = 'other-company', at = 1000000;
  const seed = async (name: string) => {
    await setup({ store: db.conversations(name) }).start(hello);
    await db.issuer(name).transaction({ kind: 'authorize', clientId: CLIENT, at }, state => {
      const authorization = { sessionKey: 'k'.repeat(43), clientId: CLIENT, redirectUri: REDIRECT, state: 'state', codeChallenge: 'challenge', scopes: [], browserHash: 'browser', expiresAt: at, revision: 0 };
      state.authorizations.expired = authorization;
      state.authorizations.future = { ...authorization, expiresAt: at + 1 };
      state.codes.expired = { sessionKey: 'k'.repeat(43), clientId: CLIENT, redirectUri: REDIRECT, codeChallenge: 'challenge', accountId: 'account', scopes: [], expiresAt: at, grantId: null, revision: 0 };
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
  const raw = new DatabaseSync(path); t.after(() => raw.close());
  const records = (name: string) => raw.prepare('SELECT kind,id,body FROM records WHERE ns=? ORDER BY kind,id').all(name).map(row => {
    assert.ok(typeof row.kind === 'string' && typeof row.id === 'string' && typeof row.body === 'string');
    return { kind: row.kind, id: row.id, body: row.body };
  });
  const before = records(namespace), untouched = records(other), events = raw.prepare('SELECT * FROM events ORDER BY ns,conversation,seq').all();
  const expired = new Set(['authorizations:expired', 'codes:expired', 'signIns:expired', 'accessTokens:expired', 'replay:expired', 'refreshTokens:refresh']);
  for (const limit of [0, 1.5, 1001]) assert.throws(() => db.cleanup(namespace, at, limit), /cleanup limit/);
  assert.deepEqual(records(namespace), before);
  assert.equal(await db.cleanup(namespace, at, 1), 1);
  assert.equal(records(namespace).length, before.length - 1);
  assert.equal(await db.cleanup(namespace, at, 100), 5);
  assert.equal(await db.cleanup(namespace, at, 100), 0);
  assert.deepEqual(records(namespace), before.filter(row => !expired.has(row.kind + ':' + row.id)));
  assert.deepEqual(records(other), untouched);
  await db.cleanup(namespace, at + 1000, 100);
  assert.ok(!records(namespace).some(row => row.kind === 'refreshTokens'), 'all expired ancestor hashes are collected');
  assert.deepEqual(records(other), untouched);
  assert.deepEqual(raw.prepare('SELECT * FROM events ORDER BY ns,conversation,seq').all(), events);
});

test('durable issuer rotates and revokes atomically; authority and conversation mutation share one transaction', async t => {
  const path = await fixture(), db = new SqliteCompanyDatabase(path); t.after(() => db.close());
  const env = await issuerSetup({ store: db.issuer(ISSUER), coordinator: db, requireDpopNonce: false });
  const verifier = 'v'.repeat(43), url = new URL(ISSUER + '/authorize');
  const fields = { response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'orders:read', state: 'state', code_challenge_method: 'S256', dpop_jkt: await calculateJwkThumbprint(env.dpopKey.jwk), code_challenge: createHash('sha256').update(verifier).digest('base64url') };
  for (const [name, value] of Object.entries(fields)) url.searchParams.set(name, value);
  const view = await env.issuer.beginAuthorization(new Request(url), 'binding');
  const callback = await env.issuer.completeAuthorization(view.id, 'binding', { accountId: 'account', scopes: ['orders:read'] });
  const signed = await env.send({ grant_type: 'authorization_code', assertion: undefined, code:expectValue(callback.searchParams.get('code')), redirect_uri: REDIRECT, code_verifier: verifier });
  assert.equal(signed.status, 200, JSON.stringify(signed.body));
  const { principal } = await env.issuer.authority.introspect(expectValue(signed.body.access_token));
  const rotation = worker(t, 'rotate', path), revocation = worker(t, 'revoke', path);
  const input = { refreshToken: signed.body.refresh_token };
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
  const signed2 = await env.send({ grant_type: 'authorization_code', assertion: undefined, code:expectValue(callback2.searchParams.get('code')), redirect_uri: REDIRECT, code_verifier: verifier });
  const currentPrincipal = (await env.issuer.authority.introspect(expectValue(signed2.body.access_token))).principal;
  const conversations = setup({ store: db.conversations(ISSUER), policy: env.issuer.authority.policy, authenticator: { authenticate: async () => currentPrincipal } });
  let entered!:()=>void; const gate=new Promise<void>(r=>{entered=r;});let release!:()=>void;const hold=new Promise<void>(r=>{release=r;});
  const accepted = env.issuer.authority.policy.withCurrent(currentPrincipal, ['orders:read'], async () => { entered(); await hold; return conversations.start(hello); });
  await gate;
  const revoked = env.issuer.disconnect(CLIENT, 'account');
  expectValue(release)(); const receipt = await accepted; assert.equal(receipt.status, 201); await revoked;
  assert.equal((await conversations.read(receipt.body.conversation_id)).status, 401);
  await assert.rejects(env.issuer.authority.policy.withCurrent(currentPrincipal, [], async () => { throw new Error('must not run'); }), { code: 'invalid_token' });
  const rotated = await env.send({ grant_type: 'refresh_token', assertion: undefined, refresh_token: signed.body.refresh_token });
  assert.equal(rotated.body.error, 'invalid_grant');
  assert.deepEqual((await db.issuer('https://other.test').read({ kind: 'principal', sessionId:'' })).sessions, {});
});

test('SQLite nested scopes roll back independently and expire their own handles', async t => {
  const db = new SqliteCompanyDatabase(await fixture()); t.after(()=>db.close());
  type Connection = Parameters<Parameters<typeof db.withTransaction>[0]>[0];
  let escaped: Connection | undefined, outer: Connection | undefined;
  await db.withTransaction(async connection => {
    outer = connection;
    connection.run('CREATE TABLE effects (id TEXT PRIMARY KEY)');
    connection.run('INSERT INTO effects VALUES (?)',['outer']);
    await assert.rejects(db.withTransaction(async nested => {
      escaped = nested; nested.run('INSERT INTO effects VALUES (?)',['inner']); throw new Error('abort inner');
    }), /abort inner/);
    assert.ok(escaped); assert.throws(()=>escaped!.get('SELECT 1'),/expired/);
    assert.equal(connection.get('SELECT count(*) AS n FROM effects')!.n,1);
    await db.run(async()=>{await db.withTransaction(async nested=>{escaped=nested;nested.run('INSERT INTO effects VALUES (?)',['recursive']);});});
    assert.throws(()=>escaped!.run('INSERT INTO effects VALUES (?)',['escaped']),/expired/);
    connection.run('INSERT INTO effects VALUES (?)',['after']);
  });
  assert.throws(()=>outer!.get('SELECT 1'),/expired/);
  await db.withTransaction(async connection=>assert.equal(connection.get('SELECT count(*) AS n FROM effects')!.n,3));
  await assert.rejects(db.run(async()=>{await db.withTransaction(async connection=>{connection.run('INSERT INTO effects VALUES (?)',['outer-aborted']);});throw new Error('abort outer');}),/abort outer/);
  await db.withTransaction(async connection=>assert.equal(connection.get('SELECT count(*) AS n FROM effects')!.n,3));
});

test('SQLite rejects overlapping and unawaited scopes without allowing late writes', async t => {
  const db = new SqliteCompanyDatabase(await fixture()); t.after(()=>db.close());
  await db.withTransaction(async connection=>connection.run('CREATE TABLE effects (id TEXT PRIMARY KEY)'));
  await db.withTransaction(async outer=>{
    let release!:()=>void; const gate=new Promise<void>(resolve=>{release=resolve;});
    const first=db.withTransaction(async child=>{child.run('INSERT INTO effects VALUES (?)',['overlap']);await gate;throw new Error('abort overlap');});
    await assert.rejects(db.withTransaction(async()=>{}),/concurrent nested/);
    assert.throws(()=>outer.get('SELECT 1'),/concurrent/);
    release();await assert.rejects(first,/abort overlap/);
    outer.run('INSERT INTO effects VALUES (?)',['outer']);
  });
  let late: Promise<void> | undefined, release!:()=>void, entered!:()=>void;
  const gate=new Promise<void>(resolve=>{release=resolve;}), ready=new Promise<void>(resolve=>{entered=resolve;});
  await assert.rejects(db.run(async()=>{
    await db.withTransaction(async()=>{
      late=db.withTransaction(async child=>{child.run('INSERT INTO effects VALUES (?)',['late-before']);entered();await gate;child.run('INSERT INTO effects VALUES (?)',['late-after']);});
      await ready;
    });
  }),/unawaited nested/);
  release();assert.ok(late);await assert.rejects(late,/expired/);
  await db.withTransaction(async connection=>assert.equal(connection.get('SELECT count(*) AS n FROM effects')!.n,1));
});

test('SQLite delayed operation callbacks cannot persist after an ancestor terminates', async t => {
  const db=new SqliteCompanyDatabase(await fixture());t.after(()=>db.close());
  for (const outerActive of [false,true]) {
    const namespace='delayed-'+outerActive, store=db.businessOperations(namespace);
    let release!:()=>void,entered!:()=>void,late:Promise<unknown>|undefined;
    const gate=new Promise<void>(resolve=>{release=resolve;}),ready=new Promise<void>(resolve=>{entered=resolve;});
    const terminate=()=>db.run(async()=>{
      late=store.transaction('late',async slot=>{
        slot.record={version:1,id:'late',owner:{companyId:'company',clientId:'client',userId:'user',accountId:'account'},scopes:[],revisions:{}};
        entered();await gate;
      }).then(()=>null,error=>error as unknown);
      await ready;
    });
    const verify=async()=>{
      release();assert.ok(late);const error=await late;
      assert.equal(await store.transaction('late',async slot=>slot.record),undefined,'expired callback must leave no receipt');
      assert.ok(error instanceof Error);assert.match(error.message,/expired/);
    };
    if (outerActive) await db.run(async()=>{await assert.rejects(terminate(),/unawaited nested/);await verify();});
    else {await assert.rejects(terminate(),/unawaited nested/);await verify();}
  }
});
