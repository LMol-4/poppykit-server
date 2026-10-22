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
const directories = [];
after(async () => { for (const dir of directories) await rm(dir, { recursive: true, force: true }); });
async function fixture() { const dir = await mkdtemp(join(tmpdir(), 'poppy-company-')); directories.push(dir); return join(dir, 'state.db'); }
function worker(t, mode, path) {
  const child = fork(new URL('../test-support/storage-worker.mjs', import.meta.url), [mode, path], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const exited = once(child, 'exit'); let errors = ''; child.stderr.on('data', b => { errors += b; });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill(); await exited; } });
  const message = new Promise((resolve, reject) => { child.once('message', resolve); child.once('error', reject); child.once('exit', code => { if (code) reject(new Error(errors)); }); });
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
  assert.equal(raw.prepare('SELECT count(*) AS n FROM records').get().n, 0);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM events').get().n, 0); raw.close();
});
test('death after an external side effect needs application idempotency, and stale worker cannot publish', { timeout: 15000 }, async t => {
  const path = await fixture(), accept = worker(t, 'accept', path); const receipt = await accept.message; await accept.exited;
  const first = worker(t, 'effect', path); const old = await first.message; first.child.kill(); await first.exited;
  const db = new SqliteCompanyDatabase(path); const store = db.conversations('test'); const current = setup({ store, leaseMs: 1 });
  current.clock.advance(2000);
  const fresh = await current.service.claim(); assert.equal(fresh.workId, old.work.workId); assert.notEqual(fresh.fence, old.work.fence);
  await assert.rejects(current.service.reply(old.work, 'output', { id: 'reply', sender: 'agent', text: 'done' }), { code: 'stale_work' });
  const external = new DatabaseSync(path + '.external');
  external.prepare('INSERT OR IGNORE INTO effects VALUES (?)').run(fresh.workId);
  assert.equal(external.prepare('SELECT count(*) AS n FROM effects').get().n, 1); external.close();
  await current.service.reply(fresh, 'output', { id: 'reply', sender: 'agent', text: 'done' });
  await current.service.reply(fresh, 'output', { id: 'reply', sender: 'agent', text: 'done' });
  const state = await store.read({ conversationId: receipt.receipt.conversation_id });
  assert.equal(state.conversations[receipt.receipt.conversation_id].events.filter(e => e.message?.id === 'reply').length, 1);
  db.close();
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
      state.bindings[state.conversations[first].bindingId].invalid = undefined;
    }), /non-JSON/);
    assert.deepEqual((await store.read({ conversationId: first })).conversations[first].context, {});
    await Promise.all([store.read({ conversationId: first }), store.read({ conversationId: first })]);
  });
});
test('durable issuer rotates and revokes atomically; authority and conversation mutation share one transaction', async t => {
  const path = await fixture(), db = new SqliteCompanyDatabase(path); t.after(() => db.close());
  const env = await issuerSetup({ store: db.issuer(ISSUER), coordinator: db, requireDpopNonce: false });
  const start = await env.send(); assert.equal(start.status, 200);
  const verifier = 'v'.repeat(43), url = new URL(ISSUER + '/authorize');
  const fields = { response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'poppy:read', state: 'state', code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url') };
  for (const [name, value] of Object.entries(fields)) url.searchParams.set(name, value);
  const view = await env.issuer.beginAuthorization(new Request(url), 'binding');
  const callback = await env.issuer.completeAuthorization(view.id, 'binding', { accountId: 'account', scopes: ['poppy:read'] });
  const signed = await env.send({ grant_type: 'authorization_code', assertion: undefined, code: callback.searchParams.get('code'), redirect_uri: REDIRECT, code_verifier: verifier, session_id: start.body.session_id });
  assert.equal(signed.status, 200, JSON.stringify(signed.body));
  const { principal } = await env.issuer.authority.introspect(signed.body.access_token);
  const rotation = worker(t, 'rotate', path), revocation = worker(t, 'revoke', path);
  const input = { refreshToken: signed.body.refresh_token, sessionId: start.body.session_id };
  rotation.child.send(input); revocation.child.send(input);
  const [rotatedResult, revokedResult] = await Promise.all([rotation.message, revocation.message]);
  await Promise.all([rotation.exited, revocation.exited]);
  assert.ok([200, 400].includes(rotatedResult.status));
  if (rotatedResult.status === 400) assert.equal(rotatedResult.error, 'invalid_grant');
  assert.equal(revokedResult.status, 200);
  await assert.rejects(env.issuer.authority.introspect(signed.body.access_token), { code: 'invalid_token' });
  // Start a new grant to test the policy/transaction ordering separately.
  const view2 = await env.issuer.beginAuthorization(new Request(url), 'binding2');
  const callback2 = await env.issuer.completeAuthorization(view2.id, 'binding2', { accountId: 'account', scopes: ['poppy:read'] });
  const signed2 = await env.send({ grant_type: 'authorization_code', assertion: undefined, code: callback2.searchParams.get('code'), redirect_uri: REDIRECT, code_verifier: verifier, session_id: start.body.session_id });
  const currentPrincipal = (await env.issuer.authority.introspect(signed2.body.access_token)).principal;
  const conversations = setup({ store: db.conversations(ISSUER), policy: env.issuer.authority.policy, authenticator: { authenticate: async () => currentPrincipal } });
  let entered; const gate = new Promise(r => { entered = r; }); let release; const hold = new Promise(r => { release = r; });
  const accepted = env.issuer.authority.policy.withCurrent(currentPrincipal, ['poppy:read'], async () => { entered(); await hold; return conversations.start(hello); });
  await gate;
  const revoked = env.issuer.disconnect(CLIENT, 'account');
  release(); const receipt = await accepted; assert.equal(receipt.status, 201); await revoked;
  assert.equal((await conversations.read(receipt.body.conversation_id)).status, 401);
  await assert.rejects(env.issuer.authority.policy.withCurrent(currentPrincipal, [], async () => { throw new Error('must not run'); }), { code: 'invalid_token' });
  const rotated = await env.send({ grant_type: 'refresh_token', assertion: undefined, refresh_token: signed.body.refresh_token, session_id: start.body.session_id });
  assert.equal(rotated.body.error, 'invalid_grant');
  assert.deepEqual((await db.issuer('https://other.test').read({ kind: 'principal', sessionId: start.body.session_id })).sessions, {});
});
