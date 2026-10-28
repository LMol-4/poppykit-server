import assert from 'node:assert/strict';
import { expectValue } from './assertions.mjs';
import { SqliteCompanyDatabase } from '../dist/sqlite.js';
import { setup, hello } from '../tests/conversation/support.mjs';
import { DatabaseSync } from 'node:sqlite';
import { setup as issuerSetup, ISSUER } from '../tests/auth/issuer-support.mjs';
import { effect } from './synthetic-effect.mjs';
import { PostgresCompanyDatabase } from '../dist/postgres.js';
import { testPool } from './postgres.mjs';
const [mode, path] = process.argv.slice(2);
const pool = process.env.D1_POSTGRES === '1' ? testPool() : undefined;
const db = pool ? new PostgresCompanyDatabase(pool) : new SqliteCompanyDatabase(path);
const prefix = pool ? path + ':' : '';
const store = db.conversations(prefix + 'test');
const t = setup({ store, leaseMs: 1 });
const pause = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
if (mode === 'rotate' || mode === 'revoke') {
  const input:unknown=await new Promise(resolve=>process.once('message',resolve));assert.ok(input&&typeof input==='object'&&'refreshToken' in input&&typeof input.refreshToken==='string'&&'sessionId' in input&&typeof input.sessionId==='string');
  const env = await issuerSetup({ store: db.issuer(prefix + ISSUER), coordinator: db, requireDpopNonce: false });
  if (mode === 'rotate') {
    const result = await env.send({ grant_type: 'refresh_token', assertion: undefined, refresh_token: input.refreshToken, session_id: input.sessionId });
    expectValue(process.send).call(process, { status: result.status, error: result.body.error });
  } else {
    const response = await env.issuer.revoke(new Request(ISSUER + '/oauth/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: input.refreshToken, client_id: 'https://agent.test/agent.json', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await env.clientAssertion() }) }));
    expectValue(process.send).call(process, { status: response.status });
  }
  await db.close();
} else if (mode === 'before-commit') {
  await db.run(async () => {
    await t.start(hello);
    expectValue(process.send).call(process, { ready: true }); pause();
  });
} else if (mode === 'accept' || mode === 'after-commit') {
  const receipt = await t.start(hello);
  expectValue(process.send).call(process, { ready: true, receipt: receipt.body });
  if (mode === 'after-commit') pause();
  await db.close();
} else {
  t.clock.advance(1000);
  const work = await t.service.claim();
  if (!work) throw new Error('expected pending work');
  if(mode==='effect-contract'){
    const result=effect(path+'.contract','tenant-a',work.workId,{record:'opaque-17',value:1});
    expectValue(process.send).call(process, {ready:true,work,result});pause();
  }
  const external = new DatabaseSync(path + '.external');
  external.exec('CREATE TABLE IF NOT EXISTS effects (id TEXT PRIMARY KEY)');
  // Application contract: the stable work ID deduplicates its own side effect.
  external.prepare('INSERT OR IGNORE INTO effects VALUES (?)').run(work.workId); external.close();
  if (mode === 'effect') { expectValue(process.send).call(process, { ready: true, work }); pause(); }
  await t.service.reply(work, 'output', { id: 'reply', author: { type: 'agent' }, text: 'done' });
  await t.service.finish(work, 'completed'); await db.close();
  expectValue(process.send).call(process, { ready: true, work });
}
await pool?.end();
