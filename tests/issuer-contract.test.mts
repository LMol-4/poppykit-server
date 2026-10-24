import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { runIssuerAdapterContract } from '../dist/adapter-contract.js';
import { SqliteCompanyDatabase } from '../dist/sqlite.js';
import { PostgresCompanyDatabase } from '../dist/postgres.js';
import { testPool } from '../test-support/postgres.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { resultCipher } from '../test-support/result-cipher.mjs';
import { setup, CLIENT, ISSUER, REDIRECT } from './auth/issuer-support.mjs';
import { memoryCoordinator } from './conversation/support.mjs';
import type { IssuerAdapterFixture } from '../dist/adapter-contract.js';
import type { IssuerSelection, IssuerStore } from '../dist/reference-auth/store.js';
import type { IssuerState } from '../dist/reference-auth/index.js';
function completionContract(fixture: IssuerAdapterFixture) {
  test('Direct completion survives lost commit responses, independent handles and restart without minting a new callback', async () => {
    const f = await fixture();
    try {
      const cipher = resultCipher();
      let fault: 'before' | 'after' | undefined;
      const faultStore: IssuerStore = {
        read: selection => f.store.read(selection),
        async transaction<T>(selection: IssuerSelection, change: (state: IssuerState) => T) {
          if (selection.kind === 'authorization' && fault === 'before') { fault = undefined; throw new Error('before commit'); }
          const result = await f.store.transaction(selection, change);
          if (selection.kind === 'authorization' && fault === 'after') { fault = undefined; throw new Error('lost commit acknowledgment'); }
          return result;
        },
      };
      const a = await setup({ store: faultStore, coordinator: memoryCoordinator(), authorizationResultCipher: cipher, requireDpopNonce: false });
      const b = await setup({ store: f.second, coordinator: memoryCoordinator(), authorizationResultCipher: cipher, requireDpopNonce: false });
      const binding = 'durable-browser-binding-0123456789';
      for (const decision of [{ denied: true as const }, { accountId: 'acct_1', scopes: ['poppy:read'] }]) {
        const url = new URL(`${ISSUER}/authorize`);
        const verifier = 'v'.repeat(43);
        url.search = new URLSearchParams({ response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'poppy:read', state: randomUUID(), code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
        const view = await a.issuer.beginAuthorization(new Request(url), binding);
        fault = 'before';
        await assert.rejects(a.issuer.completeAuthorization(view.id, binding, decision), /before commit/);
        assert.equal((await f.second.read({ kind: 'authorization', id: view.id })).authorizations[view.id].completion, undefined);
        fault = 'after';
        await assert.rejects(a.issuer.completeAuthorization(view.id, binding, decision), /lost commit acknowledgment/);
        const committed = (await f.second.read({ kind: 'authorization', id: view.id })).authorizations[view.id].completion!;
        const callbacks = await Promise.all([a.issuer.completeAuthorization(view.id, binding, decision), b.issuer.completeAuthorization(view.id, binding, decision)]);
        assert.equal(callbacks[0].href, cipher.open(committed.callback));
        assert.equal(callbacks[0].href, callbacks[1].href);
        assert.equal((await b.issuer.completeAuthorization(view.id, binding, decision)).href, callbacks[0].href);
        await assert.rejects(b.issuer.completeAuthorization(view.id, 'foreign-browser', decision), { code: 'invalid_request' });
        const opposite = 'denied' in decision ? { accountId: 'acct_1', scopes: ['poppy:read'] } : { denied: true as const };
        await assert.rejects(b.issuer.completeAuthorization(view.id, binding, opposite), { code: 'invalid_request' });
        const saved = await f.second.read({ kind: 'authorization', id: view.id });
        const code = callbacks[0].searchParams.get('code');
        if (code) {
          assert.ok(!JSON.stringify(saved).includes(code));
          const session = await a.send(); assert.equal(session.status, 200);
          const signed = await a.send({ grant_type: 'authorization_code', assertion: undefined, code, redirect_uri: REDIRECT, code_verifier: verifier, session_id: session.body.session_id });
          assert.equal(signed.status, 200);
          const refresh = (token: string | undefined) => a.send({ grant_type: 'refresh_token', assertion: undefined, refresh_token: token });
          const first = signed.body.refresh_token;
          const rotated = await refresh(first); assert.equal(rotated.status, 200);
          const latest = await refresh(rotated.body.refresh_token); assert.equal(latest.status, 200);
          assert.equal((await refresh(first)).body.error, 'invalid_grant');
          assert.equal((await refresh(latest.body.refresh_token)).body.error, 'invalid_grant', 'oldest replay revokes every descendant across durable commits');
          await assert.rejects(a.issuer.authority.introspect(latest.body.access_token!), { code: 'invalid_token' });
          await a.issuer.disconnect(CLIENT, 'acct_1');
          await assert.rejects(b.issuer.completeAuthorization(view.id, binding, decision), { code: 'invalid_request' });
        }
        b.clock.now = view.expiresAt;
        await assert.rejects(b.issuer.completeAuthorization(view.id, binding, decision), { code: 'invalid_request' });
        b.clock.now = a.clock.now;
      }
    } finally { await f.close(); }
  });
}
const sqliteFixture: IssuerAdapterFixture = async()=>{
  const dir=await mkdtemp(join(tmpdir(),'issuer-contract-')),path=join(dir,'db.sqlite'),a=new SqliteCompanyDatabase(path),b=new SqliteCompanyDatabase(path);
  return {store:a.issuer('contract'),second:b.issuer('contract'),close:async()=>{a.close();b.close();await rm(dir,{recursive:true});}};
};
runIssuerAdapterContract(sqliteFixture); completionContract(sqliteFixture);
if(process.env.D1_POSTGRES==='1') {
const postgresFixture: IssuerAdapterFixture = async()=>{
  const pool=testPool(),a=new PostgresCompanyDatabase(pool),b=new PostgresCompanyDatabase(pool),namespace=(process.env.D1_NAMESPACE??'d1')+':'+randomUUID();
  return {store:a.issuer(namespace),second:b.issuer(namespace),close:async()=>{await a.close();await b.close();await pool.end();}};
};
runIssuerAdapterContract(postgresFixture); completionContract(postgresFixture);
}
