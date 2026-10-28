// Contract tests for a host's conversation storage adapter. Call runConversationAdapterContract(fixture) from a
// node:test file; each case gets a fresh fixture: two handles (e.g. two connections) on one fresh namespace that the
// host created from initialConversationState. Process kill and engine atomicity stay the host's own tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthorityError } from './auth/authority.js';
import type { AuthorityPolicy, Principal } from './auth/authority.js';
import { createConversationService, resetConversationState } from './conversation/service.js';
import type { ConversationOptions, ConversationService, WorkRef } from './conversation/service.js';
import type { IssuerStore } from './reference-auth/store.js';
export type IssuerAdapterFixture = () => Promise<{store:IssuerStore;second:IssuerStore;close():Promise<void>}>;
/** A fresh shared namespace, including absent-row serialization; no vendor-specific fixture is required. */
export function runIssuerAdapterContract(fixture:IssuerAdapterFixture):void {
  test('issuer adapter contract: replay updates serialize, snapshots detach and failed callbacks roll back',async()=>{
    const f=await fixture(), selection={kind:'browser',sessionId:'absent',replayKey:'counter'} as const;
    try {
      await Promise.all(Array.from({length:10},(_,i)=>(i%2?f.store:f.second).transaction(selection,state=>{state.replay.counter=(state.replay.counter??0)+1;})));
      const state=await f.store.read(selection);assert.equal(state.replay.counter,10);state.replay.counter=999;
      await assert.rejects(f.store.transaction(selection,draft=>{draft.replay.counter=0;throw new Error('rollback');}),/rollback/);
      await assert.rejects(f.store.transaction(selection,async draft=>{draft.replay.counter=0;}));
      assert.equal((await f.second.read(selection)).replay.counter,10);
    } finally {await f.close();}
  });
}

type Store = ConversationOptions['store'] & { inspect(): Promise<import('./conversation/service.js').ConversationStoreState>; adminTransaction<T>(change: (draft: import('./conversation/service.js').ConversationStoreState) => T): Promise<T> };
export type ConversationAdapterFixture = () => Promise<{ store: Store; second: Store; close(): Promise<void> }>;

const endpoint = 'https://contract.example.test/poppy/conversations';
const base = { issuer: 'https://auth.contract.test', clientId: 'https://agent.contract.test/client', sessionId: 's1', userId: 'u_1', scopes: [], tokenExpiresAt: 9e12, sessionVersion: 1 };
const principals: Record<string, Principal> = {
  signedOut: base,
  account1: { ...base, accountId: 'acct_1', scopes: ['orders:read'] },
  account2: { ...base, accountId: 'acct_2', scopes: ['orders:read'] },
};
const message = { id: 'msg_1', author: { type: 'agent' }, text: 'Where is order 1042?' } as const;
const reply = { id: 'msg_r1', author: { type: 'agent' }, text: 'Shipped.' } as const;

function check<T>(held: readonly string[], needed: readonly string[], action: () => Promise<T>): Promise<T> {
  if (!needed.every(scope => held.includes(scope))) return Promise.reject(new AuthorityError('insufficient_scope'));
  return action();
}
const policy: AuthorityPolicy = {
  withCurrent: (principal, scopes, action) => check(principal.scopes, scopes, action),
  withAccepted: (authority, scopes, action) => check(authority.principal.scopes, scopes, action),
};
function serviceOn(store: ConversationOptions['store'], clock: { now(): number }): ConversationService {
  const authenticator = {
    async authenticate(request: Request) {
      const principal = principals[request.headers.get('authorization')?.slice('DPoP '.length) ?? ''];
      if (!principal) throw new AuthorityError('invalid_token');
      return principal;
    },
  };
  return createConversationService({historyScopes:['orders:read'], endpoint, store, authenticator, policy, clock, leaseMs: 1000, supportedScopes: ['orders:read'] });
}
async function call(service: ConversationService, path: string, as: string, body?: unknown, query = '') {
  const response = await service.handle(new Request(`${endpoint}${path}${query}`, {
    method: body === undefined ? 'GET' : 'POST', headers: { authorization: `DPoP ${as}` }, body: body === undefined ? undefined : JSON.stringify(body),
  }));
  return { status: response.status, body: await response.json() };
}

export function runConversationAdapterContract(fixture: ConversationAdapterFixture): void {
  const clock = { t: Date.UTC(2026, 9, 19, 12), now: () => clock.t };
  async function withFixture(body: (stores: { store: Store; second: Store }) => Promise<void>): Promise<void> {
    const opened = await fixture();
    try { await body(opened); } finally { await opened.close(); }
  }

  test('adapter contract: concurrent conflicting output retries publish one immutable result',()=>withFixture(async({store,second})=>{
    const a=serviceOn(store,clock),b=serviceOn(second,clock);
    const id=(await call(a,'','signedOut',{message})).body.conversation_id;
    const work=(await a.claim())!;
    const results=await Promise.allSettled([a.reply(work,'same-call',reply),b.reply(work,'same-call',{...reply,text:'conflicting result'})]);
    assert.equal(results.filter(result=>result.status==='fulfilled').length,1);
    const failed=results.find(result=>result.status==='rejected');assert.ok(failed&&failed.status==='rejected');assert.equal(failed.reason.code,'output_conflict');
    const events=(await call(a,`/${id}/events`,'signedOut')).body.events as {message?:{id:string}}[];
    assert.equal(events.filter(event=>event.message?.id===reply.id).length,1);
  }));

  test('adapter contract: reads and results are detached; failed, non-JSON and async changes roll back', () => withFixture(async ({ store, second }) => {
    const snapshot = await store.inspect();
    snapshot.bindings.leaked = {};
    assert.deepEqual((await store.inspect()).bindings, {});
    let draftAfterCommit: { bindings: Record<string, { accountId?: string }> } | undefined;
    const result = await store.adminTransaction(draft => { draft.bindings.kept = {}; draftAfterCommit = draft; return draft.bindings; });
    result.kept.accountId = 'leaked';
    draftAfterCommit!.bindings.late = {};
    assert.deepEqual((await second.inspect()).bindings, { kept: {} });
    await assert.rejects(store.adminTransaction(draft => { draft.bindings.thrown = {}; throw new Error('abort'); }), { message: 'abort' });
    await assert.rejects(store.adminTransaction(draft => { draft.bindings.undefinedField = { accountId: undefined }; }));
    await assert.rejects(store.adminTransaction((async (draft: { bindings: Record<string, object> }) => { draft.bindings.async = {}; }) as never));
    assert.deepEqual((await second.inspect()).bindings, { kept: {} });
  }));

  test('adapter contract: concurrent transactions on both handles lose no update', () => withFixture(async ({ store, second }) => {
    await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? store : second).adminTransaction(draft => { draft.bindings[`b${i}`] = {}; })));
    assert.equal(Object.keys((await store.inspect()).bindings).length, 20);
  }));

  test('adapter contract: simultaneous first-message retries on both handles start one conversation and one job', () => withFixture(async ({ store, second }) => {
    const [a, b] = [serviceOn(store, clock), serviceOn(second, clock)];
    const results = await Promise.all([a, b, a, b].map(service => call(service, '', 'signedOut', { message })));
    assert.ok(results.every(result => result.status === 201));
    assert.equal(new Set(results.map(result => result.body.conversation_id)).size, 1);
    const state = await second.inspect();
    assert.equal(Object.keys(state.conversations).length, 1);
    assert.equal(state.work.length, 1);
  }));

  test('adapter contract: racing account use across handles binds parent and Direct Conversation to exactly one account', () => withFixture(async ({ store, second }) => {
    const [a, b] = [serviceOn(store, clock), serviceOn(second, clock)];
    const parent = (await call(a, '', 'account1', { message })).body.conversation_id;
    const parentWork = (await a.claim())!;
    const outcome = (promise: Promise<{ accountId: string }>) => promise.then(value => value.accountId, error => String(error.code));
    const results = await Promise.all([
      outcome(a.requireAccount(parentWork, ['orders:read'])),
      (async () => {
        const opened = await call(b, '', 'account2', { parent_conversation_id: parent, message: { id: 'msg_c', author: { type: 'human' }, text: 'Hi.' } });
        if (opened.status !== 201) return String(opened.body.error);
        return outcome(b.claim().then(work => b.requireAccount(work!, ['orders:read'])));
      })(),
    ]);
    const winners = results.filter(result => result.startsWith('acct_'));
    assert.equal(winners.length, 1, String(results));
    const state = await store.inspect();
    assert.ok(Object.values(state.conversations).every(conversation => conversation.bindingId === parent));
    assert.deepEqual(state.bindings[parent], { accountId: winners[0] });
    const loser = winners[0] === 'acct_1' ? 'account2' : 'account1';
    for (const id of Object.keys(state.conversations)) assert.deepEqual((await call(b, `/${id}/events`, loser)).body, { error: 'insufficient_scope' });
  }));

  test('adapter contract: lease reclaim on the other handle fences the old worker; output IDs dedupe', () => withFixture(async ({ store, second }) => {
    const [a, b] = [serviceOn(store, clock), serviceOn(second, clock)];
    const id = (await call(a, '', 'signedOut', { message })).body.conversation_id;
    const old = (await a.claim())!;
    clock.t += 1000;
    const fresh = (await b.claim())!;
    assert.deepEqual([fresh.workId === old.workId, fresh.fence === old.fence], [true, false]);
    await assert.rejects(a.reply(old, 'out_1', reply), { code: 'stale_work' });
    await b.reply(fresh, 'out_1', reply);
    await a.reply(fresh as WorkRef, 'out_1', reply);
    await assert.rejects(a.reply(fresh, 'out_1', { ...reply, text: 'changed' }), { code: 'output_conflict' });
    const events = (await call(b, `/${id}/events`, 'signedOut')).body.events as { message?: { id: string } }[];
    assert.equal(events.filter(event => event.message?.id === reply.id).length, 1);
  }));

  test('adapter contract: reserved output IDs persist atomic reply and prompt receipts across handles', () => withFixture(async ({ store, second }) => {
    const a = serviceOn(store, clock);
    const id = (await call(a, '', 'signedOut', { message })).body.conversation_id;
    const work = (await a.claim())!;
    for (const outputId of ['__proto__', 'constructor', 'ordinary']) {
      const b = serviceOn(second, clock);
      const value = { ...reply, id: `reply_${outputId}` };
      await a.reply(work, outputId, value);
      await b.reply(work, outputId, value);
      await assert.rejects(b.reply(work, outputId, { ...value, text: 'changed' }), { code: 'output_conflict' });
      await a.requestAuthorization(work, `auth_${outputId}`, ['orders:read']);
      await b.requestAuthorization(work, `auth_${outputId}`, ['orders:read']);
      await a.requestUser(work, `user_${outputId}`, outputId);
      await b.requestUser(work, `user_${outputId}`, outputId);
      await assert.rejects(b.requestUser(work, `user_${outputId}`, 'changed'), { code: 'output_conflict' });
      const persisted = await second.inspect();
      const receipt = persisted.work.find(row => row.id === work.workId)!;
      assert.ok(Object.hasOwn(receipt.outputs, outputId));
    }
    const events = (await call(serviceOn(second, clock), `/${id}/events`, 'signedOut')).body.events as { type: string; message?: { role: string } }[];
    assert.equal(events.filter(event => event.message?.role === 'company').length, 3);
    assert.equal(events.filter(event => event.type === 'authorization').length, 3);
    assert.equal(events.filter(event => event.type === 'user_requested').length, 3);
    clock.t += 1000;
    await serviceOn(second, clock).claim();
    await assert.rejects(a.reply(work, '__proto__', reply), { code: 'stale_work' });
  }));

  test('adapter contract: a waited POST committed before a crash is recovered unchanged on the other handle', () => withFixture(async ({ store, second }) => {
    const crashing = serviceOn({ read: () => store.inspect(), transaction: (_selection, change) => store.adminTransaction(change).then(() => { throw new Error('crash after commit'); }) }, clock);
    await assert.rejects(call(crashing, '', 'signedOut', { message }, '?wait=10'), { message: 'crash after commit' });
    const b = serviceOn(second, clock);
    const recovered = await call(b, '', 'signedOut', { message }, '?wait=1');
    assert.equal(recovered.status, 201);
    assert.equal(recovered.body.events.length, 2);
    await b.reply((await b.claim())!, 'out_1', reply);
    assert.deepEqual(await call(b, '', 'signedOut', { message }), recovered);
    assert.equal((await store.inspect()).work.length, 1);
  }));

  test('adapter contract: a reset through one handle invalidates fences and conversations used through the other', () => withFixture(async ({ store, second }) => {
    const a = serviceOn(store, clock);
    const id = (await call(a, '', 'signedOut', { message })).body.conversation_id;
    const work = (await a.claim())!;
    const { generation } = await store.inspect();
    await second.adminTransaction(resetConversationState);
    assert.notEqual((await store.inspect()).generation, generation);
    await assert.rejects(a.reply(work, 'out_1', reply), { code: 'stale_work' });
    assert.equal(await a.claim(), null);
    assert.equal((await call(a, `/${id}/events`, 'signedOut')).status, 404);
  }));
}
