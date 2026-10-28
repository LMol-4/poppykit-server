import type {Message,AuthorType,ConversationEvent} from '../../dist/protocol/wire.js';
import type {ConversationOptions} from '../../dist/conversation/service.js';
import { expectValue,messageValue,optionalMessage } from '../../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthorityError, createConversationService, initialConversationState, PublicationError } from '../../dist/index.js';
import { endpoint, hello, principals, setup, memoryStore } from './support.mjs';

test('company author details survive reply and history while responder and user identity remain enforced',async()=>{
  const t=setup({authorizeOperator:async()=>{}}),id=(await t.start(hello)).body.conversation_id;
  const work=expectValue(await t.service.claim());
  const author={type:'agent' as const,id:'concierge',name:'Concierge',image:'https://company.example/concierge.png'};
  await t.service.reply(work,'company',{id:'company_reply',author,text:'Hello.'});
  const page=(await t.read(id)).body;
  assert.deepEqual(page.events.find((e:ConversationEvent)=>e.type==='message'&&(e.message as Message).id==='company_reply').message.author,author);
  await assert.rejects(t.service.reply(work,'wrong',{id:'wrong',author:{type:'human'},text:'Wrong responder'}),{name:'ValidationError'});
  assert.equal((await t.start({id:'forged',author,text:'forged user identity'})).status,400);
});

test('start returns 201 three-field ack, records events and pending work', async () => {
  const t = setup();
  const res = await t.start(hello);
  assert.equal(res.status, 201);
  assert.deepEqual(Object.keys(res.body).sort(), ['conversation_id', 'responder', 'status']);
  assert.equal(res.body.status, 'working');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const state = await t.store.read();
  const conversation = state.conversations[res.body.conversation_id];
  assert.deepEqual(conversation.events.map((event:ConversationEvent) => event.type), ['message', 'state']);
  assert.deepEqual(conversation.events[0].message, { ...hello, role: 'user' });
  assert.equal(state.work.length, 1);
  assert.equal(state.work[0].phase, 'pending');
  assert.equal(state.work[0].authority.principal.userId, 'u_alice');
});

test('first-message retry returns the original conversation without a second job', async () => {
  const t = setup();
  const first = await t.start(hello);
  t.clock.advance(1000);
  // Reordered keys and a client-sent role are the same content.
  const retry = await t.start({ x_extension: { keep: true }, data: { a: [1, 2], b: 1 }, text: hello.text, author: { type: 'agent' }, id: 'msg_1', role: 'company' });
  assert.equal(retry.status, 201);
  assert.deepEqual(retry.body, first.body);
  const state = await t.store.read();
  assert.equal(Object.keys(state.conversations).length, 1);
  assert.equal(state.work.length, 1);
  assert.equal(state.conversations[first.body.conversation_id].events.length, 2);
});

test('simultaneous first-message retries create one conversation', async () => {
  const t = setup();
  const results = await Promise.all([t.start(hello), t.start(hello), t.start(hello)]);
  assert.equal(new Set(results.map(result => result.body.conversation_id)).size, 1);
  const state = await t.store.read();
  assert.equal(Object.keys(state.conversations).length, 1);
  assert.equal(state.work.length, 1);
});

test('changed content, extension field or target under a used message ID conflicts', async () => {
  const t = setup();
  const first = await t.start(hello);
  for (const changed of [{ ...hello, text: 'Where is order 1043?' }, { ...hello, x_extension: { keep: false } }, { ...hello, data: { a: [2, 1], b: 1 } }]) {
    const res = await t.start(changed);
    assert.equal(res.status, 409);
    assert.deepEqual(res.body, { error: 'message_id_conflict' });
  }
  const other = await t.start({ id: 'msg_2', author: { type: 'agent' }, text: 'second conversation' });
  // Same message ID sent to a different conversation is not reinterpreted.
  const moved = await t.send(other.body.conversation_id, hello);
  assert.equal(moved.status, 409);
  const state = await t.store.read();
  assert.equal(state.work.length, 2);
  assert.equal(state.conversations[first.body.conversation_id].events.length, 2);
});

test('message ID scope is per user: another user can reuse it', async () => {
  const t = setup();
  const a = await t.start(hello);
  const b = await t.start(hello, { as: 'bob' });
  assert.equal(b.status, 201);
  assert.notEqual(a.body.conversation_id, b.body.conversation_id);
});

test('retry reauthenticates and is denied when current policy denies', async () => {
  const t = setup();
  await t.start(hello);
  const unauthenticated = await t.start(hello, { as: 'nobody' });
  assert.equal(unauthenticated.status, 401);
  assert.deepEqual(unauthenticated.body, { error: 'invalid_token' });
  assert.equal(unauthenticated.headers.get('www-authenticate'), 'DPoP error="invalid_token", algs="ES256"');
  t.policy.deny = new AuthorityError('invalid_token');
  const denied = await t.start(hello);
  assert.equal(denied.status, 401);
});

test('foreign user or client cannot read, send to, or learn of a conversation', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  for (const as of ['bob', 'otherClient']) {
    assert.deepEqual(await t.read(body.conversation_id, { as }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
    assert.equal((await t.send(body.conversation_id, { id: 'msg_x', author: { type: 'agent' }, text: 'hi' }, { as })).status, 404);
  }
  assert.equal((await t.read('cnv_unknown')).status, 404);
  assert.equal((await t.read('__proto__')).status, 404);
  assert.equal((await t.read('constructor')).status, 404);
});

test('account-bound conversation: same account reads with orders:read; same User signed out or on another account gets insufficient_scope; others 404', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  t.store.set(state => { state.bindings[body.conversation_id].accountId = 'acct_1'; });
  const ok = await t.read(body.conversation_id, { as: 'aliceSignedIn' });
  assert.equal(ok.status, 200);
  assert.deepEqual(t.calls.at(-1), { kind: 'current', userId: 'u_alice', scopes: ['orders:read'] });
  const signedOut = await t.read(body.conversation_id);
  assert.equal(signedOut.status, 403);
  assert.deepEqual(signedOut.body, { error: 'insufficient_scope' });
  // Spec 7.11 and 4.2: the same User on account B is not signed in to account A.
  const otherAccount = await t.read(body.conversation_id, { as: 'aliceOtherAccount' });
  assert.deepEqual([otherAccount.status, otherAccount.body], [403, { error: 'insufficient_scope' }]);
  // A different User on account B is a stranger: 404, also for an unknown ID.
  for (const id of [body.conversation_id, 'cnv_unknown']) {
    assert.deepEqual(await t.read(id, { as: 'bobOtherAccount' }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
  }
  // A different client on account A without orders:read: 404, as for an unknown ID.
  assert.equal((await t.read(body.conversation_id, { as: 'otherClientNoScopes' })).status, 404);
  // Changed reuse of the first message ID is checked for ownership before any 409.
  assert.equal((await t.start({ ...hello, text: 'changed' }, { as: 'aliceOtherAccount' })).status, 403);
  assert.equal((await t.start({ ...hello, text: 'changed' }, { as: 'bobOtherAccount' })).status, 201, 'message IDs are per User');
  // Retrying the original first message on a now-bound conversation is checked against current ownership too.
  assert.equal((await t.start(hello)).status, 403);
});

test('ownership moves from User ID to account once bound (spec 7.2)', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const id = body.conversation_id;
  const next = (n: string) => ({ id: `msg_${n}`, author: { type: 'agent' }, text: 'more' });
  // Unbound: client_id + User ID, so another User on the same account is a stranger.
  assert.equal((await t.read(id, { as: 'carolSameAccount' })).status, 404);
  assert.equal((await t.send(id, next('c1'), { as: 'carolSameAccount' })).status, 404);
  t.store.set(state => { state.bindings[id].accountId = 'acct_1'; });
  // Bound: client_id + account; the User ID no longer has to match.
  assert.equal((await t.read(id, { as: 'carolSameAccount' })).status, 200);
  assert.equal((await t.send(id, next('c2'), { as: 'carolSameAccount' })).status, 202);
  assert.equal((await t.read(id, { as: 'aliceSignedIn' })).status, 200);
  // Same account through another client, or a signed-out stranger: indistinguishable 404.
  for (const as of ['otherClientSameAccount', 'bob', 'otherClient']) {
    assert.deepEqual(await t.read(id, { as }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
    assert.equal((await t.send(id, next(`x_${as}`), { as })).status, 404);
  }
  // Without orders:read, another client on the same account still sees 404 for a real ID, as for an unknown one.
  assert.deepEqual(await t.read(id, { as: 'otherClientNoScopes' }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
  assert.deepEqual(await t.read('cnv_unknown', { as: 'otherClientNoScopes' }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
  const signedOut = await t.read(id);
  assert.deepEqual([signedOut.status, signedOut.body], [403, { error: 'insufficient_scope' }]);
  assert.equal(signedOut.headers.get('www-authenticate'), 'DPoP error="insufficient_scope", scope="orders:read", algs="ES256"');
  assert.equal((await t.send(id, next('a2'))).status, 403);
});

test('multi-page idle history uses real cursors and six-field pages', async () => {
  const t = setup({ pageSize: 2 });
  const { body } = await t.start(hello);
  const id = body.conversation_id;
  for (const n of [2, 3]) assert.equal((await t.send(id, { id: `msg_${n}`, author: { type: 'agent' }, context: { user_available: n === 2 } })).status, 202);
  // Finish the work so the conversation is idle with history remaining.
  const claim = await t.service.claim();
  await t.service.finish(expectValue(claim), 'completed');
  const seen = [];
  let cursor;
  let res;
  do {
    res = await t.read(id, { query: cursor ? `?cursor=${cursor}` : '' });
    assert.equal(res.status, 200);
    assert.deepEqual(Object.keys(res.body).sort(), ['conversation_id', 'cursor', 'events', 'has_more', 'responder', 'status']);
    assert.equal(res.body.status, 'idle');
    assert.equal(res.body.cursor, res.body.events.at(-1).id);
    seen.push(...res.body.events);
    cursor = res.body.cursor;
  } while (res.body.has_more);
  assert.deepEqual(seen.map((event:ConversationEvent) => event.type), ['message', 'state', 'message', 'message', 'state']);
  assert.equal(new Set(seen.map((event:ConversationEvent) => event.id)).size, 5);
  const empty = await t.read(id, { query: `?cursor=${cursor}` });
  assert.deepEqual([empty.body.events, empty.body.cursor, empty.body.has_more], [[], cursor, false]);
  assert.deepEqual((await t.store.read()).conversations[id].context, { user_available: false });
});

test('context-only message is recorded without creating work', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  await t.service.finish(expectValue(await t.service.claim()), 'completed');
  const res = await t.send(body.conversation_id, { id: 'msg_ctx', author: { type: 'agent' }, context: { locale: 'en-US' } });
  assert.deepEqual([res.status, res.body.status], [202, 'idle']);
  assert.equal(await t.service.claim(), null);
});

test('invalid cursor, wait and malformed requests are rejected without acceptance', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const other = await t.start({ id: 'msg_o', author: { type: 'agent' }, text: 'other' });
  const foreignCursor = (await t.read(other.body.conversation_id)).body.cursor;
  assert.deepEqual((await t.read(body.conversation_id, { query: `?cursor=${foreignCursor}` })).body, { error: 'invalid_cursor' });
  assert.equal((await t.read(body.conversation_id, { query: '?wait=1.5' })).status, 400);
  const badCursorSend = await t.send(body.conversation_id, { id: 'msg_c', author: { type: 'agent' }, text: 'x' }, { query: '?wait=0&cursor=evt_nope' });
  assert.deepEqual([badCursorSend.status, badCursorSend.body], [400, { error: 'invalid_cursor' }]);
  assert.equal((await t.start({ id: 'msg_s', author: { type: 'agent' }, text: 'x' }, { query: '?cursor=evt_nope' })).status, 400);
  const before = (await t.store.read()).work.length;
  for (const bad of [{ id: 'msg bad', author: { type: 'agent' }, text: 'x' }, { id: 'msg_e', author: { type: 'agent' } }, { id: 'msg_r', author: { type: 'robot' }, text: 'x' }]) {
    assert.deepEqual((await t.start(bad)).body, { error: 'invalid_request' });
  }
  assert.equal((await t.call('POST', '', { body: '{not json' })).status, 400);
  assert.equal((await t.call('POST', '', { body: JSON.stringify({ message: { id: 'msg_big', author: { type: 'agent' }, text: 'x'.repeat(1048577) } }) })).status, 400);
  // A Direct Conversation needs a valid parent ID and the User's own words.
  for (const parent of ['bad id', 42]) {
    assert.equal((await t.call('POST', '', { body: { parent_conversation_id: parent, message: { id: 'msg_d', author: { type: 'human' }, text: 'x' } } })).status, 400);
  }
  assert.equal((await t.call('POST', '', { body: { parent_conversation_id: body.conversation_id, message: { id: 'msg_d', author: { type: 'agent' }, text: 'x' } } })).status, 400);
  assert.equal((await t.store.read()).work.length, before);
  // The rejected IDs were never recorded, so they can still be used.
  assert.equal((await t.send(body.conversation_id, { id: 'msg_c', author: { type: 'agent' }, text: 'x' })).status, 202);
});

test('closed conversation rejects new messages but retries return the original receipt', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const first = await t.send(body.conversation_id, { id: 'msg_2', author: { type: 'agent' }, text: 'more' });
  t.store.set(state => { state.conversations[body.conversation_id].status = 'closed'; });
  assert.deepEqual((await t.send(body.conversation_id, { id: 'msg_3', author: { type: 'agent' }, text: 'x' })).body, { error: 'conversation_closed' });
  const retry = await t.send(body.conversation_id, { id: 'msg_2', author: { type: 'agent' }, text: 'more' });
  assert.deepEqual([retry.status, retry.body], [first.status, first.body]);
});

test('POST with wait returns a page receipt that a retry repeats unchanged', async () => {
  const t = setup();
  const res = await t.start(hello, { query: '?wait=0' });
  assert.equal(res.status, 201);
  assert.deepEqual(res.body.events.map((event:ConversationEvent) => event.type), ['message', 'state']);
  assert.equal(res.body.has_more, false);
  const claim = await t.service.claim();
  await t.service.reply(expectValue(claim), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: 'Shipped yesterday.' });
  const retry = await t.start(hello, { query: '?wait=5' });
  assert.deepEqual([retry.status, retry.body], [res.status, res.body]);
});

test('retry without wait of a waited POST still needs orders:read on an account-bound conversation', async () => {
  const t = setup();
  const waited = await t.start(hello, { query: '?wait=0' });
  const plain = await t.send(waited.body.conversation_id, { id: 'msg_2', author: { type: 'agent' }, text: 'more' });
  t.store.set(state => { state.bindings[waited.body.conversation_id].accountId = 'acct_1'; });
  const denied = await t.start(hello, { as: 'aliceNoScopes' });
  assert.deepEqual([denied.status, denied.body], [403, { error: 'insufficient_scope' }]);
  const allowed = await t.start(hello, { as: 'aliceSignedIn' });
  assert.deepEqual([allowed.status, allowed.body], [201, waited.body]);
  // A three-field receipt holds no history, so no read scope is needed.
  const ack = await t.send(waited.body.conversation_id, { id: 'msg_2', author: { type: 'agent' }, text: 'more' }, { as: 'aliceNoScopes' });
  assert.deepEqual([ack.status, ack.body], [plain.status, plain.body]);
});

test('binding that gains an account between read and transaction rescopes a retry to orders:read', async () => {
  const t = setup();
  const waited = await t.start(hello, { query: '?wait=0', as: 'aliceNoScopes' });
  assert.equal(waited.status, 201);
  t.store.afterRead = state => { state.bindings[waited.body.conversation_id].accountId = 'acct_1'; };
  t.calls.length = 0;
  const retry = await t.start(hello, { as: 'aliceNoScopes' });
  assert.deepEqual([retry.status, retry.body], [403, { error: 'insufficient_scope' }]);
  assert.deepEqual(t.calls.map(call => call.scopes), [[], ['orders:read']]);
});

test('routing: wrong origin, path, method and missing auth', async () => {
  const t = setup();
  const res = await t.service.handle(new Request('https://evil.example.test/poppy/conversations', { method: 'POST', body: '{}' }));
  assert.equal(res.status, 404);
  assert.equal((await t.call('GET', '')).status, 405);
  assert.equal((await t.call('POST', '/cnv_1/events')).status, 405);
  assert.equal((await t.call('POST', '/cnv_1/unknown', { body: {} })).status, 404);
  assert.equal((await t.service.handle(new Request(`${endpoint}x`, { method: 'POST', body: '{}' }))).status, 404);
  const anon = await t.service.handle(new Request(endpoint, { method: 'POST', body: JSON.stringify({ message: hello }) }));
  assert.equal(anon.status, 401);
  assert.doesNotMatch(await anon.text(), /tok_abc/);
});

test('only AuthorityError becomes an auth response; other errors are re-thrown', async () => {
  const t = setup();
  // Look-alike coded errors are not trusted to choose a status or headers.
  t.policy.deny = Object.assign(new Error('limited'), { code: 'rate_limited', status: 429, headers: new Headers({ 'Retry-After': '5' }) });
  await assert.rejects(t.start(hello), { message: 'limited' });
  t.policy.deny = new Error('boom');
  await assert.rejects(t.start(hello), { message: 'boom' });
  t.policy.deny = new AuthorityError('insufficient_scope', { scope: 'orders:read' });
  const denied = await t.start(hello);
  assert.deepEqual([denied.status, denied.body], [403, { error: 'insufficient_scope' }]);
  assert.equal(denied.headers.get('www-authenticate'), 'DPoP error="insufficient_scope", scope="orders:read", algs="ES256"');
  assert.equal((await t.store.read()).work.length, 0);
});

test('construction rejects invalid options', () => {
  const store = memoryStore(initialConversationState());
  const base={historyScopes:['orders:read'],endpoint,store,authenticator:{async authenticate(){return principals.alice;}},policy:setup().policy,clock:{now:()=>0}};
  for (const historyScopes of [undefined, [], ['poppy:read'], ['bad scope']]) assert.throws(() => createConversationService({ ...base, historyScopes: historyScopes as string[] }));
  assert.throws(() => createConversationService({ ...base, supportedScopes: ['poppy:read'] }));
  assert.throws(() => createConversationService({ ...base, directScopes: ['poppy:write'] }));
  assert.throws(() => createConversationService({ ...base, pageSize: 0 }), TypeError);
  assert.throws(() => createConversationService({ ...base, leaseMs: -1 }), TypeError);
  assert.throws(() => createConversationService({ ...base, finishedWorkLimit: 0 }), TypeError);
  assert.throws(() => createConversationService({ ...base, endpoint: 'http://api.example.test/poppy' }));
});

test('deterministic handler: claim, reply, finish; reply visible on read and conversation idle', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const claim = await t.service.claim();
  assert.equal(expectValue(claim).conversationId, body.conversation_id);
  assert.deepEqual(expectValue(claim).message, hello);
  assert.ok(expectValue(claim).workId && expectValue(claim).fence);
  assert.equal(await t.service.claim(), null, 'claimed work is not handed out twice');
  await t.service.reply(expectValue(claim), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: `Order 1042 shipped.` });
  await t.service.reply(expectValue(claim), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: `Order 1042 shipped.` });
  await t.service.finish(expectValue(claim), 'completed');
  assert.deepEqual(t.calls.filter(call => call.kind === 'accepted').map(call => call.userId), ['u_alice', 'u_alice', 'u_alice']);
  const page = (await t.read(body.conversation_id)).body;
  assert.equal(page.status, 'idle');
  assert.deepEqual(page.events.map((event:ConversationEvent) => event.type), ['message', 'state', 'message', 'state']);
  assert.deepEqual(page.events[2].message, { id: 'msg_r1', author: { type: 'agent' }, text: 'Order 1042 shipped.', role: 'company' });
  assert.deepEqual([page.events[3].status, page.events[3].responder], ['idle', 'agent']);
});

test('output ID reuse with different content is rejected', async () => {
  const t = setup();
  await t.start(hello);
  const claim = await t.service.claim();
  await t.service.reply(expectValue(claim), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: 'one' });
  await assert.rejects(t.service.reply(expectValue(claim), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: 'two' }), { code: 'output_conflict' });
  await assert.rejects(t.service.reply(expectValue(claim), 'out_2', { id: 'msg_r2', author: { type: 'agent' }, context: { a: 1 } }), { name: 'ValidationError' });
});

test('stale fence after lease reclaim cannot publish or finish', async () => {
  const t = setup({ leaseMs: 1000 });
  const { body } = await t.start(hello);
  const old = await t.service.claim();
  t.clock.advance(1000);
  await assert.rejects(t.service.reply(expectValue(old), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: 'late' }), PublicationError);
  const fresh = await t.service.claim();
  assert.equal(expectValue(fresh).workId, expectValue(old).workId);
  assert.notEqual(expectValue(fresh).fence, expectValue(old).fence);
  await assert.rejects(t.service.reply(expectValue(old), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: 'stale' }), { code: 'stale_work' });
  await assert.rejects(t.service.finish(expectValue(old), 'completed'), { code: 'stale_work' });
  await assert.rejects(t.service.reply({ workId: 'wrk_unknown', fence: expectValue(fresh).fence }, 'o', { id: 'm', author: { type: 'agent' }, text: 'x' }), { code: 'stale_work' });
  t.clock.advance(500);
  await t.service.renew(expectValue(fresh));
  t.clock.advance(800);
  await t.service.reply(expectValue(fresh), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: 'fresh' });
  await t.service.finish(expectValue(fresh), 'completed');
  await assert.rejects(t.service.finish(expectValue(fresh), 'completed'), { code: 'stale_work' }, 'finished work rejects further publication');
  const events = (await t.read(body.conversation_id)).body.events;
  assert.deepEqual(events.filter((event: { type: string; }) => event.type === 'message').map((event:ConversationEvent) => messageValue(event.message).text), [hello.text, 'fresh']);
});

test('withAccepted denial blocks publication and leaves state unchanged', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const claim = await t.service.claim();
  t.policy.deny = new AuthorityError('invalid_token');
  await assert.rejects(t.service.reply(expectValue(claim), 'out_1', { id: 'msg_r1', author: { type: 'agent' }, text: 'x' }), AuthorityError);
  t.policy.deny = null;
  assert.equal((await t.store.read()).conversations[body.conversation_id].events.length, 2);
});

test('work is serial per conversation and finish keeps working while more is pending', async () => {
  const t = setup();
  const a = (await t.start(hello)).body.conversation_id;
  await t.send(a, { id: 'msg_2', author: { type: 'agent' }, text: 'also' });
  const b = (await t.start({ id: 'msg_b', author: { type: 'agent' }, text: 'b' })).body.conversation_id;
  const first = await t.service.claim();
  const second = await t.service.claim();
  assert.deepEqual([expectValue(first).conversationId, expectValue(second).conversationId], [a, b]);
  assert.equal(await t.service.claim(), null);
  await t.service.finish(expectValue(first), 'completed');
  assert.equal((await t.read(a)).body.status, 'working');
  const third = await t.service.claim();
  assert.equal(expectValue(third).message.id, 'msg_2');
  await t.service.finish(expectValue(third), 'failed');
  const page = (await t.read(a)).body;
  assert.equal(page.status, 'idle');
  assert.equal(page.events.at(-2).message.role, 'company');
  await t.service.finish(expectValue(second), 'suspended');
  assert.equal(await t.service.claim(), null, 'suspended work is not resumed automatically');
});

test('an idle claim only reads; a claim that loses the race after its read returns null', async () => {
  const t = setup();
  assert.equal(await t.service.claim(), null);
  assert.equal(t.store.transactions, 0, 'no candidate, no write transaction');
  await t.start(hello);
  const before = t.store.transactions;
  let winner!:Awaited<ReturnType<ReturnType<typeof setup>['service']['claim']>>;
  t.store.afterRead = async () => { winner = await t.service.claim(); };
  assert.equal(await t.service.claim(), null, 'the transaction rechecks the candidate');
  assert.equal(expectValue(winner).message.id, hello.id);
  assert.equal(t.store.transactions, before + 2);
  assert.equal((await t.store.read()).work[0].fence, expectValue(winner).fence, 'the loser changed nothing');
});

test('finished work is pruned oldest first beyond the limit; held and unfinished work and receipts are kept', async () => {
  const t = setup({ finishedWorkLimit: 2 });
  const ids = []; const claims = [];
  for (const n of [1, 2, 3]) {
    ids.push((await t.start({ id: `msg_${n}`, author: { type: 'agent' }, text: `q${n}` })).body.conversation_id);
    claims.push(await t.service.claim());
    await t.service.finish(expectValue(claims.at(-1)), 'completed');
  }
  await t.handoff(ids[0]);
  await t.send(ids[0], { id: 'msg_held', author: { type: 'agent' }, text: 'for the person' });
  const phases = async () => (await t.store.read()).work.map(work => [work.message.id, work.phase]);
  assert.deepEqual(await phases(), [['msg_2', 'completed'], ['msg_3', 'completed'], ['msg_held', 'held']]);
  await t.start({ id: 'msg_4', author: { type: 'agent' }, text: 'q4' });
  await t.service.finish(expectValue(await t.service.claim()), 'failed');
  await t.start({ id: 'msg_5', author: { type: 'agent' }, text: 'q5' });
  assert.deepEqual(await phases(), [['msg_3', 'completed'], ['msg_held', 'held'], ['msg_4', 'failed'], ['msg_5', 'pending']]);
  assert.equal(Object.keys((await t.store.read()).messages).length, 6, 'message receipts are kept as long as the conversation (spec 7.3)');
  await assert.rejects(t.service.finish(expectValue(claims[1]), 'completed'), { code: 'stale_work' }, 'a pruned fence is stale, as it was once finished');
  assert.equal((await t.start({ id: 'msg_1', author: { type: 'agent' }, text: 'q1' })).body.conversation_id, ids[0], 'dedupe outlives the pruned work');
});

const childMessage = { id: 'msg_child', author: { type: 'human' }, text: 'Hi, I have a question.' };
const openChild = async (t:ReturnType<typeof setup>,parent:string,as:string) => (await t.direct(parent, childMessage, { as })).body.conversation_id;
const bindingOf = async (t:ReturnType<typeof setup>,id:string) => { const state = await t.store.read(); return state.bindings[state.conversations[id].bindingId]; };

test('requireAccount binds the shared parent/child ownership once and checks the accepted scopes', async () => {
  const t = setup();
  const parent = (await t.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
  const child = await openChild(t, parent, 'aliceSignedIn');
  const claim = await t.service.claim();
  assert.equal(expectValue(claim).conversationId, child, 'the parent is suspended while its Direct Conversation is open');
  t.calls.length = 0;
  assert.deepEqual(await t.service.requireAccount(expectValue(claim), ['orders:read']), { accountId: 'acct_1' });
  assert.deepEqual(t.calls, [{ kind: 'accepted', userId: 'u_alice', scopes: ['orders:read'] }]);
  assert.deepEqual(await bindingOf(t, parent), { accountId: 'acct_1' });
  // Idempotent for the same account; the parent is bound by the child's account use.
  assert.deepEqual(await t.service.requireAccount(expectValue(claim), []), { accountId: 'acct_1' });
  for (const id of [parent, child]) {
    assert.equal((await t.read(id, { as: 'carolSameAccount' })).status, 200);
    assert.equal((await t.read(id)).status, 403);
    assert.equal((await t.read(id, { as: 'aliceOtherAccount' })).status, 403);
    assert.equal((await t.read(id, { as: 'bobOtherAccount' })).status, 404);
  }
});

test('requireAccount refuses signed-out work, missing scopes and stale fences without binding', async () => {
  const t = setup();
  const signedOut = (await t.start(hello)).body.conversation_id;
  const noScopes = (await t.start({ ...hello, id: 'msg_n' }, { as: 'aliceNoScopes' })).body.conversation_id;
  const first = await t.service.claim();
  const second = await t.service.claim();
  await assert.rejects(t.service.requireAccount(expectValue(first), []), { code: 'insufficient_scope' });
  await assert.rejects(t.service.requireAccount(expectValue(second), ['orders:read']), { code: 'insufficient_scope' });
  await assert.rejects(t.service.requireAccount(expectValue({ ...expectValue(second), fence: 'stale' }), []), { code: 'stale_work' });
  for (const id of [signedOut, noScopes]) assert.deepEqual(await bindingOf(t, id), {});
});

// Alice's parent work (account 1) races Alice opening a Direct Conversation on account 2 and that child's first account use.
test('race: Direct Conversation creation, first account use and reads have exactly one winner', async () => {
  type Order=(bind:()=>Promise<string>,child:()=>Promise<string>,t:ReturnType<typeof setup>,parent:string)=>Promise<string[]>;
  const orders:Record<string,Order> = {
    'bind, then child': async (bind, child) => [await bind(), await child()],
    'child, then bind': async (bind, child) => [await child(), await bind()],
    'child commits inside the bind gap': async (bind, child, t) => { let opened!:Promise<string>; t.store.afterRead = () => { opened = child(); return opened; }; const bound = await bind(); return [bound, await opened]; },
    'bind commits inside the child gap': async (bind, child, t) => { let bound!:Promise<string>; t.store.afterRead = () => { bound = bind(); return bound; }; const opened = await child(); return [opened, await bound]; },
    concurrent: async (bind, child, t, parent) => {
      const [bound,opened,...reads]=await Promise.all([bind(),child(),t.read(parent,{as:'aliceSignedIn'}),t.read(parent,{as:'aliceOtherAccount'})]);
      for(const read of reads)assert.ok([200,403].includes(read.status));return [bound,opened];
    },
  };
  for (const [name, run] of Object.entries(orders)) {
    const t = setup();
    const parent = (await t.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
    const parentClaim = await t.service.claim();
    const outcome=(promise:Promise<{accountId:string}>)=>promise.then(value=>value.accountId,(error:unknown)=>{assert.ok(error&&typeof error==='object'&&'code' in error&&typeof error.code==='string');return error.code;});
    const bind = () => outcome(t.service.requireAccount(expectValue(parentClaim), ['orders:read']));
    const child = async () => {
      const res = await t.direct(parent, childMessage, { as: 'aliceOtherAccount' });
      if (res.status !== 201) return res.body.error;
      return outcome(t.service.claim().then(claim => t.service.requireAccount(expectValue(claim), ['orders:read'])));
    };
    const results = await run(bind, child, t, parent);
    const winners = results.filter(result => result.startsWith('acct_'));
    assert.equal(winners.length, 1, `${name}: ${results}`);
    for (const loser of results.filter(result => !result.startsWith('acct_'))) assert.ok(['insufficient_scope', 'stale_work'].includes(loser), `${name}: ${loser}`);
    const state = await t.store.read();
    const ids = Object.keys(state.conversations);
    assert.ok(ids.every(id => state.conversations[id].bindingId === parent), `${name}: one shared binding`);
    assert.deepEqual(state.bindings[parent], { accountId: winners[0] });
    const [winner, loser] = winners[0] === 'acct_1' ? ['aliceSignedIn', 'aliceOtherAccount'] : ['aliceOtherAccount', 'aliceSignedIn'];
    for (const id of ids) {
      assert.equal((await t.read(id, { as: winner })).status, 200, name);
      assert.deepEqual((await t.read(id, { as: loser })).body, { error: 'insufficient_scope' }, name);
    }
  }
});

test('account use committed between a read and its transaction: the read sees the binding', async () => {
  const t = setup();
  const parent = (await t.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
  const child = await openChild(t, parent, 'aliceSignedIn');
  const childClaim = await t.service.claim();
  // The signed-out read snapshots an unbound child, then the child's worker binds before the read commits.
  t.store.afterRead = () => t.service.requireAccount(expectValue(childClaim), []);
  assert.deepEqual((await t.read(child)).body, { error: 'insufficient_scope' });
  // A different account's message racing the binding is refused and leaves no trace.
  t.store.afterRead = null;
  const before = (await t.store.read()).conversations[parent].events.length;
  assert.equal((await t.send(parent, { id: 'msg_o', author: { type: 'agent' }, text: 'x' }, { as: 'aliceOtherAccount' })).status, 403);
  assert.equal((await t.store.read()).conversations[parent].events.length, before);
  // A worker's history read racing a first account use is rescoped to orders:read.
  const t2 = setup();
  const id = (await t2.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
  const claim = await t2.service.claim();
  t2.store.afterRead = state => { state.bindings[id].accountId = 'acct_1'; };
  t2.calls.length = 0;
  assert.equal((await t2.service.history(expectValue(claim))).length, 2);
  assert.deepEqual(t2.calls.map(call => call.scopes), [[], ['orders:read']]);
});

test('history: unbound needs no scope; bound needs the bound account and orders:read', async () => {
  const t = setup();
  const out = (await t.start(hello)).body.conversation_id;
  const noScopes = (await t.start({ ...hello, id: 'msg_n' }, { as: 'aliceNoScopes' })).body.conversation_id;
  const [outClaim, noScopesClaim] = [await t.service.claim(), await t.service.claim()];
  assert.deepEqual((await t.service.history(expectValue(outClaim))).map((event:ConversationEvent) => event.type), ['message', 'state']);
  t.store.set(state => { state.bindings[out].accountId = 'acct_1'; state.bindings[noScopes].accountId = 'acct_1'; });
  // Signed-out work holds no read scope; signed-in work without orders:read is over its ceiling.
  await assert.rejects(t.service.history(expectValue(outClaim)), { code: 'insufficient_scope' });
  await assert.rejects(t.service.history(expectValue(noScopesClaim)), { code: 'insufficient_scope' });
  const other = (await t.start({ ...hello, id: 'msg_x' }, { as: 'aliceOtherAccount' })).body.conversation_id;
  const otherClaim = await t.service.claim();
  assert.equal(expectValue(otherClaim).conversationId, other);
  t.store.set(state => { state.bindings[other].accountId = 'acct_1'; });
  await assert.rejects(t.service.history(expectValue(otherClaim)), { code: 'insufficient_scope' });
});

test('history scopes enforce the explicit Company policy (spec 4.4)', async () => {
  for (const [options, allowed, denied] of ([[{historyScopes:['orders:read']},'aliceSignedIn','aliceCustomScope'],[{historyScopes:['shop:history']},'aliceCustomScope','aliceSignedIn']] satisfies [Partial<ConversationOptions>,string,string][])) {
    const t = setup(expectValue(options));
    const id = (await t.start(hello)).body.conversation_id;
    t.store.set(state => { state.bindings[id].accountId = 'acct_1'; });
    assert.equal((await t.read(id, { as: allowed })).status, 200);
    const refused = await t.read(id, { as: denied });
    assert.deepEqual([refused.status, refused.body.error], [403, 'insufficient_scope']);
  }
});

test('a path conversation ID that fails the pattern is 400 invalid_request, unknown paths stay 404 (spec 7.13)', async () => {
  const t = setup();
  for (const [method, path] of [['GET', '/bad.id/events'], ['POST', '/bad%20id/messages'], ['POST', `/${'a'.repeat(257)}/close`], ['POST', '/a$b/handoff']]) {
    assert.deepEqual(await t.call(method, path, method === 'GET' ? {} : { body: {} }).then(r => [r.status, r.body]), [400, { error: 'invalid_request' }], path);
  }
  for (const path of ['/bad.id', '/cnv_1/other', '/cnv_1/events/x']) assert.deepEqual(await t.call('GET', path).then(r => [r.status, r.body]), [404, { error: 'not_found' }], path);
});
