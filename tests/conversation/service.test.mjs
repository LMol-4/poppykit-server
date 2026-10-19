import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthorityError, createConversationService, initialConversationState, PublicationError } from '../../dist/index.js';
import { memoryStore } from './support.mjs';

const endpoint = 'https://api.example.test/poppy/conversations';
const base = { issuer: 'https://auth.example.test', clientId: 'https://agent.example.test/client', sessionId: 's1', scopes: [], tokenExpiresAt: 9e12, sessionVersion: 1 };
const principals = {
  alice: { ...base, userId: 'u_alice' },
  aliceSignedIn: { ...base, userId: 'u_alice', accountId: 'acct_1', scopes: ['poppy:read'] },
  aliceNoScopes: { ...base, userId: 'u_alice', accountId: 'acct_1', scopes: [] },
  aliceOtherAccount: { ...base, userId: 'u_alice', accountId: 'acct_2', scopes: ['poppy:read'] },
  bob: { ...base, userId: 'u_bob' },
  bobOtherAccount: { ...base, userId: 'u_bob', accountId: 'acct_2', scopes: ['poppy:read'] },
  carolSameAccount: { ...base, userId: 'u_carol', accountId: 'acct_1', scopes: ['poppy:read'] },
  otherClientSameAccount: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice', accountId: 'acct_1', scopes: ['poppy:read'] },
  otherClientNoScopes: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice', accountId: 'acct_1', scopes: [] },
  otherClient: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice' },
};

function setup(options = {}) {
  let now = Date.UTC(2026, 9, 19, 12);
  const clock = { now: () => now, advance(ms) { now += ms; } };
  const store = memoryStore(initialConversationState());
  const calls = [];
  const authenticator = {
    async authenticate(request) {
      const token = /^DPoP (\w+)$/.exec(request.headers.get('authorization') ?? '')?.[1];
      if (!token || !principals[token]) throw new AuthorityError('invalid_token');
      return principals[token];
    },
  };
  const policy = {
    deny: null,
    async withCurrent(principal, scopes, action) {
      calls.push({ kind: 'current', userId: principal.userId, scopes: [...scopes] });
      if (policy.deny) throw policy.deny;
      if (!scopes.every(scope => principal.scopes.includes(scope))) throw new AuthorityError('insufficient_scope', { scope: scopes.join(' ') });
      return action();
    },
    async withAccepted(authority, scopes, action) {
      calls.push({ kind: 'accepted', userId: authority.principal.userId, scopes: [...scopes] });
      if (policy.deny) throw policy.deny;
      if (!scopes.every(scope => authority.principal.scopes.includes(scope))) throw new AuthorityError('insufficient_scope', { scope: scopes.join(' ') });
      return action();
    },
  };
  const service = createConversationService({ endpoint, store, authenticator, policy, clock, pageSize: options.pageSize, leaseMs: options.leaseMs });
  async function call(method, path, { as = 'alice', body, query = '' } = {}) {
    const response = await service.handle(new Request(`${endpoint}${path}${query}`, {
      method, headers: { authorization: `DPoP ${as}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    }));
    return { status: response.status, headers: response.headers, body: await response.json() };
  }
  const start = (message, opts) => call('POST', '', { ...opts, body: { message } });
  const send = (id, message, opts) => call('POST', `/${id}/messages`, { ...opts, body: { message } });
  const read = (id, opts) => call('GET', `/${id}/events`, opts);
  return { service, store, clock, calls, policy, call, start, send, read };
}

const hello = { id: 'msg_1', sender: 'agent', text: 'Where is order 1042?', data: { b: 1, a: [1, 2] }, x_extension: { keep: true } };

test('start returns 201 three-field ack, records events and pending work', async () => {
  const t = setup();
  const res = await t.start(hello);
  assert.equal(res.status, 201);
  assert.deepEqual(Object.keys(res.body).sort(), ['conversation_id', 'responder', 'status']);
  assert.equal(res.body.status, 'working');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const state = await t.store.read();
  const conversation = state.conversations[res.body.conversation_id];
  assert.deepEqual(conversation.events.map(event => event.type), ['message', 'state']);
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
  const retry = await t.start({ x_extension: { keep: true }, data: { a: [1, 2], b: 1 }, text: hello.text, sender: 'agent', id: 'msg_1', role: 'company' });
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
  const other = await t.start({ id: 'msg_2', sender: 'agent', text: 'second conversation' });
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
    assert.equal((await t.send(body.conversation_id, { id: 'msg_x', sender: 'agent', text: 'hi' }, { as })).status, 404);
  }
  assert.equal((await t.read('cnv_unknown')).status, 404);
  assert.equal((await t.read('__proto__')).status, 404);
  assert.equal((await t.read('constructor')).status, 404);
});

test('account-bound conversation: same account reads with poppy:read; same User signed out or on another account gets sign_in_required; others 404', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  t.store.set(state => { state.bindings[body.conversation_id].accountId = 'acct_1'; });
  const ok = await t.read(body.conversation_id, { as: 'aliceSignedIn' });
  assert.equal(ok.status, 200);
  assert.deepEqual(t.calls.at(-1), { kind: 'current', userId: 'u_alice', scopes: ['poppy:read'] });
  const signedOut = await t.read(body.conversation_id);
  assert.equal(signedOut.status, 403);
  assert.deepEqual(signedOut.body, { error: 'sign_in_required' });
  // Spec 7.11 and 4.2: the same User on account B is not signed in to account A.
  const otherAccount = await t.read(body.conversation_id, { as: 'aliceOtherAccount' });
  assert.deepEqual([otherAccount.status, otherAccount.body], [403, { error: 'sign_in_required' }]);
  // A different User on account B is a stranger: 404, also for an unknown ID.
  for (const id of [body.conversation_id, 'cnv_unknown']) {
    assert.deepEqual(await t.read(id, { as: 'bobOtherAccount' }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
  }
  // A different client on account A without poppy:read: 404, as for an unknown ID.
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
  const next = n => ({ id: `msg_${n}`, sender: 'agent', text: 'more' });
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
  // Without poppy:read, another client on the same account still sees 404 for a real ID, as for an unknown one.
  assert.deepEqual(await t.read(id, { as: 'otherClientNoScopes' }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
  assert.deepEqual(await t.read('cnv_unknown', { as: 'otherClientNoScopes' }).then(r => [r.status, r.body]), [404, { error: 'conversation_not_found' }]);
  const signedOut = await t.read(id);
  assert.deepEqual([signedOut.status, signedOut.body], [403, { error: 'sign_in_required' }]);
  assert.equal(signedOut.headers.get('www-authenticate'), 'DPoP error="sign_in_required", algs="ES256"');
  assert.equal((await t.send(id, next('a2'))).status, 403);
});

test('multi-page idle history uses real cursors and six-field pages', async () => {
  const t = setup({ pageSize: 2 });
  const { body } = await t.start(hello);
  const id = body.conversation_id;
  for (const n of [2, 3]) assert.equal((await t.send(id, { id: `msg_${n}`, sender: 'agent', context: { user_available: n === 2 } })).status, 202);
  // Finish the work so the conversation is idle with history remaining.
  const claim = await t.service.claim();
  await t.service.finish(claim, 'completed');
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
  assert.deepEqual(seen.map(event => event.type), ['message', 'state', 'message', 'message', 'state']);
  assert.equal(new Set(seen.map(event => event.id)).size, 5);
  const empty = await t.read(id, { query: `?cursor=${cursor}` });
  assert.deepEqual([empty.body.events, empty.body.cursor, empty.body.has_more], [[], cursor, false]);
  assert.deepEqual((await t.store.read()).conversations[id].context, { user_available: false });
});

test('context-only message is recorded without creating work', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  await t.service.finish(await t.service.claim(), 'completed');
  const res = await t.send(body.conversation_id, { id: 'msg_ctx', sender: 'agent', context: { locale: 'en-US' } });
  assert.deepEqual([res.status, res.body.status], [202, 'idle']);
  assert.equal(await t.service.claim(), null);
});

test('invalid cursor, wait and malformed requests are rejected without acceptance', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const other = await t.start({ id: 'msg_o', sender: 'agent', text: 'other' });
  const foreignCursor = (await t.read(other.body.conversation_id)).body.cursor;
  assert.deepEqual((await t.read(body.conversation_id, { query: `?cursor=${foreignCursor}` })).body, { error: 'invalid_cursor' });
  assert.equal((await t.read(body.conversation_id, { query: '?wait=1.5' })).status, 400);
  const badCursorSend = await t.send(body.conversation_id, { id: 'msg_c', sender: 'agent', text: 'x' }, { query: '?wait=0&cursor=evt_nope' });
  assert.deepEqual([badCursorSend.status, badCursorSend.body], [400, { error: 'invalid_cursor' }]);
  assert.equal((await t.start({ id: 'msg_s', sender: 'agent', text: 'x' }, { query: '?cursor=evt_nope' })).status, 400);
  const before = (await t.store.read()).work.length;
  for (const bad of [{ id: 'msg bad', sender: 'agent', text: 'x' }, { id: 'msg_e', sender: 'agent' }, { id: 'msg_r', sender: 'robot', text: 'x' }]) {
    assert.deepEqual((await t.start(bad)).body, { error: 'invalid_request' });
  }
  assert.equal((await t.call('POST', '', { body: '{not json' })).status, 400);
  assert.equal((await t.call('POST', '', { body: JSON.stringify({ message: { id: 'msg_big', sender: 'agent', text: 'x'.repeat(1048577) } }) })).status, 400);
  assert.equal((await t.call('POST', '', { body: { parent_conversation_id: body.conversation_id, message: { id: 'msg_d', sender: 'human', text: 'x' } } })).status, 400);
  assert.equal((await t.store.read()).work.length, before);
  // The rejected IDs were never recorded, so they can still be used.
  assert.equal((await t.send(body.conversation_id, { id: 'msg_c', sender: 'agent', text: 'x' })).status, 202);
});

test('closed conversation rejects new messages but retries return the original receipt', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const first = await t.send(body.conversation_id, { id: 'msg_2', sender: 'agent', text: 'more' });
  t.store.set(state => { state.conversations[body.conversation_id].status = 'closed'; });
  assert.deepEqual((await t.send(body.conversation_id, { id: 'msg_3', sender: 'agent', text: 'x' })).body, { error: 'conversation_closed' });
  const retry = await t.send(body.conversation_id, { id: 'msg_2', sender: 'agent', text: 'more' });
  assert.deepEqual([retry.status, retry.body], [first.status, first.body]);
});

test('POST with wait returns a page receipt that a retry repeats unchanged', async () => {
  const t = setup();
  const res = await t.start(hello, { query: '?wait=0' });
  assert.equal(res.status, 201);
  assert.deepEqual(res.body.events.map(event => event.type), ['message', 'state']);
  assert.equal(res.body.has_more, false);
  const claim = await t.service.claim();
  await t.service.reply(claim, 'out_1', { id: 'msg_r1', sender: 'agent', text: 'Shipped yesterday.' });
  const retry = await t.start(hello, { query: '?wait=5' });
  assert.deepEqual([retry.status, retry.body], [res.status, res.body]);
});

test('retry without wait of a waited POST still needs poppy:read on an account-bound conversation', async () => {
  const t = setup();
  const waited = await t.start(hello, { query: '?wait=0' });
  const plain = await t.send(waited.body.conversation_id, { id: 'msg_2', sender: 'agent', text: 'more' });
  t.store.set(state => { state.bindings[waited.body.conversation_id].accountId = 'acct_1'; });
  const denied = await t.start(hello, { as: 'aliceNoScopes' });
  assert.deepEqual([denied.status, denied.body], [403, { error: 'insufficient_scope' }]);
  const allowed = await t.start(hello, { as: 'aliceSignedIn' });
  assert.deepEqual([allowed.status, allowed.body], [201, waited.body]);
  // A three-field receipt holds no history, so no read scope is needed.
  const ack = await t.send(waited.body.conversation_id, { id: 'msg_2', sender: 'agent', text: 'more' }, { as: 'aliceNoScopes' });
  assert.deepEqual([ack.status, ack.body], [plain.status, plain.body]);
});

test('binding that gains an account between read and transaction rescopes a retry to poppy:read', async () => {
  const t = setup();
  const waited = await t.start(hello, { query: '?wait=0', as: 'aliceNoScopes' });
  assert.equal(waited.status, 201);
  t.store.afterRead = state => { state.bindings[waited.body.conversation_id].accountId = 'acct_1'; };
  t.calls.length = 0;
  const retry = await t.start(hello, { as: 'aliceNoScopes' });
  assert.deepEqual([retry.status, retry.body], [403, { error: 'insufficient_scope' }]);
  assert.deepEqual(t.calls.map(call => call.scopes), [[], ['poppy:read']]);
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
  t.policy.deny = new AuthorityError('insufficient_scope', { scope: 'poppy:read' });
  const denied = await t.start(hello);
  assert.deepEqual([denied.status, denied.body], [403, { error: 'insufficient_scope' }]);
  assert.equal(denied.headers.get('www-authenticate'), 'DPoP error="insufficient_scope", scope="poppy:read", algs="ES256"');
  assert.equal((await t.store.read()).work.length, 0);
});

test('construction rejects invalid options', () => {
  const store = memoryStore(initialConversationState());
  const base = { endpoint, store, authenticator: {}, policy: {}, clock: { now: () => 0 } };
  assert.throws(() => createConversationService({ ...base, pageSize: 0 }), TypeError);
  assert.throws(() => createConversationService({ ...base, leaseMs: -1 }), TypeError);
  assert.throws(() => createConversationService({ ...base, endpoint: 'http://api.example.test/poppy' }));
});

test('deterministic handler: claim, reply, finish; reply visible on read and conversation idle', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const claim = await t.service.claim();
  assert.equal(claim.conversationId, body.conversation_id);
  assert.deepEqual(claim.message, hello);
  assert.ok(claim.workId && claim.fence);
  assert.equal(await t.service.claim(), null, 'claimed work is not handed out twice');
  await t.service.reply(claim, 'out_1', { id: 'msg_r1', sender: 'agent', text: `Order 1042 shipped.` });
  await t.service.reply(claim, 'out_1', { id: 'msg_r1', sender: 'agent', text: `Order 1042 shipped.` });
  await t.service.finish(claim, 'completed');
  assert.deepEqual(t.calls.filter(call => call.kind === 'accepted').map(call => call.userId), ['u_alice', 'u_alice', 'u_alice']);
  const page = (await t.read(body.conversation_id)).body;
  assert.equal(page.status, 'idle');
  assert.deepEqual(page.events.map(event => event.type), ['message', 'state', 'message', 'state']);
  assert.deepEqual(page.events[2].message, { id: 'msg_r1', sender: 'agent', text: 'Order 1042 shipped.', role: 'company' });
  assert.deepEqual([page.events[3].status, page.events[3].responder], ['idle', 'agent']);
});

test('output ID reuse with different content is rejected', async () => {
  const t = setup();
  await t.start(hello);
  const claim = await t.service.claim();
  await t.service.reply(claim, 'out_1', { id: 'msg_r1', sender: 'agent', text: 'one' });
  await assert.rejects(t.service.reply(claim, 'out_1', { id: 'msg_r1', sender: 'agent', text: 'two' }), { code: 'output_conflict' });
  await assert.rejects(t.service.reply(claim, 'out_2', { id: 'msg_r2', sender: 'agent', context: { a: 1 } }), { name: 'ValidationError' });
});

test('stale fence after lease reclaim cannot publish or finish', async () => {
  const t = setup({ leaseMs: 1000 });
  const { body } = await t.start(hello);
  const old = await t.service.claim();
  t.clock.advance(1000);
  await assert.rejects(t.service.reply(old, 'out_1', { id: 'msg_r1', sender: 'agent', text: 'late' }), PublicationError);
  const fresh = await t.service.claim();
  assert.equal(fresh.workId, old.workId);
  assert.notEqual(fresh.fence, old.fence);
  await assert.rejects(t.service.reply(old, 'out_1', { id: 'msg_r1', sender: 'agent', text: 'stale' }), { code: 'stale_work' });
  await assert.rejects(t.service.finish(old, 'completed'), { code: 'stale_work' });
  await assert.rejects(t.service.reply({ workId: 'wrk_unknown', fence: fresh.fence }, 'o', { id: 'm', sender: 'agent', text: 'x' }), { code: 'stale_work' });
  t.clock.advance(500);
  await t.service.renew(fresh);
  t.clock.advance(800);
  await t.service.reply(fresh, 'out_1', { id: 'msg_r1', sender: 'agent', text: 'fresh' });
  await t.service.finish(fresh, 'completed');
  await assert.rejects(t.service.finish(fresh, 'completed'), { code: 'stale_work' }, 'finished work rejects further publication');
  const events = (await t.read(body.conversation_id)).body.events;
  assert.deepEqual(events.filter(event => event.type === 'message').map(event => event.message.text), [hello.text, 'fresh']);
});

test('withAccepted denial blocks publication and leaves state unchanged', async () => {
  const t = setup();
  const { body } = await t.start(hello);
  const claim = await t.service.claim();
  t.policy.deny = new AuthorityError('invalid_token');
  await assert.rejects(t.service.reply(claim, 'out_1', { id: 'msg_r1', sender: 'agent', text: 'x' }), AuthorityError);
  t.policy.deny = null;
  assert.equal((await t.store.read()).conversations[body.conversation_id].events.length, 2);
});

test('work is serial per conversation and finish keeps working while more is pending', async () => {
  const t = setup();
  const a = (await t.start(hello)).body.conversation_id;
  await t.send(a, { id: 'msg_2', sender: 'agent', text: 'also' });
  const b = (await t.start({ id: 'msg_b', sender: 'agent', text: 'b' })).body.conversation_id;
  const first = await t.service.claim();
  const second = await t.service.claim();
  assert.deepEqual([first.conversationId, second.conversationId], [a, b]);
  assert.equal(await t.service.claim(), null);
  await t.service.finish(first, 'completed');
  assert.equal((await t.read(a)).body.status, 'working');
  const third = await t.service.claim();
  assert.equal(third.message.id, 'msg_2');
  await t.service.finish(third, 'failed');
  const page = (await t.read(a)).body;
  assert.equal(page.status, 'idle');
  assert.equal(page.events.at(-2).message.role, 'company');
  await t.service.finish(second, 'suspended');
  assert.equal(await t.service.claim(), null, 'suspended work is not resumed automatically');
});

// J15 creates Direct Conversations; until then a child sharing the parent's binding is seeded as J15 will store it.
function seedChild(t, parentId, principal) {
  const id = `cnv_child_${principal.accountId ?? 'out'}`;
  t.store.set(state => {
    const parent = state.conversations[parentId];
    state.conversations[id] = { ...structuredClone(parent), id, events: [] };
    state.work.push({ id: `wrk_${id}`, conversationId: id, message: { id: `msg_${id}`, sender: 'human', text: 'hi' }, authority: { principal, acceptedAt: 0, revocationPolicy: 'stop-account-work' }, phase: 'pending', outputs: {} });
  });
  return id;
}
const bindingOf = async (t, id) => { const state = await t.store.read(); return state.bindings[state.conversations[id].bindingId]; };

test('requireAccount binds the shared parent/child ownership once and checks the accepted scopes', async () => {
  const t = setup();
  const parent = (await t.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
  const child = seedChild(t, parent, principals.aliceSignedIn);
  const claim = await t.service.claim();
  t.calls.length = 0;
  assert.deepEqual(await t.service.requireAccount(claim, ['poppy:read']), { accountId: 'acct_1' });
  assert.deepEqual(t.calls, [{ kind: 'accepted', userId: 'u_alice', scopes: ['poppy:read'] }]);
  assert.deepEqual(await bindingOf(t, child), { accountId: 'acct_1' });
  // Idempotent for the same account; the child sees the binding without its own account use.
  assert.deepEqual(await t.service.requireAccount(claim, []), { accountId: 'acct_1' });
  assert.equal((await t.read(child, { as: 'carolSameAccount' })).status, 200);
  assert.equal((await t.read(child)).status, 403);
  assert.equal((await t.read(child, { as: 'aliceOtherAccount' })).status, 403);
  assert.equal((await t.read(child, { as: 'bobOtherAccount' })).status, 404);
});

test('requireAccount refuses signed-out work, missing scopes and stale fences without binding', async () => {
  const t = setup();
  const signedOut = (await t.start(hello)).body.conversation_id;
  const noScopes = (await t.start({ ...hello, id: 'msg_n' }, { as: 'aliceNoScopes' })).body.conversation_id;
  const first = await t.service.claim();
  const second = await t.service.claim();
  await assert.rejects(t.service.requireAccount(first, []), { code: 'sign_in_required' });
  await assert.rejects(t.service.requireAccount(second, ['poppy:read']), { code: 'insufficient_scope' });
  await assert.rejects(t.service.requireAccount({ ...second, fence: 'stale' }, []), { code: 'stale_work' });
  for (const id of [signedOut, noScopes]) assert.deepEqual(await bindingOf(t, id), {});
});

test('racing account uses on parent and child: exactly one account wins', async () => {
  for (const order of [0, 1]) {
    const t = setup();
    const parent = (await t.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
    seedChild(t, parent, principals.aliceOtherAccount);
    const claims = [await t.service.claim(), await t.service.claim()];
    if (order) claims.reverse();
    const results = await Promise.allSettled(claims.map(claim => t.service.requireAccount(claim, ['poppy:read'])));
    const won = results.filter(result => result.status === 'fulfilled');
    assert.equal(won.length, 1);
    assert.equal(results.find(result => result.status === 'rejected').reason.code, 'sign_in_required');
    assert.deepEqual(await bindingOf(t, parent), { accountId: won[0].value.accountId });
  }
});

test('account use committed between a read and its transaction: the read sees the binding', async () => {
  const t = setup();
  const parent = (await t.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
  const child = seedChild(t, parent, principals.aliceSignedIn);
  const parentClaim = await t.service.claim();
  // The signed-out read snapshots an unbound child, then the parent's worker binds before the read commits.
  t.store.afterRead = () => t.service.requireAccount(parentClaim, []);
  assert.deepEqual((await t.read(child)).body, { error: 'sign_in_required' });
  // A different account's message racing the binding is refused and leaves no trace.
  t.store.afterRead = null;
  const before = (await t.store.read()).conversations[parent].events.length;
  assert.equal((await t.send(parent, { id: 'msg_o', sender: 'agent', text: 'x' }, { as: 'aliceOtherAccount' })).status, 403);
  assert.equal((await t.store.read()).conversations[parent].events.length, before);
  // A worker's history read racing a first account use is rescoped to poppy:read.
  const t2 = setup();
  const id = (await t2.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
  const claim = await t2.service.claim();
  t2.store.afterRead = state => { state.bindings[id].accountId = 'acct_1'; };
  t2.calls.length = 0;
  assert.equal((await t2.service.history(claim)).length, 2);
  assert.deepEqual(t2.calls.map(call => call.scopes), [[], ['poppy:read']]);
});

test('history: unbound needs no scope; bound needs the bound account and poppy:read', async () => {
  const t = setup();
  const out = (await t.start(hello)).body.conversation_id;
  const noScopes = (await t.start({ ...hello, id: 'msg_n' }, { as: 'aliceNoScopes' })).body.conversation_id;
  const [outClaim, noScopesClaim] = [await t.service.claim(), await t.service.claim()];
  assert.deepEqual((await t.service.history(outClaim)).map(event => event.type), ['message', 'state']);
  t.store.set(state => { state.bindings[out].accountId = 'acct_1'; state.bindings[noScopes].accountId = 'acct_1'; });
  // Signed-out work holds no read scope; signed-in work without poppy:read is over its ceiling.
  await assert.rejects(t.service.history(outClaim), { code: 'insufficient_scope' });
  await assert.rejects(t.service.history(noScopesClaim), { code: 'insufficient_scope' });
  const other = (await t.start({ ...hello, id: 'msg_x' }, { as: 'aliceOtherAccount' })).body.conversation_id;
  const otherClaim = await t.service.claim();
  assert.equal(otherClaim.conversationId, other);
  t.store.set(state => { state.bindings[other].accountId = 'acct_1'; });
  await assert.rejects(t.service.history(otherClaim), { code: 'sign_in_required' });
});
