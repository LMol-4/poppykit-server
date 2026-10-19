import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthorityError, createConversationService, resetConversationState } from '../../dist/index.js';
import { endpoint, hello, principals, setup } from './support.mjs';

const human = (id, text = 'Hi, it is me.') => ({ id, sender: 'human', text });
const reply = (id, sender = 'agent') => ({ id, sender, text: 'Here to help.' });
const types = events => events.map(event => event.type);
const operator = { staff: 'op_1' };
function staffSetup(options = {}) {
  const authorized = [];
  const t = setup({ authorizeOperator: async (op, id) => { if (op !== operator) throw new Error('operator denied'); authorized.push(id); }, ...options });
  return { ...t, authorized };
}

test('Direct Conversation: opens linked, suspends the parent, and closing it resumes the parent', async () => {
  const t = setup();
  const parent = (await t.start(hello)).body.conversation_id;
  const stale = await t.service.claim();
  const opened = await t.direct(parent, human('msg_d1'));
  assert.equal(opened.status, 201);
  const child = opened.body.conversation_id;
  assert.notEqual(child, parent);
  const state = await t.store.read();
  assert.equal(state.conversations[child].bindingId, state.conversations[parent].bindingId);
  assert.deepEqual(state.conversations[parent].events.at(-1), { ...state.conversations[parent].events.at(-1), type: 'direct_opened', conversation_id: child });
  // The parent's running attempt is fenced and its work waits; only the child is claimable.
  await assert.rejects(t.service.reply(stale, 'out_1', reply('msg_r')), { code: 'stale_work' });
  const childClaim = await t.service.claim();
  assert.equal(childClaim.conversationId, child);
  assert.equal(await t.service.claim(), null);
  // Parent is readable but takes no messages or handoff; a second child is refused; children cannot nest.
  assert.equal((await t.read(parent)).status, 200);
  for (const res of [await t.send(parent, { id: 'msg_p2', sender: 'agent', text: 'x' }), await t.handoff(parent), await t.direct(parent, human('msg_d2'))]) {
    assert.deepEqual([res.status, res.body], [409, { error: 'direct_conversation_open', conversation_id: child }]);
  }
  assert.deepEqual((await t.direct(child, human('msg_d3'))).body, { error: 'conversation_not_found' });
  // Direct messages carry the User's own words.
  assert.equal((await t.send(child, { id: 'msg_a', sender: 'agent', text: 'summary' })).status, 400);
  assert.equal((await t.send(child, human('msg_d4', 'Medium, please.'))).status, 202);
  // Both workers' history is the linked history: parent events with the child's spliced in after direct_opened.
  await t.service.reply(childClaim, 'out_1', reply('msg_r1'));
  const history = await t.service.history(childClaim);
  assert.deepEqual(types(history), ['message', 'state', 'direct_opened', 'message', 'state', 'message', 'message']);
  // Closing the child: direct_closed on the parent, parent takes messages and its work runs again.
  const closed = await t.close(child);
  assert.deepEqual([closed.status, closed.body], [200, { conversation_id: child, status: 'closed', responder: 'agent' }]);
  await assert.rejects(t.service.reply(childClaim, 'out_2', reply('msg_r2')), { code: 'stale_work' });
  const page = (await t.read(parent)).body;
  assert.deepEqual(page.events.at(-1).type, 'direct_closed');
  assert.equal(page.events.at(-1).conversation_id, child);
  const resumed = await t.service.claim();
  assert.equal(resumed.conversationId, parent);
  assert.equal(resumed.workId, stale.workId);
  assert.equal((await t.send(parent, { id: 'msg_p3', sender: 'agent', text: 'back' })).status, 202);
  const parentHistory = await t.service.history(resumed);
  assert.deepEqual(types(parentHistory), ['message', 'state', 'direct_opened', 'message', 'state', 'message', 'message', 'state', 'direct_closed', 'message']);
  // A new Direct Conversation may open once the previous one closed; a retried start returns the same child.
  const again = await t.direct(parent, human('msg_d5'));
  assert.equal(again.status, 201);
  assert.deepEqual((await t.direct(parent, human('msg_d5'))).body, again.body);
});

test('Direct Conversation: parent must exist, belong to the caller and be open', async () => {
  const t = setup();
  const parent = (await t.start(hello)).body.conversation_id;
  for (const as of ['bob', 'otherClient']) assert.deepEqual((await t.direct(parent, human('msg_x'), { as })).body, { error: 'conversation_not_found' });
  assert.deepEqual((await t.direct('cnv_unknown', human('msg_x'))).body, { error: 'conversation_not_found' });
  t.store.set(state => { state.bindings[parent].accountId = 'acct_1'; });
  assert.deepEqual((await t.direct(parent, human('msg_x'))).body, { error: 'sign_in_required' });
  assert.equal((await t.direct(parent, human('msg_x'), { as: 'carolSameAccount' })).status, 201, 'bound: same account through the same client is the owner');
  const closedParent = (await t.start({ ...hello, id: 'msg_2' })).body.conversation_id;
  await t.close(closedParent);
  assert.deepEqual((await t.direct(closedParent, human('msg_y'))).body, { error: 'conversation_closed' });
  const state = await t.store.read();
  assert.equal(Object.keys(state.conversations).length, 3);
});

test('closing the parent closes its open Direct Conversation and cancels all their work atomically', async () => {
  const t = setup();
  const parent = (await t.start(hello)).body.conversation_id;
  const child = (await t.direct(parent, human('msg_d1'))).body.conversation_id;
  const childClaim = await t.service.claim();
  const res = await t.close(parent);
  assert.deepEqual([res.status, res.body.status], [200, 'closed']);
  const state = await t.store.read();
  assert.deepEqual(types(state.conversations[parent].events).slice(-2), ['direct_closed', 'state']);
  assert.equal(state.conversations[child].status, 'closed');
  assert.ok(state.work.every(work => work.phase === 'cancelled'));
  await assert.rejects(t.service.reply(childClaim, 'out_1', reply('msg_r')), { code: 'stale_work' });
  assert.equal(await t.service.claim(), null);
  assert.deepEqual((await t.send(child, human('msg_z'))).body, { error: 'conversation_closed' });
});

test('close is idempotent, keeps history readable and rejects new messages, handoff and stale output', async () => {
  const t = setup();
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  const first = await t.close(id);
  const events = (await t.read(id)).body.events.length;
  const second = await t.close(id);
  assert.deepEqual([second.status, second.body], [first.status, first.body]);
  assert.equal((await t.read(id)).body.events.length, events, 'closing again adds no event');
  assert.deepEqual((await t.send(id, { id: 'msg_2', sender: 'agent', text: 'x' })).body, { error: 'conversation_closed' });
  assert.deepEqual((await t.handoff(id)).body, { error: 'conversation_closed' });
  await assert.rejects(t.service.reply(claim, 'out_1', reply('msg_r')), { code: 'stale_work' });
  await assert.rejects(t.service.finish(claim, 'completed'), { code: 'stale_work' });
});

test('handoff and close routes check ownership like every other route', async () => {
  const t = setup();
  const id = (await t.start(hello)).body.conversation_id;
  for (const action of ['handoff', 'close']) {
    for (const as of ['bob', 'otherClient', 'nobody']) assert.ok([401, 404].includes((await t[action](id, { as })).status));
    assert.deepEqual((await t[action]('cnv_unknown')).body, { error: 'conversation_not_found' });
    assert.equal((await t.call('POST', `/${id}/${action}`, { body: '[]' })).status, 400, 'body must be a JSON object');
    assert.equal((await t.call('GET', `/${id}/${action}`)).status, 405);
  }
  t.store.set(state => { state.bindings[id].accountId = 'acct_1'; });
  for (const action of ['handoff', 'close']) {
    assert.deepEqual((await t[action](id)).body, { error: 'sign_in_required' });
    assert.deepEqual((await t[action](id, { as: 'bobOtherAccount' })).body, { error: 'conversation_not_found' });
  }
  assert.equal((await t.store.read()).conversations[id].status, 'working', 'nothing changed');
  assert.equal((await t.close(id, { as: 'carolSameAccount' })).status, 200);
});

test('handoff queues and cancels the agent attempt; a repeat changes nothing; no staff returns to idle without retrying it', async () => {
  const t = staffSetup();
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  const res = await t.handoff(id);
  assert.deepEqual([res.status, res.body], [202, { conversation_id: id, status: 'queued', responder: 'agent' }]);
  await assert.rejects(t.service.reply(claim, 'out_1', reply('msg_r')), { code: 'stale_work' });
  const events = (await t.read(id)).body.events.length;
  assert.deepEqual((await t.handoff(id)).body, res.body);
  assert.equal((await t.read(id)).body.events.length, events);
  assert.equal(await t.service.claim(), null, 'no automated claims while queued');
  await t.service.noHumanAvailable(operator, id, 'Nobody is available right now.');
  await t.service.noHumanAvailable(operator, id, 'Nobody is available right now.');
  const page = (await t.read(id)).body;
  assert.deepEqual([page.status, page.responder], ['idle', 'agent']);
  const tail = page.events.slice(-2);
  assert.deepEqual([tail[0].message.text, tail[0].message.sender, tail[0].message.role], ['Nobody is available right now.', 'agent', 'company']);
  assert.deepEqual([tail[1].type, tail[1].status, tail[1].responder], ['state', 'idle', 'agent']);
  assert.equal(page.events.filter(event => event.message?.text === 'Nobody is available right now.').length, 1, 'idempotent');
  assert.equal(await t.service.claim(), null, 'the handed-off message is not retried by automation');
  assert.equal((await t.store.read()).work[0].phase, 'cancelled');
});

test('messages sent while queued wait for the person; with no staff the agent answers only those', async () => {
  const t = staffSetup();
  const id = (await t.start(hello)).body.conversation_id;
  await t.service.claim();
  await t.handoff(id);
  assert.equal((await t.send(id, { id: 'msg_2', sender: 'agent', text: 'More detail for the person.' })).body.status, 'queued');
  assert.equal((await t.send(id, { id: 'msg_ctx', sender: 'agent', context: { user_available: false } })).status, 202);
  assert.equal(await t.service.claim(), null, 'messages while queued create no automated work');
  await t.service.noHumanAvailable(operator, id, 'Nobody is available right now.');
  const page = (await t.read(id)).body;
  assert.deepEqual([page.status, page.responder], ['working', 'agent']);
  const next = await t.service.claim();
  assert.equal(next.message.id, 'msg_2');
  await t.service.finish(next, 'completed');
  assert.equal(await t.service.claim(), null, 'the handed-off message and the context update are not retried');
  assert.equal((await t.read(id)).body.status, 'idle');
});

test('returning to the agent queues user messages the person left unanswered', async () => {
  const t = staffSetup();
  const id = (await t.start(hello)).body.conversation_id;
  await t.handoff(id);
  const person = await t.service.joinHuman(operator, id);
  await t.service.reply(person, 'out_1', reply('msg_h1', 'human'));
  await t.send(id, { id: 'msg_2', sender: 'human', text: 'One more thing.' });
  await t.send(id, { id: 'msg_3', sender: 'human', text: 'And another.' });
  await t.service.returnToAgent(operator, id);
  assert.deepEqual([(await t.read(id)).body.status, (await t.read(id)).body.responder], ['working', 'agent']);
  const first = await t.service.claim();
  assert.equal(first.message.id, 'msg_2');
  assert.deepEqual(first.message, { id: 'msg_2', sender: 'human', text: 'One more thing.' });
  await t.service.finish(first, 'completed');
  assert.equal((await t.service.claim()).message.id, 'msg_3');
});

test('a person joins, publishes as human, then returns the conversation to the agent', async () => {
  const t = staffSetup();
  const id = (await t.start(hello)).body.conversation_id;
  const agent = await t.service.claim();
  await t.handoff(id);
  const person = await t.service.joinHuman(operator, id);
  assert.deepEqual(t.authorized, [id]);
  assert.deepEqual([person.conversationId, person.message], [id, hello]);
  let page = (await t.read(id)).body;
  assert.deepEqual([page.status, page.responder, page.events.at(-1).responder], ['idle', 'human', 'human']);
  await assert.rejects(t.service.reply(agent, 'out_1', reply('msg_r')), { code: 'stale_work' });
  assert.equal(await t.service.claim(), null);
  // The person replies as human; agent-sent output on their claim is refused. Handoff while a person responds changes nothing.
  await assert.rejects(t.service.reply(person, 'out_x', reply('msg_x')), { name: 'ValidationError' });
  await t.service.reply(person, 'out_1', reply('msg_h1', 'human'));
  assert.deepEqual((await t.handoff(id)).body, { conversation_id: id, status: 'idle', responder: 'human' });
  // Messages while a person responds create no automated work; the person reads them in history.
  await t.send(id, { id: 'msg_2', sender: 'human', text: 'Thanks!' });
  assert.equal(await t.service.claim(), null);
  assert.equal((await t.service.history(person)).at(-1).message.text, 'Thanks!');
  // The person's claim is not lease-bound.
  t.clock.advance(10 * 60_000);
  await t.service.reply(person, 'out_2', reply('msg_h2', 'human'));
  await t.service.returnToAgent(operator, id);
  await t.service.returnToAgent(operator, id);
  page = (await t.read(id)).body;
  assert.deepEqual([page.status, page.responder], ['idle', 'agent']);
  assert.deepEqual(page.events.filter(event => event.type === 'message' && event.message.role === 'company').map(event => event.message.sender), ['human', 'human']);
  await assert.rejects(t.service.reply(person, 'out_3', reply('msg_h3', 'human')), { code: 'stale_work' });
  await t.send(id, { id: 'msg_3', sender: 'agent', text: 'Back to you.' });
  assert.equal((await t.service.claim()).message.id, 'msg_3');
});

test('staff operations: operator authorization is mandatory and stored customer authority applies', async () => {
  const t = staffSetup();
  const id = (await t.start(hello)).body.conversation_id;
  await t.handoff(id);
  const before = await t.store.read();
  await assert.rejects(t.service.joinHuman({ staff: 'mallory' }, id), { message: 'operator denied' });
  await assert.rejects(t.service.joinHuman(operator, 'cnv_unknown'), { code: 'stale_work' });
  await assert.rejects(t.service.noHumanAvailable(operator, id, ''), TypeError);
  t.policy.deny = new AuthorityError('invalid_token');
  await assert.rejects(t.service.joinHuman(operator, id), AuthorityError);
  t.policy.deny = null;
  assert.deepEqual(await t.store.read(), before);
  assert.deepEqual(t.calls.filter(call => call.kind === 'accepted').map(call => call.userId), ['u_alice']);
  const unconfigured = setup();
  const other = (await unconfigured.start(hello)).body.conversation_id;
  await assert.rejects(unconfigured.service.joinHuman(operator, other), TypeError);
  // No person joins a closed conversation; closing cancels the pending handoff and a person's claim.
  const person = await t.service.joinHuman(operator, id);
  await t.close(id);
  await assert.rejects(t.service.reply(person, 'out_1', reply('msg_h', 'human')), { code: 'stale_work' });
  await assert.rejects(t.service.joinHuman(operator, id), { code: 'stale_work' });
  const queued = (await t.start({ ...hello, id: 'msg_q' })).body.conversation_id;
  await t.handoff(queued);
  assert.deepEqual((await t.close(queued)).body, { conversation_id: queued, status: 'closed', responder: 'agent' });
  await t.service.noHumanAvailable(operator, queued, 'Nobody.');
  assert.equal((await t.read(queued)).body.events.at(-1).status, 'closed', 'no-staff after close is a no-op');
});

test('company handoff and close through a work reference', async () => {
  const t = setup();
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  await t.service.handoff(claim);
  assert.equal((await t.read(id)).body.status, 'queued');
  await assert.rejects(t.service.handoff(claim), { code: 'stale_work' });
  const second = (await t.start({ ...hello, id: 'msg_2' })).body.conversation_id;
  const other = await t.service.claim();
  assert.equal(other.conversationId, second);
  await t.service.close(other);
  assert.equal((await t.read(second)).body.status, 'closed');
  await assert.rejects(t.service.close(other), { code: 'stale_work' });
});

test('reset: a fresh generation invalidates every old fence and conversation', async () => {
  const t = setup();
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  const { generation } = await t.store.read();
  await t.store.transaction(resetConversationState);
  const state = await t.store.read();
  assert.notEqual(state.generation, generation);
  assert.deepEqual([state.conversations, state.work, state.messages, state.bindings], [{}, [], {}, {}]);
  await assert.rejects(t.service.reply(claim, 'out_1', reply('msg_r')), { code: 'stale_work' });
  assert.equal((await t.read(id)).status, 404);
  // The old message ID starts a new conversation after reset.
  assert.notEqual((await t.start(hello)).body.conversation_id, id);
});

test('waited POST receipt survives a crash after commit: a retry on a fresh service returns it without a second job', async () => {
  const t = setup();
  const crashing = createConversationService({
    endpoint, authenticator: { authenticate: async () => principals.alice },
    policy: t.policy, clock: t.clock,
    store: { read: () => t.store.read(), transaction: change => t.store.transaction(change).then(() => { throw new Error('crash after commit'); }) },
  });
  await assert.rejects(crashing.handle(new Request(`${endpoint}?wait=10`, { method: 'POST', body: JSON.stringify({ message: hello }) })), { message: 'crash after commit' });
  const retry = await t.start(hello, { query: '?wait=3' });
  assert.equal(retry.status, 201);
  assert.deepEqual(types(retry.body.events), ['message', 'state']);
  assert.equal((await t.store.read()).work.length, 1);
  // Later events do not alter the receipt.
  await t.service.reply(await t.service.claim(), 'out_1', reply('msg_r'));
  assert.deepEqual((await t.start(hello, { query: '?wait=0' })).body, retry.body);
});

test('long poll: holds until an event arrives, then delivers it', async () => {
  const t = setup({ pollIntervalMs: 1 });
  const id = (await t.start(hello)).body.conversation_id;
  const cursor = (await t.read(id)).body.cursor;
  const claim = await t.service.claim();
  const held = t.read(id, { query: `?cursor=${cursor}&wait=30` });
  await new Promise(resolve => setTimeout(resolve, 5));
  await t.service.reply(claim, 'out_1', reply('msg_r'));
  const res = await held;
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.events.map(event => event.message.id), ['msg_r']);
});

test('long poll: times out with an empty page at the capped deadline, and returns at once when events exist', async () => {
  const t = setup({ pollIntervalMs: 1 });
  const id = (await t.start(hello)).body.conversation_id;
  const cursor = (await t.read(id)).body.cursor;
  let settled = false;
  const held = t.read(id, { query: `?cursor=${cursor}&wait=999` }).finally(() => { settled = true; });
  await new Promise(resolve => setTimeout(resolve, 5));
  t.clock.advance(29_999);
  await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(settled, false, 'held up to the 30 s cap');
  t.clock.advance(1);
  const res = await held;
  assert.deepEqual([res.status, res.body.events, res.body.cursor, res.body.has_more], [200, [], cursor, false]);
  // With unread events a waited read does not hold at all.
  assert.equal((await t.read(id, { query: '?wait=30' })).body.events.length, 2);
});

test('long poll: a reader revoked during the hold gets no data', async () => {
  const t = setup({ pollIntervalMs: 1 });
  const id = (await t.start(hello)).body.conversation_id;
  const cursor = (await t.read(id)).body.cursor;
  const claim = await t.service.claim();
  const held = t.read(id, { query: `?cursor=${cursor}&wait=30` });
  await new Promise(resolve => setTimeout(resolve, 5));
  t.policy.denyCurrent = new AuthorityError('invalid_token');
  await t.service.reply(claim, 'out_1', reply('msg_r'));
  const res = await held;
  assert.deepEqual([res.status, res.body], [401, { error: 'invalid_token' }]);
});

test('long poll: foreign readers are refused before any hold; an aborted wait only stops waiting', async () => {
  const t = setup({ pollIntervalMs: 1 });
  const id = (await t.start(hello)).body.conversation_id;
  assert.equal((await t.read(id, { as: 'bob', query: '?wait=30' })).status, 404);
  const cursor = (await t.read(id)).body.cursor;
  const controller = new AbortController();
  const held = t.read(id, { query: `?cursor=${cursor}&wait=30`, signal: controller.signal });
  await new Promise(resolve => setTimeout(resolve, 5));
  controller.abort();
  const res = await held;
  assert.deepEqual([res.status, res.body.events], [200, []]);
  assert.equal((await t.store.read()).work[0].phase, 'pending', 'accepted work is untouched');
});

test('construction rejects an invalid poll interval', () => {
  assert.throws(() => setup({ pollIntervalMs: 0 }), TypeError);
});
