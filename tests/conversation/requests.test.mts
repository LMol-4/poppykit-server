import type {Message,Sender,ConversationEvent} from '../../dist/protocol/wire.js';
import type {ConversationOptions} from '../../dist/conversation/service.js';
import { expectValue } from '../../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthorityError } from '../../dist/index.js';
import { hello, setup } from './support.mjs';

const directScopes = ['poppy:read', 'poppy:write'];
const latest = async (t:ReturnType<typeof setup>,id:string) => (await t.store.read()).conversations[id].events.at(-1);

test('requestAuthorization on signed-out work adds a sign_in_required authorization event', async () => {
  const t = setup({ directScopes });
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  await t.service.requestAuthorization(expectValue(claim), 'auth', ['poppy:read']);
  const event = await latest(t, id);
  assert.deepEqual(Object.keys(expectValue(event)).sort(), ['created_at', 'error', 'id', 'scope', 'type']);
  assert.deepEqual({ type: expectValue(event).type, error: expectValue(event).error, scope: expectValue(event).scope }, { type: 'authorization', error: 'sign_in_required', scope: 'poppy:read' });
  assert.match(expectValue(event).id, /^evt_/);
  assert.equal(expectValue(event).created_at, new Date(t.clock.now()).toISOString());
  // The conversation stays open and the work continues until it finishes (7.11).
  const page = (await t.read(id)).body;
  assert.deepEqual([page.status, page.responder, page.events.at(-1)], ['working', 'agent', event]);
  await t.service.finish(expectValue(claim), 'suspended');
  assert.equal((await t.read(id)).body.status, 'idle');
});

test('requestAuthorization on signed-in work lacking scopes asks for insufficient_scope', async () => {
  const t = setup({ directScopes });
  const id = (await t.start(hello, { as: 'aliceSignedIn' })).body.conversation_id;
  const claim = await t.service.claim();
  await t.service.requestAuthorization(expectValue(claim), 'auth', ['poppy:read', 'poppy:write', 'poppy:read']);
  const event = await latest(t, id);
  assert.deepEqual([expectValue(event).error, expectValue(event).scope], ['insufficient_scope', 'poppy:read poppy:write']);
});

test('requestAuthorization dedupes a stable output ID and rejects changed reuse', async () => {
  const t = setup({ directScopes });
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  await t.service.requestAuthorization(expectValue(claim), 'auth', ['poppy:read']);
  await t.service.requestAuthorization(expectValue(claim), 'auth', ['poppy:read']);
  const events = (await t.store.read()).conversations[id].events;
  assert.equal(events.filter((event:ConversationEvent) => event.type === 'authorization').length, 1);
  await assert.rejects(t.service.requestAuthorization(expectValue(claim), 'auth', ['poppy:write']), { code: 'output_conflict' });
  await t.service.reply(expectValue(claim), 'out_1', { id: 'msg_r1', sender: 'agent', text: 'Please sign in.' });
  await assert.rejects(t.service.requestAuthorization(expectValue(claim), 'out_1', ['poppy:read']), { code: 'output_conflict' });
  assert.equal((await t.store.read()).conversations[id].events.length, events.length + 1);
});

test('requestAuthorization validates scopes against the direct scopes before writing', async () => {
  const t = setup({ directScopes });
  await t.start(hello);
  const claim = await t.service.claim();
  const before = await t.store.read();
  for (const scopes of [[], ['poppy:admin'], ['poppy:read', 'openid'], 'poppy:read', [1]]) {
    // @ts-expect-error The table includes malformed non-string scopes.
    await assert.rejects(t.service.requestAuthorization(expectValue(claim), 'auth', scopes), TypeError, JSON.stringify(scopes));
  }
  await assert.rejects(setup().service.requestAuthorization(expectValue(claim), 'auth', ['poppy:read']), /supportedScopes is not configured/);
  assert.deepEqual(await t.store.read(), before);
});

test('stale fences cannot request authorization or a user', async () => {
  const t = setup({ directScopes, leaseMs: 1000 });
  const id = (await t.start(hello)).body.conversation_id;
  const old = await t.service.claim();
  t.clock.advance(1000);
  await assert.rejects(t.service.requestAuthorization(expectValue(old), 'auth', ['poppy:read']), { code: 'stale_work' }, 'expired lease');
  const fresh = await t.service.claim();
  await assert.rejects(t.service.requestAuthorization(expectValue(old), 'auth', ['poppy:read']), { code: 'stale_work' }, 'reclaimed');
  await assert.rejects(t.service.requestUser(expectValue(old), 'user', 'A specialist needs you.'), { code: 'stale_work' });
  await assert.rejects(t.service.requestAuthorization({ workId: 'wrk_unknown', fence: expectValue(fresh).fence }, 'auth', ['poppy:read']), { code: 'stale_work' });
  await t.service.finish(expectValue(fresh), 'suspended');
  await assert.rejects(t.service.requestAuthorization(expectValue(fresh), 'auth', ['poppy:read']), { code: 'stale_work' }, 'finished');
  const events = (await t.store.read()).conversations[id].events;
  assert.ok(!events.some((event:ConversationEvent) => event.type === 'authorization' || event.type === 'user_requested'));
});

test('requestUser adds a user_requested event, dedupes, and leaves status and responder alone', async () => {
  const t = setup();
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  const reason = 'A specialist needs to confirm the exchange with the customer.';
  await t.service.requestUser(expectValue(claim), 'user', reason);
  await t.service.requestUser(expectValue(claim), 'user', reason);
  const page = (await t.read(id)).body;
  const requests = page.events.filter((event: { type: string; }) => event.type === 'user_requested');
  assert.equal(requests.length, 1);
  assert.deepEqual(Object.keys(requests[0]).sort(), ['created_at', 'id', 'reason', 'type']);
  assert.equal(requests[0].reason, reason);
  assert.deepEqual([page.status, page.responder], ['working', 'agent']);
  await assert.rejects(t.service.requestUser(expectValue(claim), 'user', 'Something else.'), { code: 'output_conflict' });
  await assert.rejects(t.service.requestUser(expectValue(claim), 'user2', ''), TypeError);
  // @ts-expect-error Undefined user reason must reach runtime validation.
  await assert.rejects(t.service.requestUser(expectValue(claim), 'user2', undefined), TypeError);
});

test('requestUser needs the accepted authority', async () => {
  const t = setup();
  const id = (await t.start(hello)).body.conversation_id;
  const claim = await t.service.claim();
  t.policy.deny = new AuthorityError('invalid_token');
  await assert.rejects(t.service.requestUser(expectValue(claim), 'user', 'A specialist needs you.'), { code: 'invalid_token' });
  assert.ok(!(await t.store.read()).conversations[id].events.some((event:ConversationEvent) => event.type === 'user_requested'));
});

test('requestUser is refused inside a Direct Conversation, where the User is already talking', async () => {
  const t = setup();
  const parent = (await t.start(hello)).body.conversation_id;
  await t.service.finish(expectValue(await t.service.claim()), 'completed');
  const child = (await t.direct(parent, { id: 'msg_child', sender: 'human', text: 'Hi.' })).body.conversation_id;
  const claim = await t.service.claim();
  assert.equal(expectValue(claim).conversationId, child);
  await assert.rejects(t.service.requestUser(expectValue(claim), 'user', 'A specialist needs you.'), { name: 'TypeError', message: /Direct Conversation/ });
  assert.ok(!(await t.store.read()).conversations[child].events.some((event:ConversationEvent) => event.type === 'user_requested'));
  await t.service.reply(expectValue(claim), 'user', { id: 'msg_r1', sender: 'agent', text: 'Hello.' }); // the refused request used no output ID
});

test('a request body with a duplicate member is 400 invalid_request', async () => {
  const t = setup({ directScopes });
  const body = `{"message":${JSON.stringify(hello)},"message":${JSON.stringify(hello)}}`;
  const rejected = await t.call('POST', '', { body });
  assert.deepEqual([rejected.status, rejected.body], [400, { error: 'invalid_request' }]);
  assert.equal((await t.call('POST', '', { body: JSON.stringify({ message: hello }) })).status, 201, 'control: same body without the duplicate');
});
