import type {Message,AuthorType,ConversationEvent} from '../../dist/protocol/wire.js';
import type {ConversationOptions} from '../../dist/conversation/service.js';
import type {Principal,WorkRevocationPolicy} from '../../dist/auth/authority.js';
import {createMetadataResolver} from '../../dist/network/discovery.js';
import { expectValue,messageValue,optionalMessage } from '../../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createConversationService, initialConversationState } from '../../dist/index.js';
import { createReferenceIssuer, initialIssuerState } from '../../dist/reference-auth/index.js';
import { memoryCoordinator, memoryStore } from './support.mjs';

// Conversation service composed with the reference policy and one shared coordinator.
const ISSUER = 'https://auth.shop.test';
const CLIENT = 'https://agent.test/agent.json';
const endpoint = 'https://api.shop.test/poppy/conversations';
const NOW = Date.UTC(2026, 9, 19, 12);
const HOUR = 3_600_000;

function setup(revocationPolicy?:WorkRevocationPolicy) {
  const clock = { t: NOW, now: () => clock.t };
  const initial = initialIssuerState();
  initial.sessions.s1 = { clientId: CLIENT, userId: 'usr_1', version: 1, createdAt: NOW, expiresAt: NOW + 24 * HOUR, accountId: 'acct_1', grantId: 'g1' };
  initial.grants.g1 = { clientId: CLIENT, userId: 'usr_1', accountId: 'acct_1', scopes: ['orders:read'], expiresAt: NOW + 30 * 24 * HOUR, revoked: false, refreshHash: '', previousHash: '' };
  const issuerStore = memoryStore(initial);
  const coordinator = memoryCoordinator();
  const issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: `${ISSUER}/token`, revocationEndpoint: `${ISSUER}/revoke`, protectedResources: ['https://shop.test'], metadata:createMetadataResolver({async fetch(){throw new Error('unexpected policy metadata fetch');}}),supportedScopes:[], store: issuerStore, coordinator, now: clock.now });
  const principal = { issuer: ISSUER, clientId: CLIENT, userId: 'usr_1', sessionId: 's1', accountId: 'acct_1', grantId: 'g1', scopes: ['orders:read'], tokenExpiresAt: NOW + HOUR, sessionVersion: 1, issuerGeneration: initial.generation };
  // Stands in for token verification, which J10 extends to signed-in tokens.
  let current:Principal = principal;
  const authenticator = { async authenticate() { return current; } };
  const signOut = () => { const { accountId, grantId, ...signedOut } = { ...principal, scopes: [] }; current = signedOut; };
  const store = memoryStore(initialConversationState());
  const service = createConversationService({ historyScopes: ['orders:read'], endpoint, store, authenticator, policy: issuer.authority.policy, clock, revocationPolicy, pollIntervalMs: 1, authorizeOperator: async () => {}, directScopes: ['orders:read', 'orders:write'] });
  const call = async (method:string,path:string,body?:unknown) => {
    const response = await service.handle(new Request(`${endpoint}${path}`, { method, headers: { authorization: 'DPoP x' }, body: body===undefined?undefined:JSON.stringify(body) }));
    return { status: response.status, body: await response.json() };
  };
  return { clock, issuer, issuerStore, store, service, call, coordinator, signOut };
}
const message:Message = { id: 'msg_1', author: { type: 'agent' }, text: 'Where is order 1042?' };
const reply:Message = { id: 'msg_r1', author: { type: 'agent' }, text: 'Shipped.' };

test('token expiry fences buffered SSE frames and body reads after initial authentication', async () => {
  const t = setup(), id = (await t.call('POST', '', { message })).body.conversation_id;
  const response = await t.service.handle(new Request(`${endpoint}/${id}/events`, { headers: { accept: 'text/event-stream' } }));
  const reader = response.body!.getReader();
  assert.equal((await reader.read()).done, false);
  t.clock.t = NOW + HOUR;
  assert.equal((await reader.read()).done, true, 'buffered frames cannot outlive the token');
  const u = setup(), other = (await u.call('POST', '', { message })).body.conversation_id;
  const body = new ReadableStream<Uint8Array>({ pull(controller) {
    u.clock.t = NOW + HOUR;
    controller.enqueue(new TextEncoder().encode(JSON.stringify({ message: { ...message, id: 'after_body_wait' } })));
    controller.close();
  } }, { highWaterMark: 0 });
  const rejected = await u.service.handle(new Request(`${endpoint}/${other}/messages`, { method: 'POST', body, duplex: 'half' } as RequestInit));
  assert.equal(rejected.status, 401);
  assert.ok(!(await u.store.read()).conversations[other].events.some(event => event.type === 'message' && (event.message as { id: string }).id === 'after_body_wait'));
});

test('a long-poll rechecks the token after its wait instead of returning protected events', async () => {
  const t = setup(), id = (await t.call('POST', '', { message })).body.conversation_id;
  const cursor = (await t.call('GET', `/${id}/events`)).body.cursor;
  const reads = t.store.reads;
  const waiting = t.call('GET', `/${id}/events?cursor=${cursor}&wait=1`);
  await t.store.untilReads(reads + 1);
  t.clock.t = NOW + HOUR;
  assert.equal((await waiting).status, 401);
});

test('expired-token accepted work continues: bind, read history, reply and finish', async () => {
  const t = setup();
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  t.clock.t = NOW + 2 * HOUR; // the admission token expired an hour ago
  const claim = await t.service.claim();
  assert.deepEqual(await t.service.requireAccount(expectValue(claim), ['orders:read']), { accountId: 'acct_1' });
  assert.equal((await t.service.history(expectValue(claim))).length, 2);
  await t.service.reply(expectValue(claim), 'out_1', reply);
  await t.service.finish(expectValue(claim), 'completed');
  const state = await t.store.read();
  assert.equal(state.bindings[id].accountId, 'acct_1');
  assert.equal(state.conversations[id].status, 'idle');
  assert.equal(t.coordinator.held, false);
});

test('stop-account-work: after revocation no account work, publication or read gets through', async () => {
  const t = setup();
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  const claim = await t.service.claim();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  const before = await t.store.read();
  await assert.rejects(t.service.requireAccount(expectValue(claim), ['orders:read']), { code: 'invalid_token' });
  await assert.rejects(t.service.history(expectValue(claim)), { code: 'invalid_token' });
  await assert.rejects(t.service.reply(expectValue(claim), 'out_1', reply), { code: 'invalid_token' });
  await assert.rejects(t.service.finish(expectValue(claim), 'completed'), { code: 'invalid_token' });
  assert.deepEqual(await t.store.read(), before);
  assert.deepEqual(await t.call('GET', `/${id}/events`), { status: 401, body: { error: 'invalid_token' } });
  assert.equal((await t.call('POST', `/${id}/messages`, { message: { ...message, id: 'msg_2' } })).status, 401);
});

test('stop-account-work: revoked work can still fail or suspend, so the conversation is not stuck working', async () => {
  for (const outcome of ['failed', 'suspended'] as const) {
    const t = setup();
    const id = (await t.call('POST', '', { message })).body.conversation_id;
    const claim = await t.service.claim();
    await t.issuer.disconnect(CLIENT, 'acct_1');
    await assert.rejects(t.service.reply(expectValue(claim), 'out_1', reply), { code: 'invalid_token' });
    await t.service.finish(expectValue(claim), outcome);
    let state = await t.store.read();
    assert.deepEqual([state.work[0].phase, state.conversations[id].status], [outcome, 'idle']);
    await assert.rejects(t.service.finish(expectValue(claim), outcome), { code: 'stale_work' }, 'the fence still applies');
    // After sign-out the conversation continues signed out (spec 4.9): the next message is accepted and claimable.
    t.signOut();
    assert.equal((await t.call('POST', `/${id}/messages`, { message: { ...message, id: 'msg_2' } })).status, 202);
    const next = await t.service.claim();
    assert.equal(expectValue(next).message.id, 'msg_2');
    await t.service.reply(expectValue(next), 'out_1', reply);
    await t.service.finish(expectValue(next), 'completed');
    state = await t.store.read();
    assert.equal(state.conversations[id].status, 'idle');
  }
});

test('stop-account-work: revoked work can still ask to sign in, but cannot ask for the user', async () => {
  const t = setup();
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  const claim = await t.service.claim();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  await assert.rejects(t.service.requestUser(expectValue(claim), 'user', 'A specialist needs you.'), { code: 'invalid_token' });
  // Asking to sign in uses no account and is exactly what the signed-out User needs (spec 4.9, 7.11).
  await t.service.requestAuthorization(expectValue(claim), 'auth', ['orders:read']);
  await t.service.finish(expectValue(claim), 'suspended');
  const conversation = (await t.store.read()).conversations[id];
  const event = conversation.events.at(-2);
  assert.deepEqual([expectValue(event).type, expectValue(event).error, expectValue(event).scope], ['authorization', 'insufficient_scope', 'orders:read']);
  assert.equal(conversation.status, 'idle');
  assert.equal(t.coordinator.held, false);
});

test('revoked work asking for a scope it never had is told to sign in, not to widen scopes', async () => {
  for (const revocationPolicy of ['stop-account-work', 'allow-accepted-work-to-finish'] as const) {
    const t = setup(revocationPolicy);
    const id = (await t.call('POST', '', { message })).body.conversation_id;
    const claim = await t.service.claim();
    await t.service.requestAuthorization(expectValue(claim), 'live', ['orders:write']);
    await t.issuer.disconnect(CLIENT, 'acct_1');
    await t.service.requestAuthorization(expectValue(claim), 'revoked', ['orders:write']);
    const events = (await t.store.read()).conversations[id].events.filter((event:ConversationEvent) => event.type === 'authorization');
    assert.deepEqual(events.map((event:ConversationEvent) => [event.error, event.scope]), [['insufficient_scope', 'orders:write'], ['insufficient_scope', 'orders:write']], revocationPolicy);
  }
});

test("stop-account-work: a person's replies use no account and still publish after revocation; account reads do not", async () => {
  const t = setup();
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  const person = await t.service.joinHuman({}, id);
  await t.issuer.disconnect(CLIENT, 'acct_1');
  await assert.rejects(t.service.requireAccount(person, ['orders:read']), { code: 'invalid_token' });
  await assert.rejects(t.service.history(person), { code: 'invalid_token' });
  await t.service.renew(person);
  await t.service.reply(person, 'out_1', { id: 'msg_h1', author: { type: 'human' }, text: 'I can help with that.' });
  const { generation } = await t.issuerStore.read();
  t.issuerStore.set(state => { state.generation = 'after-reset'; });
  await assert.rejects(t.service.finish(person, 'completed'), { code: 'invalid_token' }, 'a reset still stops it');
  t.issuerStore.set(state => { state.generation = generation; });
  await t.service.finish(person, 'completed');
  const state = await t.store.read();
  assert.equal(messageValue(expectValue(state.conversations[id].events.at(-1)).message).author.type, 'human');
  assert.deepEqual(state.bindings[id], {}, 'no account was used');
  await assert.rejects(t.service.reply(person, 'out_2', { id: 'msg_h2', author: { type: 'human' }, text: 'x' }), { code: 'stale_work' }, 'the fence still applies');
  await assert.rejects(t.service.joinHuman({}, id), { code: 'invalid_token' }, 'joining acts under the revoked customer authority');
});

test('a revoked sign-in request still respects the fence and a reset generation', async () => {
  const t = setup();
  await t.call('POST', '', { message });
  const claim = await t.service.claim();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  t.clock.t = NOW + 2 * 60_000; // past the default lease
  await assert.rejects(t.service.requestAuthorization(expectValue(claim), 'auth', ['orders:read']), { code: 'stale_work' });
  const fresh = await t.service.claim();
  t.issuerStore.set(state => { state.generation = 'after-reset'; });
  await assert.rejects(t.service.requestAuthorization(expectValue(fresh), 'auth', ['orders:read']), { code: 'invalid_token' });
});

test('failing revoked work still respects a reset generation', async () => {
  const t = setup();
  await t.call('POST', '', { message });
  const claim = await t.service.claim();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  t.issuerStore.set(state => { state.generation = 'after-reset'; });
  await assert.rejects(t.service.finish(expectValue(claim), 'failed'), { code: 'invalid_token' });
});

test('allow-accepted-work-to-finish: accepted work completes but the revoked reader still sees nothing', async () => {
  const t = setup('allow-accepted-work-to-finish');
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  const claim = await t.service.claim();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  assert.deepEqual(await t.service.requireAccount(expectValue(claim), ['orders:read']), { accountId: 'acct_1' });
  await t.service.reply(expectValue(claim), 'out_1', reply);
  await t.service.finish(expectValue(claim), 'completed');
  assert.deepEqual(await t.call('GET', `/${id}/events`), { status: 401, body: { error: 'invalid_token' } });
});

test('revoked read: a revocation committed after authentication but before the final snapshot returns no data', async () => {
  const t = setup();
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  assert.equal((await t.call('GET', `/${id}/events`)).status, 200);
  // The reader has authenticated and taken its pre-check snapshot; the revocation lands before delivery.
  t.store.afterRead = () => t.issuer.disconnect(CLIENT, 'acct_1');
  assert.deepEqual(await t.call('GET', `/${id}/events`), { status: 401, body: { error: 'invalid_token' } });
});

test('held long poll: a disconnect during the hold releases no data', async () => {
  const t = setup('allow-accepted-work-to-finish');
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  const cursor = (await t.call('GET', `/${id}/events`)).body.cursor;
  const claim = await t.service.claim();
  const holding = t.store.untilReads(t.store.reads + 2); // initial authorized read, then the hold's first poll
  const held = t.call('GET', `/${id}/events?cursor=${cursor}&wait=30`);
  await holding;
  await t.issuer.disconnect(CLIENT, 'acct_1');
  await t.service.reply(expectValue(claim), 'out_1', reply);
  assert.deepEqual(await held, { status: 401, body: { error: 'invalid_token' } });
  assert.equal(t.coordinator.held, false, 'the hold never held the coordinator');
});
