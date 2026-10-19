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

function setup(revocationPolicy) {
  const clock = { t: NOW, now: () => clock.t };
  const initial = initialIssuerState();
  initial.sessions.s1 = { clientId: CLIENT, userId: 'usr_1', version: 1, createdAt: NOW };
  initial.grants.g1 = { clientId: CLIENT, accountId: 'acct_1', expiresAt: NOW + 30 * 24 * HOUR, revoked: false };
  const issuerStore = memoryStore(initial);
  const coordinator = memoryCoordinator();
  const issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: `${ISSUER}/token`, revocationEndpoint: `${ISSUER}/revoke`, poppyDomains: ['shop.test'], metadata: {}, store: issuerStore, coordinator, now: clock.now });
  const principal = { issuer: ISSUER, clientId: CLIENT, userId: 'usr_1', sessionId: 's1', accountId: 'acct_1', grantId: 'g1', scopes: ['poppy:read'], tokenExpiresAt: NOW + HOUR, sessionVersion: 1, issuerGeneration: initial.generation };
  // Stands in for token verification, which J10 extends to signed-in tokens.
  let current = principal;
  const authenticator = { async authenticate() { return current; } };
  const signOut = () => { const { accountId, grantId, ...signedOut } = { ...principal, scopes: [] }; current = signedOut; };
  const store = memoryStore(initialConversationState());
  const service = createConversationService({ endpoint, store, authenticator, policy: issuer.authority.policy, clock, revocationPolicy });
  const call = async (method, path, body) => {
    const response = await service.handle(new Request(`${endpoint}${path}`, { method, headers: { authorization: 'DPoP x' }, body: body && JSON.stringify(body) }));
    return { status: response.status, body: await response.json() };
  };
  return { clock, issuer, issuerStore, store, service, call, coordinator, signOut };
}
const message = { id: 'msg_1', sender: 'agent', text: 'Where is order 1042?' };
const reply = { id: 'msg_r1', sender: 'agent', text: 'Shipped.' };

test('expired-token accepted work continues: bind, read history, reply and finish', async () => {
  const t = setup();
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  t.clock.t = NOW + 2 * HOUR; // the admission token expired an hour ago
  const claim = await t.service.claim();
  assert.deepEqual(await t.service.requireAccount(claim, ['poppy:read']), { accountId: 'acct_1' });
  assert.equal((await t.service.history(claim)).length, 2);
  await t.service.reply(claim, 'out_1', reply);
  await t.service.finish(claim, 'completed');
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
  await assert.rejects(t.service.requireAccount(claim, ['poppy:read']), { code: 'invalid_token' });
  await assert.rejects(t.service.history(claim), { code: 'invalid_token' });
  await assert.rejects(t.service.reply(claim, 'out_1', reply), { code: 'invalid_token' });
  await assert.rejects(t.service.finish(claim, 'completed'), { code: 'invalid_token' });
  assert.deepEqual(await t.store.read(), before);
  assert.deepEqual(await t.call('GET', `/${id}/events`), { status: 401, body: { error: 'invalid_token' } });
  assert.equal((await t.call('POST', `/${id}/messages`, { message: { ...message, id: 'msg_2' } })).status, 401);
});

test('stop-account-work: revoked work can still fail or suspend, so the conversation is not stuck working', async () => {
  for (const outcome of ['failed', 'suspended']) {
    const t = setup();
    const id = (await t.call('POST', '', { message })).body.conversation_id;
    const claim = await t.service.claim();
    await t.issuer.disconnect(CLIENT, 'acct_1');
    await assert.rejects(t.service.reply(claim, 'out_1', reply), { code: 'invalid_token' });
    await t.service.finish(claim, outcome);
    let state = await t.store.read();
    assert.deepEqual([state.work[0].phase, state.conversations[id].status], [outcome, 'idle']);
    await assert.rejects(t.service.finish(claim, outcome), { code: 'stale_work' }, 'the fence still applies');
    // After sign-out the conversation continues signed out (spec 4.9): the next message is accepted and claimable.
    t.signOut();
    assert.equal((await t.call('POST', `/${id}/messages`, { message: { ...message, id: 'msg_2' } })).status, 202);
    const next = await t.service.claim();
    assert.equal(next.message.id, 'msg_2');
    await t.service.reply(next, 'out_1', reply);
    await t.service.finish(next, 'completed');
    state = await t.store.read();
    assert.equal(state.conversations[id].status, 'idle');
  }
});

test('failing revoked work still respects a reset generation', async () => {
  const t = setup();
  await t.call('POST', '', { message });
  const claim = await t.service.claim();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  t.issuerStore.set(state => { state.generation = 'after-reset'; });
  await assert.rejects(t.service.finish(claim, 'failed'), { code: 'invalid_token' });
});

test('allow-accepted-work-to-finish: accepted work completes but the revoked reader still sees nothing', async () => {
  const t = setup('allow-accepted-work-to-finish');
  const id = (await t.call('POST', '', { message })).body.conversation_id;
  const claim = await t.service.claim();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  assert.deepEqual(await t.service.requireAccount(claim, ['poppy:read']), { accountId: 'acct_1' });
  await t.service.reply(claim, 'out_1', reply);
  await t.service.finish(claim, 'completed');
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
