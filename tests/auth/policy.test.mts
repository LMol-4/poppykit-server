import type {Principal,WorkRevocationPolicy} from '../../dist/auth/authority.js';
import {createMetadataResolver} from '../../dist/network/discovery.js';
import { expectValue } from '../../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createReferenceIssuer, initialIssuerState } from '../../dist/reference-auth/index.js';
import { AuthorityError } from '../../dist/index.js';
import { memoryCoordinator, memoryStore } from '../conversation/support.mjs';
import { NOW } from './support.mjs';

const ISSUER = 'https://auth.shop.test';
const CLIENT = 'https://agent.test/agent.json';
const DAY = 86_400_000;

// Grants are seeded as J10 sign-in will store them.
function setup() {
  const clock = { now: NOW };
  const initial = initialIssuerState();
  initial.sessions.s1 = { clientId: CLIENT, userId: 'usr_1', version: 1, createdAt: NOW, expiresAt: NOW + 7 * DAY, accountId: 'acct_1', grantId: 'g1' };
  initial.grants.g1 = { clientId: CLIENT, userId: 'usr_1', accountId: 'acct_1', scopes: ['poppy:read'], expiresAt: NOW + 30 * DAY, revoked: false, refreshHash: '', previousHash: '' };
  const store = memoryStore(initial);
  const coordinator = memoryCoordinator();
  const issuer = createReferenceIssuer({ issuer: ISSUER, tokenEndpoint: `${ISSUER}/token`, revocationEndpoint: `${ISSUER}/revoke`, poppyDomains: ['shop.test'], metadata:createMetadataResolver({async fetch(){throw new Error('unexpected policy metadata fetch');}}),directScopes:[], store, coordinator, now: () => clock.now });
  const signedIn = { issuer: ISSUER, clientId: CLIENT, userId: 'usr_1', sessionId: 's1', accountId: 'acct_1', grantId: 'g1', scopes: ['poppy:read'], tokenExpiresAt: NOW + 3_600_000, sessionVersion: 1, issuerGeneration: initial.generation };
  const { accountId, grantId, ...signedOut } = { ...signedIn, scopes: [] };
  const accepted = (principal:Principal, revocationPolicy:WorkRevocationPolicy = 'stop-account-work') => ({ principal, acceptedAt: NOW, revocationPolicy });
  return { clock, store, coordinator, issuer, policy: issuer.authority.policy, signedIn, signedOut, accepted };
}

test('withCurrent runs the action while holding the coordinator after checking the issuer snapshot', async () => {
  const t = setup();
  const result = await t.policy.withCurrent(t.signedIn, ['poppy:read'], async () => ({ held: t.coordinator.held }));
  assert.deepEqual(result, { held: true });
  assert.equal(t.coordinator.held, false);
  assert.equal(await t.policy.withCurrent(t.signedOut, [], async () => 'ok'), 'ok');
});

test('withCurrent rejects stale or foreign principals and missing scopes without running the action', async () => {
  const t = setup();
  let runs = 0;
  const action = async () => { runs++; };
  const stale = {
    issuer: { issuer: 'https://other.test' },
    generation: { issuerGeneration: 'old' },
    noGeneration: { issuerGeneration: undefined },
    session: { sessionId: 'nope' },
    sessionUser: { userId: 'usr_2' },
    sessionClient: { clientId: 'https://agent.test/other.json' },
    unknownGrant: { grantId: 'g2' },
    accountWithoutGrant: { grantId: undefined },
    grantAccount: { accountId: 'acct_2' },
    prototypeGrant: { grantId: '__proto__' },
  };
  for (const [name, change] of Object.entries(stale)) {
    await assert.rejects(t.policy.withCurrent({ ...t.signedIn, ...change }, [], action), { code: 'invalid_token', status: 401 }, name);
  }
  const invalidStates: ((state: ReturnType<typeof initialIssuerState>) => void)[] = [
    state => { state.sessions.s1.expiresAt = NOW; },
    state => { state.grants.g1.expiresAt = NOW; },
    state => { state.grants.g1.revoked = true; },
    state => { state.generation = 'after-reset'; },
  ];
  for (const invalidate of invalidStates) {
    const current = setup(); current.store.set(invalidate);
    await assert.rejects(current.policy.withCurrent(current.signedIn, [], action), { code: 'invalid_token', status: 401 });
  }
  const scope = await t.policy.withCurrent(t.signedIn, ['poppy:read', 'poppy:write'], action).catch(error => error);
  assert.ok(scope instanceof AuthorityError);
  assert.deepEqual([scope.code, scope.status, scope.headers.get('www-authenticate')], ['insufficient_scope', 403, 'DPoP error="insufficient_scope", scope="poppy:read poppy:write", algs="ES256"']);
  await assert.rejects(t.policy.withCurrent(t.signedOut, ['poppy:read'], action), { code: 'insufficient_scope' });
  assert.equal(runs, 0);
  assert.equal(t.coordinator.held, false);
});

test('expiry is not revocation: accepted work outlives its token, current readers need a live grant', async () => {
  const t = setup();
  let runs = 0;
  t.clock.now = t.signedIn.tokenExpiresAt - 1;
  await t.policy.withCurrent(t.signedIn, ['poppy:read'], async () => { runs++; });
  t.clock.now++;
  await assert.rejects(t.policy.withCurrent(t.signedIn, [], async () => { runs++; }), { code: 'invalid_token' });
  assert.equal(runs, 1);
  t.clock.now = t.signedIn.tokenExpiresAt + DAY;
  assert.equal(await t.policy.withAccepted(t.accepted(t.signedIn), ['poppy:read'], async () => 'continued'), 'continued');
  // An ended account sign-in (grant expiry) is not token expiry: stop policy ends account work.
  t.clock.now = NOW + 31 * DAY;
  await assert.rejects(t.policy.withAccepted(t.accepted(t.signedIn), [], async () => {}), { code: 'invalid_token' });
  await assert.rejects(t.policy.withCurrent(t.signedIn, [], async () => {}), { code: 'invalid_token' });
});

test('revocation: stop policy ends account work, allow-finish continues it, current readers are never relaxed', async () => {
  const t = setup();
  await t.issuer.disconnect(CLIENT, 'acct_1');
  assert.equal((await t.store.read()).grants.g1.revoked, true);
  await assert.rejects(t.policy.withAccepted(t.accepted(t.signedIn), [], async () => {}), { code: 'invalid_token' });
  await assert.rejects(t.policy.withAccepted(Object.assign(t.accepted(t.signedIn),{revocationPolicy:'unknown-policy'}), [], async () => {}), { code: 'invalid_token' }, 'unknown policy means stop');
  assert.equal(await t.policy.withAccepted(t.accepted(t.signedIn, 'allow-accepted-work-to-finish'), ['poppy:read'], async () => 'finished'), 'finished');
  await assert.rejects(t.policy.withCurrent(t.signedIn, [], async () => {}), { code: 'invalid_token' });
  // Signed-out work holds no account authority, so revocation leaves it alone.
  assert.equal(await t.policy.withAccepted(t.accepted(t.signedOut), [], async () => 'general'), 'general');
});

test('disconnect revokes only that client and account', async () => {
  const t = setup();
  t.store.set(state => {
    state.grants.g2 = { ...state.grants.g1, accountId: 'acct_2' };
    state.grants.g3 = { ...state.grants.g1, clientId: 'https://agent.test/other.json' };
  });
  await t.issuer.disconnect(CLIENT, 'acct_1');
  const { grants } = await t.store.read();
  assert.deepEqual([grants.g1.revoked, grants.g2.revoked, grants.g3.revoked], [true, false, false]);
});

test('accepted scope ceiling and reset generation hold under both revocation policies', async () => {
  const t = setup();
  for (const revocationPolicy of ['stop-account-work', 'allow-accepted-work-to-finish'] as const) {
    // A later broader sign-in does not widen work accepted with fewer scopes.
    await assert.rejects(t.policy.withAccepted(t.accepted({ ...t.signedIn, scopes: [] }, expectValue(revocationPolicy)), ['poppy:read'], async () => {}), { code: 'insufficient_scope' });
    await assert.rejects(t.policy.withAccepted(t.accepted({ ...t.signedIn, issuer: 'https://other.test' }, expectValue(revocationPolicy)), [], async () => {}), { code: 'invalid_token' });
  }
  t.store.set(state => { state.generation = 'after-reset'; });
  for (const revocationPolicy of ['stop-account-work', 'allow-accepted-work-to-finish'] as const) {
    await assert.rejects(t.policy.withAccepted(t.accepted(t.signedIn, expectValue(revocationPolicy)), [], async () => {}), { code: 'invalid_token' });
    await assert.rejects(t.policy.withAccepted(t.accepted(t.signedOut, expectValue(revocationPolicy)), [], async () => {}), { code: 'invalid_token' });
  }
});

test('coordinator orders revocation against checked actions and is released on failure', async () => {
  const t = setup();
  // A revocation ordered first denies the action queued behind it.
  const revoke = t.issuer.disconnect(CLIENT, 'acct_1');
  const denied = t.policy.withCurrent(t.signedIn, [], async () => 'read');
  await revoke;
  await assert.rejects(denied, { code: 'invalid_token' });

  const u = setup();
  // An action that holds the coordinator finishes before a later revocation commits.
  let release!:()=>void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const reading = u.policy.withCurrent(u.signedIn, [], async () => { await gate; return (await u.store.read()).grants.g1.revoked; });
  const revoking = u.issuer.disconnect(CLIENT, 'acct_1');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal((await u.store.read()).grants.g1.revoked, false, 'revocation waits for the holder');
  expectValue(release)();
  assert.equal(await reading, false);
  await revoking;
  assert.equal((await u.store.read()).grants.g1.revoked, true);

  await assert.rejects(u.policy.withAccepted(u.accepted(u.signedOut), [], async () => { throw new Error('boom'); }), { message: 'boom' });
  assert.equal(await u.policy.withAccepted(u.accepted(u.signedOut), [], async () => 'next'), 'next');
  // The policy never nests: an action that re-enters the coordinator is refused instead of deadlocking.
  await assert.rejects(u.policy.withAccepted(u.accepted(u.signedOut), [], () => u.policy.withCurrent(u.signedOut, [], async () => {})), /nested/);
});
