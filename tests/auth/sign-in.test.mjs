import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { AuthorizationError, initialIssuerState } from '../../dist/reference-auth/index.js';
import { NOW } from './support.mjs';
import { CLIENT, ISSUER, OTHER_CLIENT, REDIRECT, RESOURCE, expectError, setup } from './issuer-support.mjs';

const BINDING = 'browser-binding-0123456789abcdef';
const DAY = 86_400_000;
const REVOKE = `${ISSUER}/oauth/revoke`;

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}
function authorizeRequest(params = {}) {
  const url = new URL(`${ISSUER}/oauth/authorize`);
  const query = { response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'poppy:read poppy:write', state: 'state-1', code_challenge: pkce().challenge, code_challenge_method: 'S256', ...params };
  for (const [name, value] of Object.entries(query)) if (value !== undefined) url.searchParams.set(name, value);
  return new Request(url);
}

async function signInSetup(overrides) {
  const env = await setup({ requireDpopNonce: false, ...overrides });
  env.session = async (fields) => (await env.send(fields)).body;
  // Runs begin and complete as the host's login/consent page would, returning the code and its verifier.
  env.code = async ({ accountId = 'acct_1', scopes, params } = {}) => {
    const { verifier, challenge } = pkce();
    const view = await env.issuer.beginAuthorization(authorizeRequest({ code_challenge: challenge, ...params }), BINDING);
    const url = await env.issuer.completeAuthorization(view.id, BINDING, { accountId, scopes: scopes ?? view.scopes });
    return { code: url.searchParams.get('code'), verifier, url, view };
  };
  env.exchange = (sessionId, { code, verifier }, fields = {}) => env.send({ grant_type: 'authorization_code', assertion: undefined, code, redirect_uri: REDIRECT, code_verifier: verifier, session_id: sessionId, ...fields });
  env.signIn = async (sessionId, options) => env.exchange(sessionId, await env.code(options));
  env.refresh = (refresh_token, fields = {}) => env.send({ grant_type: 'refresh_token', assertion: undefined, refresh_token, ...fields });
  env.revoke = async (token, fields = {}) => {
    const form = { token, token_type_hint: 'refresh_token', client_id: CLIENT, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await env.clientAssertion(), ...fields };
    const body = new URLSearchParams(Object.entries(form).filter(([, value]) => value !== undefined));
    const response = await env.issuer.revoke(new Request(REVOKE, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }));
    return { status: response.status, headers: response.headers, text: await response.text() };
  };
  env.introspect = token => env.issuer.authority.introspect(token);
  return env;
}

test('Direct Sign-In signs in the Session with an Account Token; partial consent narrows the scopes', async () => {
  const env = await signInSetup();
  const signedOut = await env.session();
  const { verifier, challenge } = pkce();
  const view = await env.issuer.beginAuthorization(authorizeRequest({ code_challenge: challenge, resource: RESOURCE }), BINDING);
  assert.deepEqual({ ...view, id: undefined }, { id: undefined, clientId: CLIENT, clientName: 'Agent', scopes: ['poppy:read', 'poppy:write'], expiresAt: NOW + 600_000 });
  const callback = await env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: ['poppy:read'] });
  assert.equal(`${callback.origin}${callback.pathname}`, REDIRECT);
  assert.deepEqual([...callback.searchParams.keys()].sort(), ['code', 'iss', 'state']);
  assert.equal(callback.searchParams.get('state'), 'state-1'); assert.equal(callback.searchParams.get('iss'), ISSUER);
  const code = callback.searchParams.get('code');

  const response = await env.exchange(signedOut.session_id, { code, verifier }, { resource: RESOURCE });
  assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Object.keys(response.body).sort(), ['access_token', 'expires_in', 'refresh_token', 'refresh_token_expires_in', 'scope', 'session_id', 'signed_in', 'token_type']);
  assert.deepEqual([response.body.scope, response.body.session_id, response.body.signed_in, response.body.token_type, response.body.refresh_token_expires_in], ['poppy:read', signedOut.session_id, true, 'DPoP', 2_592_000]);
  const persisted = JSON.stringify(env.store.state);
  for (const secret of [code, response.body.refresh_token, response.body.access_token, verifier, BINDING]) assert.ok(!persisted.includes(secret), 'secrets are stored only as hashes');

  const { principal } = await env.issuer.authority.introspect(response.body.access_token, RESOURCE);
  const [grantId] = Object.keys(env.store.state.grants);
  assert.deepEqual(principal, { issuer: ISSUER, clientId: CLIENT, userId: 'usr_1', sessionId: signedOut.session_id, accountId: 'acct_1', grantId, scopes: ['poppy:read'], tokenExpiresAt: NOW + 3_600_000, sessionVersion: 1, issuerGeneration: env.store.state.generation });
  // The grant lasts the account sign-in lifetime, not the access-token lifetime.
  assert.equal(env.store.state.grants[grantId].expiresAt, NOW + 30 * DAY);
  assert.equal(await env.issuer.authority.policy.withCurrent(principal, ['poppy:read'], async () => 'read'), 'read');
  // The earlier signed-out token stays signed out.
  const before = await env.introspect(signedOut.access_token);
  assert.equal(before.principal.accountId, undefined); assert.deepEqual(before.principal.scopes, []);
  // A signed-in Session is renewed with its Account Token, not the signed-out assertion.
  expectError(await env.send({ session_id: signedOut.session_id }), 'invalid_grant');

  const metadata = (await setup({ authorizationEndpoint: `${ISSUER}/oauth/authorize` })).issuer.authorizationMetadata();
  assert.equal(metadata.authorization_endpoint, `${ISSUER}/oauth/authorize`);
  assert.deepEqual([metadata.response_types_supported, metadata.code_challenge_methods_supported], [['code'], ['S256']]);
});

test('an authorization code works once; its reuse revokes the sign-in it produced', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const grant = await env.code();
  const first = await env.exchange(session.session_id, grant);
  assert.equal(first.status, 200);
  const second = await env.session();
  expectError(await env.exchange(second.session_id, grant), 'invalid_grant');
  expectError(await env.refresh(first.body.refresh_token), 'invalid_grant');
  await assert.rejects(env.introspect(first.body.access_token), { code: 'invalid_token' });
  assert.equal(env.store.state.sessions[session.session_id].grantId, null, 'the Session was signed out');
});

test('PKCE mismatch, wrong redirect, wrong client and expired codes are invalid_grant and leave the code unused', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const grant = await env.code();
  const otherClient = { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }) };
  const cases = {
    verifier: { code_verifier: pkce().verifier },
    redirect: { redirect_uri: `${REDIRECT}/other` },
    redirectPrefix: { redirect_uri: 'https://agent.test/oauth/callbac' },
    unknownCode: { code: 'not-a-code' },
    client: otherClient,
  };
  for (const [name, fields] of Object.entries(cases)) await assert.doesNotReject(async () => expectError(await env.exchange(session.session_id, grant, fields), 'invalid_grant'), name);
  for (const name of ['code', 'redirect_uri', 'code_verifier', 'session_id']) expectError(await env.exchange(session.session_id, grant, { [name]: undefined }), 'invalid_request');
  expectError(await env.exchange('ses_missing', grant), 'invalid_session');
  expectError(await env.exchange(session.session_id, grant, { scope: 'poppy:admin' }), 'invalid_scope');
  assert.deepEqual(env.store.state.grants, {}, 'no failed exchange created a grant');
  assert.equal((await env.exchange(session.session_id, grant)).status, 200, 'the genuine exchange still succeeds');

  const late = await env.code();
  env.clock.now += 61_000;
  expectError(await env.exchange((await env.session()).session_id, late), 'invalid_grant');
});

test('beginAuthorization validates the request before persisting it', async () => {
  const env = await signInSetup();
  const noRedirect = {
    missingClient: { client_id: undefined },
    unknownClient: { client_id: 'https://agent.test/unknown.json' },
    missingRedirect: { redirect_uri: undefined },
    unregisteredRedirect: { redirect_uri: 'https://evil.test/callback' },
    redirectSuffix: { redirect_uri: `${REDIRECT}?x=1` },
  };
  for (const [name, params] of Object.entries(noRedirect)) {
    const error = await env.issuer.beginAuthorization(authorizeRequest(params), BINDING).catch(error => error);
    assert.ok(error instanceof AuthorizationError, name); assert.equal(error.redirectTo, undefined, name);
  }
  assert.equal((await env.issuer.beginAuthorization(authorizeRequest({ client_id: 'https://agent.test/unknown.json' }), BINDING).catch(error => error)).code, 'invalid_client');
  const redirected = {
    unsupported_response_type: { response_type: 'token' },
    invalid_request: { state: undefined },
    plainPkce: { code_challenge_method: 'plain' },
    noPkce: { code_challenge: undefined, code_challenge_method: undefined },
    shortChallenge: { code_challenge: 'abc' },
    invalid_scope: { scope: 'poppy:read poppy:admin' },
    emptyScope: { scope: ' ' },
    invalid_target: { resource: 'https://api.shop.test/other' },
  };
  const codes = { plainPkce: 'invalid_request', noPkce: 'invalid_request', shortChallenge: 'invalid_request', emptyScope: 'invalid_scope' };
  for (const [name, params] of Object.entries(redirected)) {
    const error = await env.issuer.beginAuthorization(authorizeRequest(params), BINDING).catch(error => error);
    assert.ok(error instanceof AuthorizationError, name);
    assert.equal(error.code, codes[name] ?? name, name);
    assert.equal(`${error.redirectTo.origin}${error.redirectTo.pathname}`, REDIRECT, name);
    assert.equal(error.redirectTo.searchParams.get('error'), error.code, name);
    assert.equal(error.redirectTo.searchParams.get('iss'), ISSUER, name);
    assert.equal(error.redirectTo.searchParams.get('state'), params.state === undefined && 'state' in params ? null : 'state-1', name);
  }
  const duplicate = new Request(`${authorizeRequest().url}&scope=poppy:read`);
  assert.equal((await env.issuer.beginAuthorization(duplicate, BINDING).catch(error => error)).code, 'invalid_request');
  await assert.rejects(env.issuer.beginAuthorization(authorizeRequest(), ''), TypeError);
  assert.deepEqual(env.store.state.authorizations, {}, 'nothing was persisted');
});

test('completeAuthorization checks the browser binding, consumes once, and never grants beyond the request', async () => {
  const env = await signInSetup();
  const view = await env.issuer.beginAuthorization(authorizeRequest({ scope: 'poppy:read' }), BINDING);
  await assert.rejects(env.issuer.completeAuthorization(view.id, 'another-browser-binding', { denied: true }), AuthorizationError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, 'another-browser-binding', { accountId: 'acct_1', scopes: ['poppy:read'] }), AuthorizationError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: ['poppy:write'] }), TypeError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: '', scopes: ['poppy:read'] }), TypeError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: [] }), TypeError);
  const denied = await env.issuer.completeAuthorization(view.id, BINDING, { denied: true });
  assert.deepEqual(Object.fromEntries(denied.searchParams), { error: 'access_denied', state: 'state-1', iss: ISSUER });
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: ['poppy:read'] }), { code: 'invalid_request' });
  await assert.rejects(env.issuer.completeAuthorization('__proto__', BINDING, { denied: true }), AuthorizationError);
  assert.deepEqual(env.store.state.codes, {});

  const expiring = await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  env.clock.now += 600_000;
  await assert.rejects(env.issuer.completeAuthorization(expiring.id, BINDING, { accountId: 'acct_1', scopes: ['poppy:read'] }), AuthorizationError);
});

test('a Session keeps its first account: another account gets account_mismatch and no tokens', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const first = await env.signIn(session.session_id);
  assert.equal(first.status, 200);
  assert.equal((await env.revoke(first.body.refresh_token)).status, 200);
  // Signed out, but still bound to acct_1.
  assert.equal((await env.send({ session_id: session.session_id })).status, 200);
  const before = structuredClone(env.store.state.accessTokens);
  expectError(await env.signIn(session.session_id, { accountId: 'acct_2' }), 'account_mismatch');
  const elsewhere = await env.signIn((await env.session()).session_id, { accountId: 'acct_2' });
  assert.equal(elsewhere.status, 200);
  const count = Object.keys(env.store.state.accessTokens).length;
  expectError(await env.refresh(elsewhere.body.refresh_token, { session_id: session.session_id }), 'account_mismatch');
  assert.equal(Object.keys(env.store.state.accessTokens).length, count, 'no tokens issued');
  assert.ok(Object.keys(before).every(key => key in env.store.state.accessTokens));
  // The same account signs in again on the same Session.
  const again = await env.signIn(session.session_id);
  assert.equal(again.status, 200); assert.equal(again.body.session_id, session.session_id);
});

test('refresh rotates the Account Token under a stable lineage without extending it; a rotated token is dead', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const signedIn = await env.signIn(session.session_id);
  const [grantId] = Object.keys(env.store.state.grants);
  env.clock.now += DAY / 2;
  const rotated = await env.refresh(signedIn.body.refresh_token, { session_id: session.session_id, scope: 'poppy:read' });
  assert.equal(rotated.status, 200);
  assert.notEqual(rotated.body.refresh_token, signedIn.body.refresh_token);
  assert.deepEqual([rotated.body.scope, rotated.body.signed_in, rotated.body.refresh_token_expires_in], ['poppy:read', true, 2_592_000 - 43_200]);
  assert.deepEqual(Object.keys(env.store.state.grants), [grantId]);
  assert.equal((await env.introspect(rotated.body.access_token)).principal.grantId, grantId);
  expectError(await env.refresh(signedIn.body.refresh_token, { session_id: session.session_id }), 'invalid_grant');

  // Without session_id a new signed-in Session starts; resources are chosen per request, not fixed by the grant.
  const fresh = await env.refresh(rotated.body.refresh_token, { resource: RESOURCE });
  assert.equal(fresh.status, 200); assert.notEqual(fresh.body.session_id, session.session_id);
  assert.equal(fresh.body.scope, 'poppy:read poppy:write', 'an earlier narrow request does not narrow the grant');
  assert.equal((await env.issuer.authority.introspect(fresh.body.access_token, RESOURCE)).principal.accountId, 'acct_1');
  const general = await env.refresh(fresh.body.refresh_token, { session_id: fresh.body.session_id });
  assert.equal(general.status, 200); assert.equal((await env.introspect(general.body.access_token)).principal.accountId, 'acct_1');

  expectError(await env.refresh(general.body.refresh_token, { scope: 'poppy:read poppy:admin' }), 'invalid_scope');
  expectError(await env.refresh(general.body.refresh_token, { scope: '' }), 'invalid_scope');
  expectError(await env.refresh(general.body.refresh_token, { resource: 'https://api.shop.test/other' }), 'invalid_target');
  const otherUser = await env.session({ assertion: await env.assertion({ sub: 'usr_2' }) });
  expectError(await env.refresh(general.body.refresh_token, { session_id: otherUser.session_id }), 'invalid_session');
  expectError(await env.refresh(general.body.refresh_token, { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }) }), 'invalid_grant');
  expectError(await env.refresh(undefined), 'invalid_request');

  // Concurrent use of one Account Token: exactly one successor.
  const results = await Promise.all([env.refresh(general.body.refresh_token), env.refresh(general.body.refresh_token)]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 400]);

  // The lineage ends at its original expiry however often it rotates.
  const latest = results.find(result => result.status === 200).body.refresh_token;
  env.clock.now = NOW + 30 * DAY;
  expectError(await env.refresh(latest), 'invalid_grant');
});

test('revocation signs out the lineage; a rotated token revokes it too; unknown and foreign tokens change nothing', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const signedIn = await env.signIn(session.session_id);
  const rotated = await env.refresh(signedIn.body.refresh_token, { session_id: session.session_id });
  const unchanged = structuredClone(env.store.state.grants);

  const unknown = await env.revoke('not-a-token');
  assert.deepEqual([unknown.status, unknown.text, unknown.headers.get('cache-control')], [200, '', 'no-store']);
  const foreign = await env.revoke(rotated.body.refresh_token, { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }) });
  assert.equal(foreign.status, 200);
  assert.deepEqual(env.store.state.grants, unchanged);
  assert.equal((await env.revoke(rotated.body.refresh_token, { client_assertion: 'bad' })).status, 401);
  assert.equal((await env.revoke(undefined)).status, 400);
  const reused = await env.clientAssertion();
  assert.equal((await env.revoke('not-a-token', { client_assertion: reused })).status, 200);
  assert.equal((await env.revoke('not-a-token', { client_assertion: reused })).status, 401, 'client assertions are single-use here too');
  assert.deepEqual(env.store.state.grants, unchanged);

  // Revoking the already rotated token (lost-response cleanup) ends the whole lineage.
  assert.equal((await env.revoke(signedIn.body.refresh_token)).status, 200);
  expectError(await env.refresh(rotated.body.refresh_token), 'invalid_grant');
  await assert.rejects(env.introspect(rotated.body.access_token), { code: 'invalid_token' });
  const renewed = await env.send({ session_id: session.session_id });
  assert.equal(renewed.status, 200); assert.equal(renewed.body.signed_in, false, 'the Session continues signed out');
  assert.equal((await env.revoke(rotated.body.refresh_token)).status, 200, 'revoking again is harmless');
});

test('disconnect revokes the account sign-ins of that client and signs out their Sessions', async () => {
  const env = await signInSetup();
  const one = await env.session(); const two = await env.session();
  const a = await env.signIn(one.session_id);
  const b = await env.signIn(two.session_id, { accountId: 'acct_2' });
  await env.issuer.disconnect(CLIENT, 'acct_1');
  assert.equal(env.store.state.sessions[one.session_id].grantId, null);
  assert.equal(env.store.state.sessions[one.session_id].accountId, 'acct_1');
  await assert.rejects(env.introspect(a.body.access_token), { code: 'invalid_token' });
  expectError(await env.refresh(a.body.refresh_token), 'invalid_grant');
  assert.equal((await env.introspect(b.body.access_token)).principal.accountId, 'acct_2');
  assert.equal((await env.refresh(b.body.refresh_token)).status, 200);
});

test('Sessions end after a day without tokens and expired records are pruned', async () => {
  const env = await signInSetup();
  const idle = await env.session();
  const kept = await env.session();
  await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  const unused = await env.code();
  const signedIn = await env.signIn(kept.session_id);
  env.clock.now += DAY - 1000;
  assert.equal((await env.refresh(signedIn.body.refresh_token, { session_id: kept.session_id })).status, 200);
  env.clock.now += 1000;
  expectError(await env.send({ session_id: idle.session_id }), 'invalid_session');
  await assert.rejects(env.introspect(idle.access_token), { code: 'invalid_token' });
  // A failed request rolls back; the next successful commit prunes.
  const later = await env.session();
  const state = env.store.state;
  assert.deepEqual(Object.keys(state.sessions).sort(), [kept.session_id, later.session_id].sort());
  assert.deepEqual([state.authorizations, state.codes], [{}, {}]);
  assert.ok(Object.values(state.accessTokens).every(record => record.expiresAt > env.clock.now));
  expectError(await env.exchange(kept.session_id, unused), 'invalid_grant');
  assert.equal(Object.keys(state.refreshTokens).length, 2, 'current and rotated Account Token of the live lineage');
});

test('a reset during begin or exchange cannot recreate state from the old generation', async () => {
  const env = await signInSetup();
  env.onClient = () => { env.store.state = initialIssuerState(); env.onClient = undefined; };
  await assert.rejects(env.issuer.beginAuthorization(authorizeRequest(), BINDING), { code: 'invalid_request' });
  assert.deepEqual(env.store.state.authorizations, {});
  const session = await env.session();
  const grant = await env.code();
  env.onJwks = () => { env.store.state = initialIssuerState(); env.onJwks = undefined; };
  expectError(await env.exchange(session.session_id, grant), 'invalid_grant');
  assert.deepEqual([env.store.state.grants, env.store.state.sessions], [{}, {}]);
});
