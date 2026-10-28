import type {Environment,Reply} from './issuer-support.mjs';
import type {ReferenceIssuerOptions} from '../../dist/reference-auth/index.js';
import { expectValue } from '../../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateJwkThumbprint } from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import { AuthorizationError, initialIssuerState } from '../../dist/reference-auth/index.js';
import { NOW, keyPair } from './support.mjs';
import { CLIENT, ISSUER, OTHER_CLIENT, REDIRECT, RESOURCE, expectError, setup } from './issuer-support.mjs';

const BINDING = 'browser-binding-0123456789abcdef';
const DAY = 86_400_000;
const REVOKE = `${ISSUER}/oauth/revoke`;

test('Direct codes bind the intended key before exchange or replay revocation; old pending codes fail closed', async () => {
  const env = await setup({ requireDpopNonce: false }); await env.send();
  const key = await calculateJwkThumbprint(env.dpopKey.jwk), other = await keyPair();
  await env.send({ assertion: await env.assertion({ sub: 'usr_other' }) }, { dpop: await env.proof({ key: other }) });
  const { verifier, challenge } = pkce();
  for (const dpop_jkt of [undefined, '', 'short', 'x'.repeat(44), '+'.repeat(43)]) await assert.rejects(env.issuer.beginAuthorization(authorizeRequest({ dpop_jkt }), BINDING), { code: 'invalid_request' });
  const view = await env.issuer.beginAuthorization(authorizeRequest({ code_challenge: challenge, dpop_jkt: key }), BINDING);
  const decision = { accountId: 'acct', scopes: ['orders:read'] };
  const callback = await env.issuer.completeAuthorization(view.id, BINDING, decision);
  assert.equal((await env.issuer.completeAuthorization(view.id, BINDING, decision)).href, callback.href, 'lost consent response returns the same code');
  const fields = { grant_type: 'authorization_code', assertion: undefined, code: callback.searchParams.get('code')!, redirect_uri: REDIRECT, code_verifier: verifier };
  expectError(await env.send(fields, { dpop: await env.proof({ key: other }) }), 'invalid_grant');
  expectError(await env.send({ ...fields, code_verifier: pkce().verifier }), 'invalid_grant');
  expectError(await env.send({ ...fields, redirect_uri: REDIRECT + '?wrong=1' }), 'invalid_grant');
  const signed = await env.send(fields); assert.equal(signed.status, 200); assert.equal(signed.body.scope, 'orders:read');
  expectError(await env.send(fields, { dpop: await env.proof({ key: other }) }), 'invalid_grant');
  assert.equal((await env.issuer.authority.introspect(signed.body.access_token!)).principal.accountId, 'acct');
  expectError(await env.send(fields), 'invalid_grant');
  await assert.rejects(env.issuer.authority.introspect(signed.body.access_token!), { code: 'invalid_token' });
  const old = await env.issuer.beginAuthorization(authorizeRequest({ dpop_jkt: key }), BINDING);
  delete (env.store.state.authorizations[old.id] as Partial<typeof env.store.state.authorizations[string]>).sessionKey;
  await assert.rejects(env.issuer.completeAuthorization(old.id, BINDING, decision), { code: 'invalid_request' });
});

test('Direct loopback registration permits port variation but exchange requires the authorization redirect exactly', async () => {
  for (const host of ['127.0.0.1', '[::1]']) {
    const env = await setup({ requireDpopNonce: false }); await env.send();
    const registered = `http://${host}:8000/cb?route=fixed`, actual = registered.replace(':8000', ':49152');
    const resolve = env.metadata.resolveClient;
    env.metadata.resolveClient = async id => ({ ...await resolve(id), redirect_uris: [registered] });
    const { verifier, challenge } = pkce(), key = await calculateJwkThumbprint(env.dpopKey.jwk);
    const view = await env.issuer.beginAuthorization(authorizeRequest({ redirect_uri: actual, code_challenge: challenge, dpop_jkt: key }), BINDING);
    const callback = await env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct', scopes: ['orders:read'] });
    assert.equal(callback.port, '49152'); assert.equal(callback.searchParams.get('route'), 'fixed');
    const fields = { grant_type: 'authorization_code', assertion: undefined, code: callback.searchParams.get('code')!, code_verifier: verifier };
    expectError(await env.send({ ...fields, redirect_uri: registered }), 'invalid_grant');
    assert.equal((await env.send({ ...fields, redirect_uri: actual })).status, 200);
    for (const redirect_uri of [actual.replace('route=fixed', 'route=other'), actual.replace('/cb', '/other'), 'http://localhost:49152/cb?route=fixed']) await assert.rejects(env.issuer.beginAuthorization(authorizeRequest({ redirect_uri, dpop_jkt: key }), BINDING), { code: 'invalid_request' });
  }
});

test('key-selected sign-in and refresh preserve ownership, sticky accounts and revocation', async () => {
  const env = await setup({ requireDpopNonce: false });
  const started = await env.send(), id = (await env.issuer.authority.introspect(expectValue(started.body.access_token))).principal.sessionId;
  const consent = async (accountId: string) => {
    const { verifier, challenge } = pkce();
    const view = await env.issuer.beginAuthorization(authorizeRequest({ code_challenge: challenge, dpop_jkt: await calculateJwkThumbprint(env.dpopKey.jwk) }), BINDING);
    const callback = await env.issuer.completeAuthorization(view.id, BINDING, { accountId, scopes: ['orders:read'] });
    return env.send({ grant_type: 'authorization_code', assertion: undefined, code: callback.searchParams.get('code')!, redirect_uri: REDIRECT, code_verifier: verifier });
  };
  const signed = await consent('account-one'); assert.equal(signed.status, 200);
  assert.deepEqual(Object.keys(signed.body).sort(), ['access_token', 'expires_in', 'refresh_token', 'refresh_token_expires_in', 'scope', 'token_type']);
  const refresh = (token: string, dpop?: string) => env.send({ grant_type: 'refresh_token', assertion: undefined, refresh_token: token }, { dpop });
  const foreign = await keyPair();
  assert.equal((await env.send({ assertion: await env.assertion({ sub: 'usr_foreign' }) }, { dpop: await env.proof({ key: foreign }) })).status, 200);
  expectError(await refresh(expectValue(signed.body.refresh_token), await env.proof({ key: foreign })), 'invalid_grant');
  const renewed = await refresh(expectValue(signed.body.refresh_token)); assert.equal(renewed.status, 200);
  assert.notEqual(renewed.body.refresh_token, signed.body.refresh_token);
  const principal = (await env.issuer.authority.introspect(expectValue(renewed.body.access_token))).principal;
  assert.deepEqual([principal.sessionId, principal.userId, principal.accountId, principal.scopes], [id, 'usr_1', 'account-one', ['orders:read']]);
  expectError(await consent('account-two'), 'account_mismatch');
  const revoked = await env.issuer.revoke(new Request(REVOKE, { method: 'POST', body: new URLSearchParams({ token: expectValue(renewed.body.refresh_token), client_id: CLIENT, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await env.clientAssertion() }) }));
  assert.equal(revoked.status, 200);
  await assert.rejects(env.issuer.authority.introspect(expectValue(renewed.body.access_token)), { code: 'invalid_token' });
  const signedOut = await env.send(); assert.equal(signedOut.status, 200);
  assert.equal((await env.issuer.authority.introspect(expectValue(signedOut.body.access_token))).principal.sessionId, id);
  expectError(await refresh(expectValue(renewed.body.refresh_token)), 'invalid_grant');
  expectError(await consent('account-two'), 'account_mismatch');
});

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}
function authorizeRequest(params:Record<string,string|undefined> = {}) {
  const url = new URL(`${ISSUER}/oauth/authorize`);
  const query = { response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'orders:read orders:write', state: 'state-1', code_challenge: pkce().challenge, code_challenge_method: 'S256', dpop_jkt: 'k'.repeat(43), ...params };
  for (const [name, value] of Object.entries(query)) if (value !== undefined) url.searchParams.set(name, value);
  return new Request(url);
}

type Fields=Record<string,string|undefined>;
type ConsentOptions={accountId?:string;scopes?:string[];params?:Fields};
type Code={code:string;verifier:string;url:URL;view:Awaited<ReturnType<Environment['issuer']['beginAuthorization']>>};
async function signInSetup(overrides:Partial<ReferenceIssuerOptions>={}) {
  let activeKey: Awaited<ReturnType<typeof keyPair>>;
  const keys = new Map<string, Awaited<ReturnType<typeof keyPair>>>();
  async function session(fields:Fields={}) { activeKey=await keyPair();const reply=await env.send(fields);if(reply.sessionId)keys.set(reply.sessionId,activeKey);return {...reply.body,sessionId:reply.sessionId,reply}; }
  async function code({accountId='acct_1',scopes,params}:ConsentOptions={}):Promise<Code>{
    const {verifier,challenge}=pkce();
    const view=await env.issuer.beginAuthorization(authorizeRequest({code_challenge:challenge,dpop_jkt:await calculateJwkThumbprint(activeKey.jwk),...params}),BINDING);
    const url=await env.issuer.completeAuthorization(view.id,BINDING,{accountId,scopes:scopes??view.scopes});
    const code=url.searchParams.get('code');assert.ok(code);return {code,verifier,url,view};
  }
  function exchange(sessionId:string|undefined,{code,verifier}:{code:string|null;verifier:string},fields:Fields={}):Promise<Reply>{ activeKey=keys.get(sessionId??'')??activeKey;return env.send({grant_type:'authorization_code',assertion:undefined,code:expectValue(code),redirect_uri:REDIRECT,code_verifier:verifier,...fields});}
  async function signIn(sessionId:string|undefined,options?:ConsentOptions):Promise<Reply>{activeKey=keys.get(sessionId??'')??activeKey;return env.exchange(sessionId,await env.code(options));}
  async function refresh(refresh_token:string|undefined,fields:Fields={}):Promise<Reply>{const {session_id,...wire}=fields;activeKey=session_id?keys.get(session_id)!:await keyPair();const reply=await env.send({grant_type:'refresh_token',assertion:undefined,refresh_token,...wire});if(reply.sessionId)keys.set(reply.sessionId,activeKey);return reply;}
  async function revoke(token:string|undefined,fields:Fields={}):Promise<{status:number;headers:Headers;text:string}>{
    const form={token,token_type_hint:'refresh_token',client_id:CLIENT,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await env.clientAssertion(),...fields};
    const body=new URLSearchParams(Object.entries(form).filter((entry):entry is [string,string]=>entry[1]!==undefined));
    const response=await env.issuer.revoke(new Request(REVOKE,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body}));
    return {status:response.status,headers:response.headers,text:await response.text()};
  }
  function introspect(token:string|undefined):ReturnType<Environment['issuer']['authority']['introspect']>{return env.issuer.authority.introspect(expectValue(token));}
  const env=Object.assign(await setup({requireDpopNonce:false,...overrides}),{session,code,exchange,signIn,refresh,revoke,introspect,selectSession:(id:string|undefined)=>{activeKey=keys.get(id??'')!;return env.send();}});
  activeKey=env.dpopKey;const proof=env.proof;env.proof=options=>proof({key:activeKey,...options});
  const begin=env.issuer.beginAuthorization;
  env.issuer.beginAuthorization=async(request,binding)=>{const url=new URL(request.url);if(url.searchParams.get('dpop_jkt')==='k'.repeat(43))url.searchParams.set('dpop_jkt',await calculateJwkThumbprint(activeKey.jwk));return begin(new Request(url,request),binding);};
  return env;
}

test('Direct Sign-In signs in the Session with an Account Token; partial consent narrows the scopes', async () => {
  const env = await signInSetup();
  const signedOut = await env.session();
  const { verifier, challenge } = pkce();
  const view = await env.issuer.beginAuthorization(authorizeRequest({ code_challenge: challenge, resource: RESOURCE }), BINDING);
  assert.deepEqual({ ...view, id: undefined }, { id: undefined, clientId: CLIENT, clientName: 'Agent', scopes: ['orders:read', 'orders:write'], expiresAt: NOW + 600_000 });
  const callback = await env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: ['orders:read'] });
  assert.equal(`${callback.origin}${callback.pathname}`, REDIRECT);
  assert.deepEqual([...callback.searchParams.keys()].sort(), ['code', 'iss', 'state']);
  assert.equal(callback.searchParams.get('state'), 'state-1'); assert.equal(callback.searchParams.get('iss'), ISSUER);
  const code = callback.searchParams.get('code');

  const response = await env.exchange(signedOut.sessionId, { code, verifier }, { resource: RESOURCE });
  assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Object.keys(response.body).sort(), ['access_token', 'expires_in', 'refresh_token', 'refresh_token_expires_in', 'scope', 'token_type']);
  assert.deepEqual([response.body.scope, response.sessionId, response.signedIn, response.body.token_type, response.body.refresh_token_expires_in], ['orders:read', signedOut.sessionId, true, 'DPoP', 2_592_000]);
  const persisted = JSON.stringify(env.store.state);
  for (const secret of [code, response.body.refresh_token, response.body.access_token, verifier, BINDING]) assert.ok(!persisted.includes(expectValue(secret)), 'secrets are stored only as hashes');

  const { principal } = await env.issuer.authority.introspect(expectValue(response.body.access_token), RESOURCE);
  const [grantId] = Object.keys(env.store.state.grants);
  assert.deepEqual(principal, { issuer: ISSUER, clientId: CLIENT, userId: 'usr_1', sessionId: signedOut.sessionId, accountId: 'acct_1', grantId, scopes: ['orders:read'], tokenExpiresAt: NOW + 3_600_000, sessionVersion: 1, issuerGeneration: env.store.state.generation });
  // The grant lasts the account sign-in lifetime, not the access-token lifetime.
  assert.equal(env.store.state.grants[grantId].expiresAt, NOW + 30 * DAY);
  assert.equal(await env.issuer.authority.policy.withCurrent(principal, ['orders:read'], async () => 'read'), 'read');
  // The earlier signed-out token stays signed out.
  const before = await env.introspect(signedOut.access_token);
  assert.equal(before.principal.accountId, undefined); assert.deepEqual(before.principal.scopes, []);
  // A signed-in Session is renewed with its Account Token, not the signed-out assertion.
  expectError(await env.send(), 'invalid_grant');

  const metadata = (await setup({ authorizationEndpoint: `${ISSUER}/oauth/authorize` })).issuer.authorizationMetadata();
  assert.equal(metadata.authorization_endpoint, `${ISSUER}/oauth/authorize`);
  assert.deepEqual([metadata.response_types_supported, metadata.code_challenge_methods_supported], [['code'], ['S256']]);
});

test('Direct pending consent retains its account revocation snapshot without affecting other accounts', async () => {
  const env = await signInSetup();
  const a = await env.issuer.beginAuthorization(authorizeRequest(), BINDING), b = await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  await env.issuer.disconnect(CLIENT, 'acct_A');
  await assert.rejects(env.issuer.completeAuthorization(a.id, BINDING, { accountId: 'acct_A', scopes: ['orders:read'] }), { code: 'invalid_request' });
  const callback = await env.issuer.completeAuthorization(b.id, BINDING, { accountId: 'acct_B', scopes: ['orders:read'] });
  assert.ok(callback.searchParams.get('code'));
  assert.ok((await env.code({ accountId: 'acct_A' })).code, 'fresh explicit consent is allowed');
});

test('an authorization code works once; its reuse revokes the sign-in it produced', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const grant = await env.code();
  const first = await env.exchange(session.sessionId, grant);
  assert.equal(first.status, 200);
  const second = await env.session();
  expectError(await env.exchange(session.sessionId, grant), 'invalid_grant');
  expectError(await env.refresh(first.body.refresh_token), 'invalid_grant');
  await assert.rejects(env.introspect(first.body.access_token), { code: 'invalid_token' });
  assert.equal(env.store.state.sessions[expectValue(session.sessionId)].grantId, null, 'the Session was signed out');
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
  for (const [name, fields] of Object.entries(cases)) await assert.doesNotReject(async () => expectError(await env.exchange(session.sessionId, grant, fields), 'invalid_grant'), name);
  for (const name of ['code', 'redirect_uri', 'code_verifier']) expectError(await env.exchange(session.sessionId, grant, { [name]: undefined }), 'invalid_request');
  for (const code_verifier of ['a'.repeat(42), 'a'.repeat(129), `${'a'.repeat(42)}+`, `${'a'.repeat(42)} `]) expectError(await env.exchange(session.sessionId, grant, { code_verifier }), 'invalid_request');
  expectError(await env.exchange(session.sessionId, grant, { session_id: 'ses_missing' }), 'invalid_request');
  expectError(await env.exchange(session.sessionId, grant, { scope: 'poppy:admin' }), 'invalid_scope');
  assert.deepEqual(env.store.state.grants, {}, 'no failed exchange created a grant');
  assert.equal((await env.exchange(session.sessionId, grant)).status, 200, 'the genuine exchange still succeeds');

  const late = await env.code();
  env.clock.now += 61_000;
  expectError(await env.exchange((await env.session()).sessionId, late), 'invalid_grant');
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
    invalid_scope: { scope: 'orders:read poppy:admin' },
    emptyScope: { scope: ' ' },
    invalid_target: { resource: 'https://api.shop.test/other' },
  };
  const codes:Record<string,string> = { plainPkce: 'invalid_request', noPkce: 'invalid_request', shortChallenge: 'invalid_request', emptyScope: 'invalid_scope' };
  for (const [name, params] of Object.entries(redirected)) {
    const error = await env.issuer.beginAuthorization(authorizeRequest(params), BINDING).catch(error => error);
    assert.ok(error instanceof AuthorizationError, name);
    assert.equal(error.code, codes[name] ?? name, name);
    assert.equal(`${expectValue(error.redirectTo).origin}${expectValue(error.redirectTo).pathname}`, REDIRECT, name);
    assert.equal(expectValue(error.redirectTo).searchParams.get('error'), error.code, name);
    assert.equal(expectValue(error.redirectTo).searchParams.get('iss'), ISSUER, name);
    assert.equal(expectValue(error.redirectTo).searchParams.get('state'), ('state' in params?params.state:undefined) === undefined && 'state' in params ? null : 'state-1', name);
  }
  const duplicate = new Request(`${authorizeRequest().url}&scope=orders:read`);
  assert.equal((await env.issuer.beginAuthorization(duplicate, BINDING).catch(error => error)).code, 'invalid_request');
  await assert.rejects(env.issuer.beginAuthorization(authorizeRequest(), ''), TypeError);
  assert.deepEqual(env.store.state.authorizations, {}, 'nothing was persisted');
});

test('completeAuthorization checks the browser binding, consumes once, and never grants beyond the request', async () => {
  const env = await signInSetup();
  const view = await env.issuer.beginAuthorization(authorizeRequest({ scope: 'orders:read' }), BINDING);
  await assert.rejects(env.issuer.completeAuthorization(view.id, 'another-browser-binding', { denied: true }), AuthorizationError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, 'another-browser-binding', { accountId: 'acct_1', scopes: ['orders:read'] }), AuthorizationError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: ['orders:write'] }), TypeError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: '', scopes: ['orders:read'] }), TypeError);
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: [] }), TypeError);
  const denied = await env.issuer.completeAuthorization(view.id, BINDING, { denied: true });
  assert.deepEqual(Object.fromEntries(denied.searchParams), { error: 'access_denied', state: 'state-1', iss: ISSUER });
  await assert.rejects(env.issuer.completeAuthorization(view.id, BINDING, { accountId: 'acct_1', scopes: ['orders:read'] }), { code: 'invalid_request' });
  await assert.rejects(env.issuer.completeAuthorization('__proto__', BINDING, { denied: true }), AuthorizationError);
  assert.deepEqual(env.store.state.codes, {});

  const expiring = await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  env.clock.now += 600_000;
  await assert.rejects(env.issuer.completeAuthorization(expiring.id, BINDING, { accountId: 'acct_1', scopes: ['orders:read'] }), AuthorizationError);
});

test('a Session keeps its first account: another account gets account_mismatch and no tokens', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const first = await env.signIn(session.sessionId);
  assert.equal(first.status, 200);
  assert.equal((await env.revoke(first.body.refresh_token)).status, 200);
  // Signed out, but still bound to acct_1.
  assert.equal((await env.send()).status, 200);
  const before = structuredClone(env.store.state.accessTokens);
  expectError(await env.signIn(session.sessionId, { accountId: 'acct_2' }), 'account_mismatch');
  const elsewhere = await env.signIn((await env.session()).sessionId, { accountId: 'acct_2' });
  assert.equal(elsewhere.status, 200);
  const count = Object.keys(env.store.state.accessTokens).length;
  expectError(await env.refresh(elsewhere.body.refresh_token, { session_id: session.sessionId }), 'account_mismatch');
  assert.equal(Object.keys(env.store.state.accessTokens).length, count, 'no tokens issued');
  assert.ok(Object.keys(before).every(key => key in env.store.state.accessTokens));
  // The same account signs in again on the same Session.
  const again = await env.signIn(session.sessionId);
  assert.equal(again.status, 200); assert.equal(again.sessionId, session.sessionId);
});

test('refresh rotates the Account Token under a stable lineage without extending it; a rotated token is dead', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const signedIn = await env.signIn(session.sessionId);
  const [grantId] = Object.keys(env.store.state.grants);
  env.clock.now += DAY / 2;
  const rotated = await env.refresh(signedIn.body.refresh_token, { session_id: session.sessionId, scope: 'orders:read' });
  assert.equal(rotated.status, 200);
  assert.notEqual(rotated.body.refresh_token, signedIn.body.refresh_token);
  assert.deepEqual([rotated.body.scope, rotated.signedIn, rotated.body.refresh_token_expires_in], ['orders:read', true, 2_592_000 - 43_200]);
  assert.deepEqual(Object.keys(env.store.state.grants), [grantId]);
  assert.equal((await env.introspect(rotated.body.access_token)).principal.grantId, grantId);

  // Without session_id a new signed-in Session starts; resources are chosen per request, not fixed by the grant.
  const fresh = await env.refresh(rotated.body.refresh_token, { resource: RESOURCE });
  assert.equal(fresh.status, 200); assert.notEqual(fresh.sessionId, session.sessionId);
  assert.equal(fresh.body.scope, 'orders:read orders:write', 'an earlier narrow request does not narrow the grant');
  assert.equal((await env.issuer.authority.introspect(expectValue(fresh.body.access_token), RESOURCE)).principal.accountId, 'acct_1');
  const general = await env.refresh(fresh.body.refresh_token, { session_id: fresh.sessionId });
  assert.equal(general.status, 200); assert.equal((await env.introspect(general.body.access_token)).principal.accountId, 'acct_1');

  expectError(await env.refresh(general.body.refresh_token, { scope: 'orders:read poppy:admin' }), 'invalid_scope');
  expectError(await env.refresh(general.body.refresh_token, { scope: '' }), 'invalid_scope');
  expectError(await env.refresh(general.body.refresh_token, { resource: 'https://api.shop.test/other' }), 'invalid_target');
  const otherUser = await env.session({ assertion: await env.assertion({ sub: 'usr_2' }) });
  expectError(await env.refresh(general.body.refresh_token, { session_id: otherUser.sessionId }), 'invalid_grant');
  expectError(await env.refresh(general.body.refresh_token, { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }) }), 'invalid_grant');
  expectError(await env.refresh(undefined), 'invalid_request');

  // Concurrent use of one Account Token: exactly one successor, and the loser's reuse revokes the lineage.
  const results = await Promise.all([env.refresh(general.body.refresh_token), env.refresh(general.body.refresh_token)]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 400]);
  const winner = expectValue(results.find((result: { status: number; }) => result.status === 200)).body;
  expectError(await env.refresh(winner.refresh_token), 'invalid_grant');
  await assert.rejects(env.introspect(winner.access_token), { code: 'invalid_token' });

  // A lineage ends at its original expiry however often it rotates.
  const later = await env.signIn((await env.session()).sessionId);
  env.clock.now += 29 * DAY;
  const step = await env.refresh(later.body.refresh_token);
  assert.equal(step.body.refresh_token_expires_in, 86_400);
  env.clock.now += DAY;
  expectError(await env.refresh(step.body.refresh_token), 'invalid_grant');
});

test('revocation signs out the lineage; a rotated token revokes it too; unknown and foreign tokens change nothing', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const signedIn = await env.signIn(session.sessionId);
  const rotated = await env.refresh(signedIn.body.refresh_token, { session_id: session.sessionId });
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
  const renewed = await env.selectSession(session.sessionId);
  assert.equal(renewed.status, 200); assert.equal(renewed.signedIn, false, 'the Session continues signed out');
  assert.equal((await env.revoke(rotated.body.refresh_token)).status, 200, 'revoking again is harmless');
});

test('disconnect revokes the account sign-ins of that client and signs out their Sessions', async () => {
  const env = await signInSetup();
  const one = await env.session(); const two = await env.session();
  const a = await env.signIn(one.sessionId);
  const b = await env.signIn(two.sessionId, { accountId: 'acct_2' });
  await env.issuer.disconnect(CLIENT, 'acct_1');
  assert.equal(env.store.state.sessions[expectValue(one.sessionId)].grantId, null);
  assert.equal(env.store.state.sessions[expectValue(one.sessionId)].accountId, 'acct_1');
  await assert.rejects(env.introspect(a.body.access_token), { code: 'invalid_token' });
  expectError(await env.refresh(a.body.refresh_token), 'invalid_grant');
  assert.equal((await env.introspect(b.body.access_token)).principal.accountId, 'acct_2');
  assert.equal((await env.refresh(b.body.refresh_token)).status, 200);
});

test('disconnect deletes the unredeemed codes of that client and account; other accounts and clients keep theirs', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const mine = await env.code();
  const otherAccount = await env.code({ accountId: 'acct_2' });
  const otherClient = await env.code({ params: { client_id: OTHER_CLIENT } });
  await env.issuer.disconnect(CLIENT, 'acct_1');
  assert.equal(Object.keys(env.store.state.codes).length, 2);
  expectError(await env.exchange(session.sessionId, mine), 'invalid_grant');
  assert.deepEqual(env.store.state.grants, {}, 'no sign-in was created from the deleted code');
  assert.equal((await env.exchange(session.sessionId, otherAccount)).status, 200);
  assert.equal(expectValue(Object.values(env.store.state.codes).find(code => code.clientId === OTHER_CLIENT)).accountId, 'acct_1');
});

test('Sessions end after a day without tokens and expired records are pruned', async () => {
  const env = await signInSetup();
  const idle = await env.session();
  const kept = await env.session();
  await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  const unused = await env.code();
  const signedIn = await env.signIn(kept.sessionId);
  env.clock.now += DAY - 1000;
  assert.equal((await env.refresh(signedIn.body.refresh_token, { session_id: kept.sessionId })).status, 200);
  env.clock.now += 1000;
  expectError(await env.selectSession(idle.sessionId), 'invalid_grant');
  await assert.rejects(env.introspect(idle.access_token), { code: 'invalid_token' });
  // A failed request rolls back; the next successful commit prunes.
  const later = await env.session();
  const state = env.store.state;
  assert.deepEqual(Object.keys(state.sessions).sort(), [kept.sessionId, later.sessionId].sort());
  assert.deepEqual([state.authorizations, state.codes], [{}, {}]);
  assert.ok(Object.values(state.accessTokens).every(record => record.expiresAt > env.clock.now));
  expectError(await env.exchange(kept.sessionId, unused), 'invalid_grant');
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
  expectError(await env.exchange(session.sessionId, grant), 'invalid_grant');
  assert.deepEqual([env.store.state.grants, env.store.state.sessions], [{}, {}]);
});

test('the grant type alone picks the branch: a stray assertion never substitutes for a code or Account Token', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const grant = await env.code();
  expectError(await env.refresh('bogus', { assertion: await env.assertion() }), 'invalid_request');
  expectError(await env.refresh('bogus', { assertion: await env.assertion(), session_id: session.sessionId }), 'invalid_request');
  expectError(await env.exchange(session.sessionId, grant, { assertion: await env.assertion() }), 'invalid_request');
  expectError(await env.send({ assertion: undefined }), 'invalid_grant');
  assert.equal(Object.keys(env.store.state.accessTokens).length, 1, 'only the first signed-out token was issued');
  assert.equal((await env.exchange(session.sessionId, grant)).status, 200, 'the code was not consumed');
});

test('pending authorizations are capped until older ones expire', async () => {
  const env = await signInSetup({ maxPendingAuthorizations: 2 });
  await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  env.clock.now += 300_000;
  const second = await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  const refused = await env.issuer.beginAuthorization(authorizeRequest(), BINDING).catch(error => error);
  assert.ok(refused instanceof AuthorizationError);
  assert.equal(refused.code, 'temporarily_unavailable');
  assert.deepEqual(Object.fromEntries(expectValue(refused.redirectTo).searchParams), { error: 'temporarily_unavailable', state: 'state-1', iss: ISSUER });
  assert.equal(Object.keys(env.store.state.authorizations).length, 2);
  // Completing one frees a slot; so does expiry.
  await env.issuer.completeAuthorization(second.id, BINDING, { denied: true });
  await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  await assert.rejects(env.issuer.beginAuthorization(authorizeRequest(), BINDING), { code: 'temporarily_unavailable' });
  env.clock.now += 300_000;
  await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  await assert.rejects(setup({ maxPendingAuthorizations: 0 }), TypeError);
});

test('per-client caps: one client filling its share leaves pending authorizations and Sessions for others', async () => {
  const env = await signInSetup({ maxPendingAuthorizationsPerClient: 2, maxSessionsPerClient: 2 });
  await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  await env.issuer.beginAuthorization(authorizeRequest(), BINDING);
  await assert.rejects(env.issuer.beginAuthorization(authorizeRequest(), BINDING), { code: 'temporarily_unavailable' });
  await env.issuer.beginAuthorization(authorizeRequest({ client_id: OTHER_CLIENT }), BINDING);

  const first = await env.session();
  env.clock.now += 60_000;
  const second = await env.session();
  const refused = await env.session();
  assert.deepEqual([refused.reply.status, refused.reply.body, refused.reply.headers.get('retry-after')], [429, { error: 'rate_limited' }, String(DAY / 1000 - 60)]);
  assert.equal(Object.keys(env.store.state.sessions).length, 2);
  const other = { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }), assertion: await env.assertion({ iss: OTHER_CLIENT }) };
  assert.equal((await env.send(other)).status, 200);
  // Renewing an existing Session is never refused, and a Session ending frees a slot.
  assert.equal((await env.selectSession(second.sessionId)).status, 200);
  env.clock.now += DAY - 60_000;
  assert.equal((await env.send()).status, 200, `${first.sessionId} ended`);
  await assert.rejects(setup({ maxSessionsPerClient: 0 }), TypeError);
  await assert.rejects(setup({ maxPendingAuthorizationsPerClient: 1.5 }), TypeError);
});

test('a rate_limited Session request rolls back: the same assertions and proof succeed once a slot frees', async () => {
  const env = await signInSetup({ maxSessionsPerClient: 1 });
  const first = await env.session();
  const fields = { assertion: await env.assertion(), client_assertion: await env.clientAssertion() };
  const dpop = await env.proof({key:await keyPair()});
  expectError(await env.send(fields, { dpop }), 'rate_limited', 429);
  delete env.store.state.sessions[expectValue(first.sessionId)]; // the Session ends
  assert.equal((await env.send(fields, { dpop })).status, 200, 'no jti was consumed by the refused request');
  expectError(await env.send(fields, { dpop }), 'invalid_grant'); // the accepted request did consume them
});

test('every Account Token ancestor remains replay-detectable until fixed grant expiry', async () => {
  const env = await signInSetup();
  let token = (await env.signIn((await env.session()).sessionId)).body.refresh_token;
  const first = token;
  for (let i = 0; i < 5; i++) token = (await env.refresh(token)).body.refresh_token;
  assert.equal(Object.keys(env.store.state.refreshTokens).length, 6);
  expectError(await env.refresh(first), 'invalid_grant');
  assert.equal((await env.revoke(first)).status, 200);
  expectError(await env.refresh(token), 'invalid_grant');
});

test('issuer state of another version is refused, not misread', async () => {
  const env = await signInSetup();
  const session = await env.session();
  Object.assign(env.store.state,{version:1});
  await assert.rejects(env.selectSession(session.sessionId), /unsupported issuer state version/);
  await assert.rejects(env.introspect(session.access_token), /unsupported issuer state version/);
  await assert.rejects(env.issuer.disconnect(CLIENT, 'acct_1'), /unsupported issuer state version/);
  await assert.rejects(env.issuer.beginAuthorization(authorizeRequest(), BINDING), /unsupported issuer state version/);
});

test('retrying the previous Account Token after a lost rotation response signs the Session out', async () => {
  const env = await signInSetup();
  const session = await env.session();
  const t1 = (await env.signIn(session.sessionId)).body.refresh_token;
  const lost = await env.refresh(t1, { session_id: session.sessionId }); // the response never reaches the client
  assert.equal(lost.status, 200);
  expectError(await env.refresh(t1, { session_id: session.sessionId }), 'invalid_grant');
  const renewed = await env.selectSession(session.sessionId);
  assert.equal(renewed.status, 200); assert.equal(renewed.signedIn, false);
  expectError(await env.refresh(lost.body.refresh_token), 'invalid_grant');
  await assert.rejects(env.introspect(lost.body.access_token), { code: 'invalid_token' });
  // Another client presenting the token changes nothing.
  const t3 = (await env.signIn((await env.session()).sessionId)).body.refresh_token;
  const t4 = (await env.refresh(t3)).body.refresh_token;
  expectError(await env.refresh(t3, { client_id: OTHER_CLIENT, client_assertion: await env.clientAssertion({ iss: OTHER_CLIENT, sub: OTHER_CLIENT }) }), 'invalid_grant');
  assert.equal((await env.refresh(t4)).status, 200);
});
