import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, calculateJwkThumbprint, CompactSign } from 'jose';
import { sessionJwt } from './support.mjs';
import { setup as referenceSetup, ISSUER, API, CLIENT } from './issuer-support.mjs';
import type { CompactJWSHeaderParameters } from 'jose';
import { createSessionAuthority, createRequestAuthenticator, createConversationService, AuthorityError } from '../../dist/index.js';
import type { Principal, AuthorityPolicy } from '../../dist/index.js';
import { SqliteCompanyDatabase } from '../../dist/sqlite.js';
import { PostgresCompanyDatabase } from '../../dist/postgres.js';
import { testPool } from '../../test-support/postgres.mjs';

for (const engine of ['SQLite', ...(process.env.D1_POSTGRES === '1' ? ['Postgres'] : [])]) {
  test(`independent Session identity and account authority survive restart (${engine})`, async t => {
    const dir = await mkdtemp(join(tmpdir(), 'poppy-session-')), path = join(dir, 'sessions.db'), namespace = `https://${randomUUID()}.company.example`;
    const pool = engine === 'Postgres' ? testPool() : undefined;
    const open = () => pool ? new PostgresCompanyDatabase(pool) : new SqliteCompanyDatabase(path);
    const handles = [open(), open()];
    t.after(async () => { for (const db of handles) await db.close(); await pool?.end(); await rm(dir, { recursive: true, force: true }); });
    const root = await generateKeyPair('ES256'), rootJwk = { ...await exportJWK(root.publicKey), kid: 'independent-root' };
    const clientId = 'https://independent.example/client.json', endpoint = 'https://resource.example/orders';
    let at = 1790900000000, revoked = false;
    const metadata = {
      async resolveCompany(): Promise<never> { throw new Error('Sessions do not require an issuer'); },
      async resolveClient(id: string) { assert.equal(id, clientId); return {client_id:clientId,client_name:'Independent peer',jwks_uri:'https://independent.example/jwks',token_endpoint_auth_method:'private_key_jwt' as const}; },
      async resolveJwks() { return {keys:[rootJwk]}; },
    };
    const accountPolicy: AuthorityPolicy = {
      async withCurrent(principal, scopes, action) { if(revoked)throw new AuthorityError('invalid_token'); assert.ok(scopes.every(scope=>principal.scopes.includes(scope)));return action(); },
      async withAccepted(accepted, _scopes, action) { if(revoked && accepted.revocationPolicy!=='allow-accepted-work-to-finish')throw new AuthorityError('invalid_token');return action(); },
    };
    const sessionsFor = (db: typeof handles[number]) => createSessionAuthority({companyId:namespace,metadata,store:db.sessions(namespace),coordinator:db,now:()=>at,accountPolicy});
    const sessions = sessionsFor(handles[0]!);
    const account: Principal = {issuer:namespace,clientId,userId:'oauth-sub-is-not-the-poppy-user',sessionId:'oauth-session-is-ignored',accountId:'account-a',grantId:'grant-a',scopes:['orders:read'],tokenExpiresAt:at+3600000,sessionVersion:0};
    const authenticator = createRequestAuthenticator({sessions,authority:{async introspect(token){if(token!=='account-token'||revoked)throw new AuthorityError('invalid_token');return {principal:account,dpopJkt:null};}},endpoints:[{origin:'https://resource.example',pathPrefix:'/orders'}],now:()=>at});
    const sign = (claims:Record<string,unknown>, header:CompactJWSHeaderParameters, key:CryptoKey) => new CompactSign(new TextEncoder().encode(JSON.stringify(claims))).setProtectedHeader(header).sign(key);
    const jwt = async (sid='session_a', sub='pairwise-user', token?:string, agentId?:string) => {
      const delegated=await generateKeyPair('ES256'),jwk=await exportJWK(delegated.publicKey),iat=Math.floor(at/1000);
      const delegation=await sign({iss:clientId,cnf:{jwk},iat,exp:iat+3600,jti:randomUUID()},{alg:'ES256',typ:'pap-delegation+jwt',kid:'independent-root'},root.privateKey);
      return sign({iss:clientId,aud:namespace,sid,sub,htm:'POST',htu:endpoint,iat,jti:randomUUID(),...(agentId?{agent_id:agentId}:{}),...(token?{ath:createHash('sha256').update(token).digest('base64url')}: {})}, {alg:'ES256',typ:'poppy-session+jwt',kid:await calculateJwkThumbprint(jwk),pap_dlg:delegation},delegated.privateKey);
    };
    const request = async (sid='session_a',sub='pairwise-user',token?:string,agentId?:string) => new Request(endpoint,{method:'POST',headers:{'poppy-session':await jwt(sid,sub,token,agentId),...(token?{authorization:`Bearer ${token}`}:{})}});
    const mcpResource=endpoint+'?tenant=a';
    const mcp=createRequestAuthenticator({sessions,authority:{async introspect(){return {principal:account,dpopJkt:null};}},endpoints:[{origin:'https://resource.example',pathPrefix:'/orders',resource:mcpResource,mcp:{dpop:false,metadataUrl:'https://resource.example/.well-known/oauth-protected-resource/orders?tenant=a'}}],now:()=>at});
    const ordinary=new Request(mcpResource,{method:'POST',headers:{authorization:'Bearer account-token'}});
    const ordinaryPrincipal=await mcp.authenticate(ordinary);assert.equal(ordinaryPrincipal.accountId,'account-a');assert.equal(ordinaryPrincipal.sessionId,'');
    for(const url of [endpoint,endpoint+'?tenant=b',endpoint+'/other?tenant=a'])await assert.rejects(mcp.authenticate(new Request(url,{headers:ordinary.headers})),{code:'invalid_token'});
    const signedOut=await authenticator.authenticate(await request());
    assert.equal(signedOut.sessionId,'session_a');assert.equal(signedOut.userId,'pairwise-user');assert.equal(signedOut.accountId,undefined);assert.deepEqual(signedOut.scopes,[]);
    const replacement=sessionsFor(handles[1]!);
    assert.equal((await replacement.authenticate(await request())).sessionId,'session_a','a changed delegated key and process handle preserve the Session');
    await assert.rejects(replacement.authenticate(await request('session_a','another-user')),{code:'invalid_session'});
    await assert.rejects(replacement.authenticate(await request('session_a','pairwise-user',undefined,'new-agent')),{code:'invalid_session'});
    const signedIn=await authenticator.authenticate(await request('session_a','pairwise-user','account-token'));
    assert.equal(signedIn.userId,'pairwise-user');assert.equal(signedIn.sessionId,'session_a');assert.equal(signedIn.accountId,'account-a');
    const parallel=await authenticator.authenticate(await request('session_b','pairwise-user','account-token'));
    assert.equal(parallel.accountId,signedIn.accountId,'the same account token works in another Session');
    account.accountId='account-b';await assert.rejects(authenticator.authenticate(await request('session_a','pairwise-user','account-token')),{code:'invalid_session'});account.accountId='account-a';
    const afterSignOut=await authenticator.authenticate(await request());assert.equal(afterSignOut.accountId,undefined);assert.deepEqual(afterSignOut.scopes,[]);
    await assert.rejects(sessions.policy.withCurrent(afterSignOut,['orders:read'],async()=>assert.fail('no account authority')),{code:'account_required'});
    revoked=true;await assert.rejects(sessions.policy.withCurrent(signedIn,['orders:read'],async()=>assert.fail('revoked authority')),{code:'invalid_token'});
    assert.equal((await authenticator.authenticate(await request())).sessionId,'session_a','revocation does not end signed-out continuity');
    await sessions.end(clientId,'session_a');await assert.rejects(replacement.authenticate(await request()),{code:'invalid_session'});
    assert.equal((await replacement.authenticate(await request('new_session'))).userId,'pairwise-user');
    const missing=await assert.rejects(authenticator.authenticate(new Request(endpoint,{method:'POST'})),{code:'invalid_session'});void missing;
    const challenge=new AuthorityError('account_required',{scope:'orders:read'});assert.equal(challenge.status,401);assert.ok(!challenge.headers.get('www-authenticate')?.includes('error='));
    assert.deepEqual(await new AuthorityError('invalid_session').response().json(),{error:'invalid_session'});
    const store=handles[0]!.sessions(namespace);const before=await store.read(clientId,'new_session');
    await assert.rejects(store.transaction(clientId,'new_session',at,state=>{state.record!.userId='not-committed';throw new Error('rollback');}),/rollback/);
    assert.deepEqual(await handles[1]!.sessions(namespace).read(clientId,'new_session'),before);
    const quotaNamespace=namespace+'/quota';
    const quotaFor=(db: typeof handles[number])=>createSessionAuthority({companyId:namespace,metadata,store:db.sessions(quotaNamespace),coordinator:db,now:()=>at,lifetimeSeconds:1,maxSessionsPerClient:1});
    const quota=quotaFor(handles[0]!),quotaPeer=quotaFor(handles[1]!);
    const quotaRequests=await Promise.all([request('quota_a'),request('quota_b')]);
    const racing=await Promise.allSettled([quota.authenticate(quotaRequests[0]!),quotaPeer.authenticate(quotaRequests[1]!)]);
    assert.equal(racing.filter(result=>result.status==='fulfilled').length,1);
    const refusal=racing.find(result=>result.status==='rejected');assert.ok(refusal?.status==='rejected'&&refusal.reason instanceof AuthorityError);assert.equal(refusal.reason.status,429);assert.equal(refusal.reason.headers.get('retry-after'),'1');
    const admitted=racing.find(result=>result.status==='fulfilled');assert.ok(admitted?.status==='fulfilled');const accepted=admitted.value;
    at+=1001;await handles[0]!.cleanup(quotaNamespace,at);assert.equal((await handles[1]!.sessions(quotaNamespace).read(clientId,accepted.sessionId)).record,null);
    const recreated=await quotaPeer.authenticate(await request(accepted.sessionId));assert.notEqual(recreated.sessionInstanceId,accepted.sessionInstanceId,'a forgotten sid creates a distinct resource Session instance');
    await assert.rejects(quota.policy.withCurrent(accepted,[],async()=>assert.fail('old instance')),{code:'invalid_session'});
    await quota.end(clientId,accepted.sessionId);assert.equal((await quotaPeer.authenticate(await request('quota_after_end'))).sessionId,'quota_after_end','ended tombstones do not occupy admission slots');
    at+=86400001;await assert.rejects(replacement.authenticate(await request('new_session')),{code:'invalid_session'});
  });
}


test('STORAGE guide combined policy admits signed-out conversations and fences signed-in host writes',async t=>{
  const database=new SqliteCompanyDatabase(':memory:');t.after(()=>database.close());
  const env=await referenceSetup({store:database.issuer(ISSUER),coordinator:database,requireDpopNonce:false});
  const sessions=createSessionAuthority({companyId:ISSUER,metadata:env.metadata,store:database.sessions(ISSUER),
    coordinator:database,accountPolicy:env.issuer.authority.policy,now:()=>env.clock.now});
  const authenticator=createRequestAuthenticator({sessions,authority:env.issuer.authority,
    endpoints:[{origin:new URL(API).origin,pathPrefix:new URL(API).pathname}],now:()=>env.clock.now});
  const service=createConversationService({endpoint:API,historyScopes:['orders:read'],store:database.conversations(ISSUER),
    policy:sessions.policy,authenticator,clock:{now:()=>env.clock.now}});
  const request=async(token?:string)=>new Request(API,{method:'POST',headers:{'content-type':'application/json',
    'poppy-session':await sessionJwt(env.identity,{issuer:ISSUER,clientId:CLIENT,url:API,sid:'guide_session',sub:'guide_user',at:env.clock.now,...(token?{token}:{})}),
    ...(token?{authorization:'DPoP '+token,dpop:await env.proof({htu:API,token})}:{})},
    body:JSON.stringify({message:{id:token?'signed_in':'signed_out',author:{type:'agent'},text:'Guide journey'}})});
  const signedOut=await authenticator.authenticate(await request());
  assert.equal((await service.handle(await request())).status,201);
  await assert.rejects(sessions.policy.withCurrent(signedOut,['orders:write'],async()=>assert.fail('signed-out protected write')),{code:'account_required'});
  const issued=await env.send();assert.equal(issued.status,200,JSON.stringify(issued.body));const token=issued.body.access_token!;
  const signedIn=await authenticator.authenticate(await request(token));assert.equal(signedIn.accountId,'fixture-account');
  assert.equal((await service.handle(await request(token))).status,201);
  await sessions.policy.withCurrent(signedIn,['orders:write'],()=>database.withTransaction(async connection=>{
    connection.run('CREATE TABLE guide_records(owner TEXT PRIMARY KEY,value TEXT)');
    connection.run('INSERT INTO guide_records VALUES(?,?)',[signedIn.accountId!,'saved']);
  }));
  await sessions.end(CLIENT,'guide_session');
  await assert.rejects(sessions.policy.withCurrent(signedIn,['orders:write'],()=>database.withTransaction(async connection=>{
    connection.run('UPDATE guide_records SET value=?',['unsafe']);
  })),{code:'invalid_session'});
  assert.equal(await database.withTransaction(async connection=>connection.get('SELECT value FROM guide_records')?.value),'saved');
});
