import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { setup, CLIENT, OTHER_CLIENT, ISSUER, TOKEN_ENDPOINT, REDIRECT } from './issuer-support.mjs';
import { SqliteCompanyDatabase } from '../../dist/sqlite.js';
import { PostgresCompanyDatabase } from '../../dist/postgres.js';
import { testPool } from '../../test-support/postgres.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { keyPair } from './support.mjs';

const hash=(value:string)=>createHash('sha256').update(value).digest('base64url');
async function fixture(bearer=false) {
  const resource='https://mcp.shop.test/mcp';
  const env=await setup({authorizationEndpoint:ISSUER+'/authorize',requireDpopNonce:false,accountLifetimeSeconds:100,...(bearer?{mcpResources:[{url:resource,dpop:false}]}:{})});
  const verifier=randomBytes(32).toString('base64url'),state=randomBytes(32).toString('base64url'),binding=randomBytes(32).toString('base64url');
  const url=new URL(ISSUER+'/authorize');url.search=new URLSearchParams({response_type:'code',client_id:CLIENT,redirect_uri:REDIRECT,scope:'orders:read orders:write',state,code_challenge:hash(verifier),code_challenge_method:'S256'}).toString();
  const view=await env.issuer.beginAuthorization(new Request(url),binding);
  const callback=await env.issuer.completeAuthorization(view.id,binding,{accountId:'account-a',scopes:['orders:read','orders:write']});
  const send=async(fields:Record<string,string>,options:{key?:Awaited<ReturnType<typeof keyPair>>;client?:string}={})=>{
    const body=new URLSearchParams({client_id:options.client??CLIENT,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await env.clientAssertion(options.client?{iss:options.client,sub:options.client}:{}),...(bearer?{resource}:{}),...fields});
    const response=await env.issuer.token(new Request(TOKEN_ENDPOINT,{method:'POST',body,headers:bearer?{}:{dpop:await env.proof({...(options.key?{key:options.key}:{})})}}));
    return {status:response.status,body:await response.json() as Record<string,unknown>};
  };
  const exchange=(changes:Record<string,string>={})=>send({grant_type:'authorization_code',code:callback.searchParams.get('code')!,redirect_uri:REDIRECT,code_verifier:verifier,...changes});
  return {env,send,exchange,resource};
}

for(const bearer of [false,true])test(`independent OAuth sign-in and refresh do not create Sessions (${bearer?'Bearer':'DPoP'})`,async()=>{
  const f=await fixture(bearer),signed=await f.exchange();assert.equal(signed.status,200);assert.equal(signed.body.token_type,bearer?'Bearer':'DPoP');
  assert.equal('session_id' in signed.body,false);assert.equal('signed_in' in signed.body,false);
  assert.deepEqual(f.env.store.state.sessions,{});assert.deepEqual(f.env.store.state.sessionKeys,{});
  const principal=(await f.env.issuer.authority.introspect(signed.body.access_token as string,bearer?f.resource:undefined)).principal;
  assert.equal(principal.clientId,CLIENT);assert.equal(principal.accountId,'account-a');assert.equal(principal.sessionId,'');assert.equal(principal.userId,'');
  assert.equal(await f.env.issuer.authority.policy.withCurrent(principal,['orders:read'],async()=>'protected'),'protected');
  const originalExpiry=Object.values(f.env.store.state.grants)[0]!.expiresAt;f.env.clock.now+=20000;
  const renewed=await f.send({grant_type:'refresh_token',refresh_token:signed.body.refresh_token as string,scope:'orders:read'},{key:await keyPair()});
  assert.equal(renewed.status,200);assert.equal(renewed.body.refresh_token_expires_in,80);assert.equal(renewed.body.scope,'orders:read');
  assert.equal(Object.values(f.env.store.state.grants)[0]!.expiresAt,originalExpiry);assert.deepEqual(f.env.store.state.sessions,{});
  await assert.rejects(f.env.issuer.authority.introspect(renewed.body.access_token as string,bearer?undefined:f.resource),{code:'invalid_token'});
  const replay=await f.send({grant_type:'refresh_token',refresh_token:signed.body.refresh_token as string});assert.equal(replay.status,400);assert.equal(replay.body.error,'invalid_grant');
  await assert.rejects(f.env.issuer.authority.introspect(renewed.body.access_token as string,bearer?f.resource:undefined),{code:'invalid_token'});
});

test('OAuth PKCE, client ownership, scope ceilings and code replay remain enforced without a Session',async()=>{
  const f=await fixture();
  const bad=await f.exchange({code_verifier:'x'.repeat(43)});assert.equal(bad.status,400);assert.equal(bad.body.error,'invalid_grant');
  const credentialInjection=await f.exchange({assertion:'obsolete-session-assertion'});assert.equal(credentialInjection.status,400);assert.equal(credentialInjection.body.error,'invalid_request');
  const signed=await f.exchange();assert.equal(signed.status,200);
  const foreign=await f.send({grant_type:'refresh_token',refresh_token:signed.body.refresh_token as string},{client:OTHER_CLIENT});assert.equal(foreign.status,400);assert.equal(foreign.body.error,'invalid_grant');
  const expanded=await f.send({grant_type:'refresh_token',refresh_token:signed.body.refresh_token as string,scope:'unapproved'});assert.equal(expanded.body.error,'invalid_scope');
  const valid=await f.send({grant_type:'refresh_token',refresh_token:signed.body.refresh_token as string});assert.equal(valid.status,200,'a rejected expansion cannot rotate the existing grant');
  const replay=await f.exchange();assert.equal(replay.body.error,'invalid_grant');
  await assert.rejects(f.env.issuer.authority.introspect(valid.body.access_token as string),{code:'invalid_token'});
});

test('independent Device grant preserves user consent and polling controls without Session binding',async()=>{
  const env=await setup({requireDpopNonce:false,device:{endpoint:ISSUER+'/device',verificationUri:ISSUER+'/verify'}});
  const body=new URLSearchParams({client_id:CLIENT,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await env.clientAssertion(),scope:'orders:read'});
  const response=await env.issuer.deviceAuthorization(new Request(ISSUER+'/device',{method:'POST',body}));assert.equal(response.status,200);const started=await response.json();
  const poll=async(client=CLIENT)=>{
    const form=new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:started.device_code,client_id:client,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await env.clientAssertion({iss:client,sub:client})});
    const key=await keyPair();const response=await env.issuer.token(new Request(TOKEN_ENDPOINT,{method:'POST',body:form,headers:{dpop:await env.proof({key})}}));return {status:response.status,body:await response.json()};
  };
  env.clock.now+=5000;assert.equal((await poll(OTHER_CLIENT)).body.error,'invalid_grant');assert.equal((await poll()).body.error,'authorization_pending');assert.equal((await poll()).body.error,'slow_down');
  const binding=randomBytes(32).toString('base64url');await env.issuer.beginDeviceAuthorization(started.user_code,binding);
  assert.equal(Object.keys(env.store.state.grants).length,0,'opening the verification page does not approve');
  await env.issuer.completeDeviceAuthorization(started.user_code,binding,{accountId:'account-device',scopes:['orders:read']});env.clock.now+=10000;
  const signed=await poll();assert.equal(signed.status,200);assert.equal((await env.issuer.authority.introspect(signed.body.access_token)).principal.accountId,'account-device');
  assert.deepEqual(env.store.state.sessions,{});assert.equal((await poll()).body.error,'invalid_grant');
});

test('independent mediated grant uses OAuth continuation, client ownership and fixed expiry without Sessions',async()=>{
  const seen:Readonly<Record<string,string>>[]=[],contexts:unknown[]=[];let needCode=true;
  const config={scopes:['orders:read'],fields:[{name:'password',label:'Password',secret:true}],maxCodeAttempts:2,maxAttemptsPerMinute:100,
    async authenticate(credentials:Readonly<Record<string,string>>,context:unknown){seen.push(credentials);contexts.push(context);return credentials.password==='private-password'?{accountId:'account-mediated',...(needCode?{challenge:{id:'backend-challenge',sentTo:'Your phone'}}:{})}:null;},async verifyCode(input:{challengeId:string;code:string}){assert.equal(input.challengeId,'backend-challenge');return input.code==='123456';}};
  const env=await setup({requireDpopNonce:false,mediated:config});
  const send=async(fields:Record<string,string>,client=CLIENT)=>{
    const body=new URLSearchParams({grant_type:'https://personalagentprotocol.org/grant/mediated-sign-in',client_id:client,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await env.clientAssertion({iss:client,sub:client}),...fields});
    const response=await env.issuer.token(new Request(TOKEN_ENDPOINT,{method:'POST',body,headers:{dpop:await env.proof()}}));return {status:response.status,body:await response.json()};
  };
  const first=await send({scope:'orders:read',password:'private-password'});assert.equal(first.status,400);assert.equal(first.body.error,'code_required');assert.equal(first.body.expires_in,600);assert.equal(first.body.sent_to,'Your phone');
  assert.ok(seen.every(value=>Object.keys(value).length===0),'credential objects are cleared after trusted hooks');assert.deepEqual(contexts,[{issuer:ISSUER,clientId:CLIENT}]);
  assert.equal((await send({sign_in_id:first.body.sign_in_id,one_time_code:'123456'},OTHER_CLIENT)).body.error,'invalid_grant');
  assert.equal((await send({sign_in_id:first.body.sign_in_id,one_time_code:'123456',scope:'orders:read'})).body.error,'invalid_request');
  env.clock.now+=1000;const wrong=await send({sign_in_id:first.body.sign_in_id,one_time_code:'wrong'});assert.equal(wrong.body.error,'code_required');assert.equal(wrong.body.expires_in,599);
  const signed=await send({sign_in_id:first.body.sign_in_id,one_time_code:'123456'});assert.equal(signed.status,200);assert.equal((await env.issuer.authority.introspect(signed.body.access_token)).principal.accountId,'account-mediated');
  assert.equal((await send({sign_in_id:first.body.sign_in_id,one_time_code:'123456'})).body.error,'invalid_grant');assert.deepEqual(env.store.state.sessions,{});
  needCode=false;const denied=await send({scope:'orders:read',password:'wrong-password'});assert.equal(denied.status,400);assert.equal(denied.body.error,'invalid_grant');assert.equal((await send({scope:'unlisted',password:'private-password'})).body.error,'invalid_scope');
});


test('retired Session-token and token-exchange grants are neither advertised nor accepted',async()=>{
  const env=await setup({requireDpopNonce:false,mcpResources:[{url:'https://mcp.shop.test/mcp?tenant=a',dpop:false}]});
  const metadata=env.issuer.authorizationMetadata();
  for(const grant_type of ['urn:ietf:params:oauth:grant-type:jwt-bearer','urn:ietf:params:oauth:grant-type:token-exchange']){
    assert.ok(!(metadata.grant_types_supported as string[]).includes(grant_type));
    const response=await env.issuer.token(new Request(TOKEN_ENDPOINT,{method:'POST',body:new URLSearchParams({grant_type})}));assert.equal(response.status,400);assert.deepEqual(await response.json(),{error:'unsupported_grant_type'});
  }
  assert.deepEqual(env.store.state.sessions,{});
});


for(const engine of ['SQLite',...(process.env.D1_POSTGRES==='1'?['Postgres']:[])])test(`uncertain mediated hooks survive expiry and bounded cleanup (${engine})`,async t=>{
  const dir=await mkdtemp(join(tmpdir(),'poppy-mediated-')),pool=engine==='Postgres'?testPool():undefined;
  const db=pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(join(dir,'issuer.db')),ns='https://'+randomUUID()+'.issuer.example',store=db.issuer(ns);
  t.after(async()=>{await db.close();await pool?.end();await rm(dir,{recursive:true,force:true});});
  const id='uncertain-hook',at=1790900000000,selection={kind:'sign_in' as const,ids:[id],clientId:CLIENT,replayKeys:[],at};
  await store.transaction(selection,state=>{state.signIns[id]={kind:'mediated',resource:null,clientId:CLIENT,scopes:['orders:read'],expiresAt:at-60000,status:'verifying',attempts:1,executionId:'original-execution',revision:0};});
  await db.cleanup(ns,at,100);
  const retained=(await store.read(selection)).signIns[id];assert.ok(retained&&retained.kind==='mediated');assert.equal(retained.status,'verifying');assert.equal(retained.executionId,'original-execution');
  let calls=0;
  const env=await setup({store,coordinator:db,maxPendingAuthorizations:1,maxPendingAuthorizationsPerClient:1,requireDpopNonce:false,mediated:{fields:[{name:'password',label:'Password',secret:true}],scopes:['orders:read'],async authenticate(){calls++;throw new Error('must remain bounded');},async verifyCode(){throw new Error('must not replay an uncertain hook');}}});
  const form=new URLSearchParams({grant_type:'https://personalagentprotocol.org/grant/mediated-sign-in',client_id:CLIENT,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await env.clientAssertion(),password:'private',scope:'orders:read'});
  const response=await env.issuer.token(new Request(TOKEN_ENDPOINT,{method:'POST',body:form,headers:{dpop:await env.proof()}}));
  assert.equal(response.status,429);assert.ok(response.headers.has('retry-after'));assert.equal(calls,0);assert.equal((await store.read(selection)).signIns[id]!.kind,'mediated');
});
