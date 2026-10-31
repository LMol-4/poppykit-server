import assert from 'node:assert/strict';
import type {JWTPayload,JWTHeaderParameters} from 'jose';
// Wire peer: no PoppyKit client, codecs, signing helpers or matching test support.
import { randomBytes, createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from 'jose';
const hash=(value:string)=>createHash('sha256').update(value).digest('base64url');
export async function independentAgent(now=Date.now){
  const clientId='https://agent.example/identity',redirect='https://agent.example/callback';
  const identity=await generateKeyPair('ES256',{extractable:true}),dpop=await generateKeyPair('ES256',{extractable:true});
  const keys = new Map<string, typeof dpop>([['person-a',dpop]]);
  type Context = { key: typeof dpop; issuer: string; sub: string; sid: string };
  const contexts = new Map<string, Context>(), accessTokens = new Set<string>();
  async function session(issuer: string, sub = 'person-a') {
    const key = await generateKeyPair('ES256', {extractable:true}), handle = randomBytes(32).toString('base64url');
    contexts.set(handle, {key,issuer,sub:hash(issuer+' '+sub),sid:randomBytes(32).toString('base64url')});
    return handle;
  }
  let selected=dpop;
  const publicKey={...await exportJWK(identity.publicKey),kid:'independent'},proofKey=await exportJWK(dpop.publicKey);
  const jwt=(claims:JWTPayload,key=identity.privateKey,header:JWTHeaderParameters={alg:'ES256',kid:'independent'})=>new SignJWT(claims).setProtectedHeader(header).sign(key);
  const assertion=(issuer:string,sub:string,extra:JWTPayload={})=>jwt({iss:clientId,sub,aud:issuer,iat:Math.floor(now()/1000),exp:Math.floor(now()/1000)+60,jti:randomBytes(32).toString('base64url'),...extra});
  async function proof(url:string,method='POST',token?:string){const u=new URL(url);u.search='';return jwt({htu:u.href,htm:method,iat:Math.floor(now()/1000),jti:randomBytes(32).toString('base64url'),...(token?{ath:hash(token)}:{})},selected.privateKey,{alg:'ES256',typ:'dpop+jwt',jwk:await exportJWK(selected.publicKey)});}
  async function token(issuer:string,handler:(request:Request)=>Promise<Response>,fields:Record<string,string>={},sub='person-a'){
    if(!keys.has(sub))keys.set(sub,await generateKeyPair('ES256',{extractable:true}));selected=keys.get(sub)!;
    const endpoint=issuer+'/token',form=new URLSearchParams({client_id:clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await assertion(issuer,clientId),...fields});
    assert.ok(fields.grant_type, 'OAuth grant must be explicit; signed-out Sessions are local');
    const response=await handler(new Request(endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',dpop:await proof(endpoint)},body:form}));
    const body=await response.clone().json();if(body.access_token) accessTokens.add(body.access_token); if(body.access_token) contexts.set(body.access_token,{key:selected,issuer,sub:hash(issuer+' '+sub),sid:randomBytes(32).toString('base64url')});return response;
  }
  async function signIn(issuer:string,handler:{token(request:Request):Promise<Response>;beginAuthorization(request:Request,binding:string):Promise<{id:string}>;completeAuthorization(id:string,binding:string,decision:{accountId?:string;scopes?:string[];denied?:boolean}):Promise<URL>},sessionToken:string,scopes:string[],decision:{accountId?:string;scopes?:string[];denied?:boolean}={accountId:'account-a',scopes}){
    const context=contexts.get(sessionToken);assert.ok(context);selected=context.key;const person=sessionToken;keys.set(person,selected);
    const verifier=randomBytes(32).toString('base64url'),url=new URL(issuer+'/authorize');
    url.search=new URLSearchParams({response_type:'code',client_id:clientId,redirect_uri:redirect,scope:scopes.join(' '),state:randomBytes(32).toString('base64url'),code_challenge_method:'S256',code_challenge:hash(verifier),dpop_jkt:await calculateJwkThumbprint(await exportJWK(selected.publicKey))}).toString();
    const authorization=await handler.beginAuthorization(new Request(url),'independent-consent-browser');
    const callback=await handler.completeAuthorization(authorization.id,'independent-consent-browser',decision);
    if(callback.searchParams.has('error'))return {error:callback.searchParams.get('error')};
    const code=callback.searchParams.get('code');assert.ok(code);
    const response=await token(issuer,handler.token,{grant_type:'authorization_code',code,redirect_uri:redirect,code_verifier:verifier,resource:new URL(issuer).origin+'/conversations'},person);
    if(response.status!==200)throw new Error('Independent sign-in failed: '+await response.text());
    const signed = await response.json(); contexts.set(signed.access_token, context); return signed;
  }
  async function request(url:string, credential:string, method='GET', body?:unknown) {
    const context=contexts.get(credential);assert.ok(context);selected=context.key;
    // Opaque access credentials are distinguished from explicitly created local handles.
    const account = accessTokens.has(credential) ? credential : undefined;
    const delegated=await generateKeyPair('ES256'),jwk=await exportJWK(delegated.publicKey),iat=Math.floor(now()/1000);
    const delegation=await jwt({iss:clientId,cnf:{jwk},iat,exp:iat+3600,jti:randomBytes(32).toString('base64url')},identity.privateKey,{alg:'ES256',kid:'independent',typ:'pap-delegation+jwt'});
    const target=new URL(url);target.search='';target.hash='';
    const sessionJwt=await jwt({iss:clientId,aud:context.issuer,sid:context.sid,sub:context.sub,htm:method,htu:target.href,iat,jti:randomBytes(32).toString('base64url'),...(account?{ath:hash(account)}:{})},delegated.privateKey,{alg:'ES256',typ:'poppy-session+jwt',kid:await calculateJwkThumbprint(jwk),pap_dlg:delegation});
    return new Request(url,{method,headers:{'poppy-session':sessionJwt,...(account?{authorization:'DPoP '+account,dpop:await proof(url,method,account)}:{}),'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
  }
  const metadata={async resolveCompany(){throw new Error('unexpected company lookup');},async resolveClient(id:string){if(id!==clientId)throw new Error('unverified client');return {client_id:clientId,client_name:'Independent peer',jwks_uri:'https://agent.example/keys',redirect_uris:[redirect],token_endpoint_auth_method:'private_key_jwt' as const};},async resolveJwks(url:string){if(url!=='https://agent.example/keys')throw new Error('unverified key destination');return {keys:[publicKey]};}};
  return {clientId,metadata,session,token,assertion,proof,request,signIn};
}
