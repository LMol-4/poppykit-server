import assert from 'node:assert/strict';
import type {JWTPayload,JWTHeaderParameters} from 'jose';
// Wire peer: no PoppyKit client, codecs, signing helpers or matching test support.
import { randomBytes, createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
const hash=(value:string)=>createHash('sha256').update(value).digest('base64url');
export async function independentAgent(now=Date.now){
  const clientId='https://agent.example/identity',redirect='https://agent.example/callback';
  const identity=await generateKeyPair('ES256',{extractable:true}),dpop=await generateKeyPair('ES256',{extractable:true});
  const publicKey={...await exportJWK(identity.publicKey),kid:'independent'},proofKey=await exportJWK(dpop.publicKey);
  const jwt=(claims:JWTPayload,key=identity.privateKey,header:JWTHeaderParameters={alg:'ES256',kid:'independent'})=>new SignJWT(claims).setProtectedHeader(header).sign(key);
  const assertion=(issuer:string,sub:string,extra:JWTPayload={})=>jwt({iss:clientId,sub,aud:issuer,iat:Math.floor(now()/1000),exp:Math.floor(now()/1000)+60,jti:randomBytes(32).toString('base64url'),...extra});
  async function proof(url:string,method='POST',token?:string){const u=new URL(url);u.search='';return jwt({htu:u.href,htm:method,iat:Math.floor(now()/1000),jti:randomBytes(32).toString('base64url'),...(token?{ath:hash(token)}:{})},dpop.privateKey,{alg:'ES256',typ:'dpop+jwt',jwk:proofKey});}
  async function token(issuer:string,handler:(request:Request)=>Promise<Response>,fields:Record<string,string>={},sub='person-a'){
    const endpoint=issuer+'/token',form=new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:jwt-bearer',assertion:await assertion(issuer,sub),client_id:clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await assertion(issuer,clientId),...fields});
    if(fields.grant_type&&fields.grant_type!=='urn:ietf:params:oauth:grant-type:jwt-bearer')form.delete('assertion');
    return handler(new Request(endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',dpop:await proof(endpoint)},body:form}));
  }
  async function signIn(issuer:string,handler:{token(request:Request):Promise<Response>;beginAuthorization(request:Request,binding:string):Promise<{id:string}>;completeAuthorization(id:string,binding:string,decision:{accountId?:string;scopes?:string[];denied?:boolean}):Promise<URL>},session:string,scopes:string[],decision:{accountId?:string;scopes?:string[];denied?:boolean}={accountId:'account-a',scopes}){
    const verifier=randomBytes(32).toString('base64url'),url=new URL(issuer+'/authorize');
    url.search=new URLSearchParams({response_type:'code',client_id:clientId,redirect_uri:redirect,scope:scopes.join(' '),state:randomBytes(32).toString('base64url'),code_challenge_method:'S256',code_challenge:hash(verifier)}).toString();
    const authorization=await handler.beginAuthorization(new Request(url),'independent-consent-browser');
    const callback=await handler.completeAuthorization(authorization.id,'independent-consent-browser',decision);
    if(callback.searchParams.has('error'))return {error:callback.searchParams.get('error')};
    const code=callback.searchParams.get('code');assert.ok(code);
    const response=await token(issuer,handler.token,{grant_type:'authorization_code',code,redirect_uri:redirect,code_verifier:verifier,session_id:session,resource:new URL(issuer).origin+'/conversations'});
    if(response.status!==200)throw new Error('Independent sign-in failed: '+await response.text());
    return response.json();
  }
  async function request(url:string,token:string,method='GET',body?:unknown){return new Request(url,{method,headers:{authorization:'DPoP '+token,dpop:await proof(url,method,token),'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});}
  const metadata={async resolveCompany(){throw new Error('unexpected company lookup');},async resolveClient(id:string){if(id!==clientId)throw new Error('unverified client');return {client_id:clientId,client_name:'Independent peer',jwks_uri:'https://agent.example/keys',redirect_uris:[redirect],token_endpoint_auth_method:'private_key_jwt' as const};},async resolveJwks(url:string){if(url!=='https://agent.example/keys')throw new Error('unverified key destination');return {keys:[publicKey]};}};
  return {clientId,metadata,token,assertion,proof,request,signIn};
}
