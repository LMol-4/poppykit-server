// Wire peer: no PoppyKit client, codecs, signing helpers or matching test support.
import { randomBytes, createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
const hash=value=>createHash('sha256').update(value).digest('base64url');
export async function independentAgent(now=Date.now){
  const clientId='https://agent.example/identity',redirect='https://agent.example/callback';
  const identity=await generateKeyPair('ES256',{extractable:true}),dpop=await generateKeyPair('ES256',{extractable:true});
  const publicKey={...await exportJWK(identity.publicKey),kid:'independent'},proofKey=await exportJWK(dpop.publicKey);
  const jwt=(claims,key=identity.privateKey,header={alg:'ES256',kid:'independent'})=>new SignJWT(claims).setProtectedHeader(header).sign(key);
  const assertion=(issuer,sub,extra={})=>jwt({iss:clientId,sub,aud:issuer,iat:Math.floor(now()/1000),exp:Math.floor(now()/1000)+60,jti:randomBytes(32).toString('base64url'),...extra});
  async function proof(url,method='POST',token){const u=new URL(url);u.search='';return jwt({htu:u.href,htm:method,iat:Math.floor(now()/1000),jti:randomBytes(32).toString('base64url'),...(token?{ath:hash(token)}:{})},dpop.privateKey,{alg:'ES256',typ:'dpop+jwt',jwk:proofKey});}
  async function token(issuer,handler,fields={},sub='person-a'){
    const endpoint=issuer+'/token',form=new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:jwt-bearer',assertion:await assertion(issuer,sub),client_id:clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await assertion(issuer,clientId),...fields});
    if(fields.grant_type&&fields.grant_type!=='urn:ietf:params:oauth:grant-type:jwt-bearer')form.delete('assertion');
    return handler(new Request(endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',dpop:await proof(endpoint)},body:form}));
  }
  async function signIn(issuer,handler,session,scopes,decision={accountId:'account-a',scopes}){
    const verifier=randomBytes(32).toString('base64url'),url=new URL(issuer+'/authorize');
    url.search=new URLSearchParams({response_type:'code',client_id:clientId,redirect_uri:redirect,scope:scopes.join(' '),state:randomBytes(32).toString('base64url'),code_challenge_method:'S256',code_challenge:hash(verifier)}).toString();
    const authorization=await handler.beginAuthorization(new Request(url),'independent-consent-browser');
    const callback=await handler.completeAuthorization(authorization.id,'independent-consent-browser',decision);
    if(callback.searchParams.has('error'))return {error:callback.searchParams.get('error')};
    const response=await token(issuer,handler.token,{grant_type:'authorization_code',code:callback.searchParams.get('code'),redirect_uri:redirect,code_verifier:verifier,session_id:session,resource:new URL(issuer).origin+'/conversations'});
    if(response.status!==200)throw new Error('Independent sign-in failed: '+await response.text());
    return response.json();
  }
  async function request(url,token,method='GET',body){return new Request(url,{method,headers:{authorization:'DPoP '+token,dpop:await proof(url,method,token),'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});}
  const metadata={async resolveClient(id){if(id!==clientId)throw new Error('unverified client');return {client_id:clientId,client_name:'Independent peer',jwks_uri:'https://agent.example/keys',redirect_uris:[redirect],token_endpoint_auth_method:'private_key_jwt'};},async resolveJwks(url){if(url!=='https://agent.example/keys')throw new Error('unverified key destination');return {keys:[publicKey]};}};
  return {clientId,metadata,token,assertion,proof,request,signIn};
}
