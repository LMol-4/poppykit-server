// Local synthetic acceptance only. Production uses createRequestAuthenticator and sessions.policy.
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createBusinessOperations,operationApiResponse} from '../dist/index.js';
import {SqliteCompanyDatabase} from '../dist/sqlite.js';
const dir=await mkdtemp(join(tmpdir(),'poppy-company-operation-')),db=new SqliteCompanyDatabase(join(dir,'company.db'));
try{
  const principal={issuer:'https://example.com',clientId:'https://agent.example/client',userId:'synthetic',sessionId:'sid',sessionInstanceId:'instance',sessionGeneration:'generation',sessionVersion:1,tokenExpiresAt:Date.now()+900000,scopes:[]};
  const operations=createBusinessOperations({companyId:principal.issuer,store:db.businessOperations(principal.issuer),metadata:{resolveClient:async()=>({extensions:{operations:{version:'2'}}})},policy:{withCurrent:(_principal,_scopes,action)=>db.run(action)}});
  let effects=0;const input={operationId:'exchange_one',principal,scopes:[],request:{channel:'api',method:'POST',url:'https://example.com/orders/one/exchange',body:Buffer.from('{"sku":"blue"}').toString('base64')},proposal:()=>({summary:'Exchange order one for the blue jacket for $70.',terms:{order_id:'one',sku:'blue',amount:'70.00'},expires_at:new Date(Date.now()+900000).toISOString()})};
  const required=await operations.local(input,async()=>{effects++;return {done:true};});assert.equal(required.kind,'approval_required');assert.equal(effects,0);assert.equal(operationApiResponse(required).status,403);
  // This is an independent synthetic wire fixture, never a real consent mechanism.
  const approval={operation_id:required.operation.operation_id,revision:required.operation.revision};
  const result=await operations.local({...input,approval},async revision=>db.withTransaction(async tx=>{tx.run('INSERT INTO records VALUES (?,?,?,?)',['example','business','exchange_one',JSON.stringify(revision.terms)]);return {done:true};}));
  assert.equal(result.kind,'completed');assert.deepEqual((await operations.local({...input,approval},async()=>{throw Error('duplicate effect');})).result,{done:true});console.log('synthetic operation committed and replayed');
}finally{db.close();await rm(dir,{recursive:true,force:true});}
