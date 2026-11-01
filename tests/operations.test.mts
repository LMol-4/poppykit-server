import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {fork} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {createBusinessOperations,AuthorityError,BusinessOperationError,operationApiResponse,operationMcpResponse,parseApprovalHeader,operationToolError,createConversationService} from '../dist/index.js';
import type {OperationInput,OperationOutcome,BusinessOperation,Principal,AuthorityPolicy,ExternalOperationEffect} from '../dist/index.js';
import type {MetadataResolver} from '../dist/network/discovery.js';
import {SqliteCompanyDatabase} from '../dist/sqlite.js';
import {PostgresCompanyDatabase} from '../dist/postgres.js';
import {runBusinessOperationAdapterContract} from '../dist/adapter-contract.js';
import {testPool} from '../test-support/postgres.mjs';
const principal:Principal={issuer:'https://company.example',clientId:'https://agent.example/client',userId:'user',sessionId:'session',sessionInstanceId:'instance',sessionGeneration:'generation',scopes:['orders:write'],sessionVersion:1,tokenExpiresAt:9e12};
const at=Date.parse('2026-10-31T12:00:00Z');
const proposal=()=>({summary:'Exchange one jacket for $70.',terms:{item:'jacket',amount:'70.00'},expires_at:'2026-11-01T12:00:00Z'});
const fail=(code:string)=>(e:unknown)=>(e as {code?:unknown})?.code===code;
function approved(outcome:OperationOutcome){assert.equal(outcome.kind,'approval_required');if(outcome.kind!=='approval_required')throw Error('expected proposal');return {operation_id:outcome.operation.operation_id,revision:outcome.operation.revision};}
for(const engine of ['SQLite',...(process.env.D1_POSTGRES==='1'?['Postgres']:[])]){
  async function fixture(){
    const dir=await mkdtemp(join(tmpdir(),'server-operations-')),path=join(dir,'company.db'),ledger=join(dir,'external.db'),namespace=randomUUID(),pool=engine==='Postgres'?testPool():undefined;
    const a=pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(path),b=pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(path);let revoked=false,supported=true,time=at;
    const policy=(db:typeof a):AuthorityPolicy=>({withCurrent:async(p,scopes,action)=>db.run(async()=>{if(revoked||p.tokenExpiresAt<=time)throw new AuthorityError('invalid_token');if(!scopes.every(s=>p.scopes.includes(s)))throw new AuthorityError(p.accountId?'insufficient_scope':'account_required',{scope:scopes.join(' ')});return action();}),withAccepted:(_p,_s,action)=>db.run(action)});
    const metadata={resolveClient:async()=>({extensions:supported?{operations:{version:'2'}}:{operations:{version:'1'}}})} as unknown as MetadataResolver;
    const service=(db:typeof a=a,effectTimeoutMs=30000)=>createBusinessOperations({companyId:principal.issuer,metadata,store:db.businessOperations(namespace),policy:policy(db),now:()=>time,retentionMs:0,effectTimeoutMs});
    const input=(id='exchange'):OperationInput=>({operationId:id,principal:{...principal},request:{channel:'api',method:'POST',url:'https://company.example/orders/one?item=jacket',body:Buffer.from('{"amount":"70.00"}').toString('base64')},scopes:[],proposal});
    const local=async(db:typeof a,operation:BusinessOperation)=>{
      const key=operation.operation_id;
      if(db instanceof SqliteCompanyDatabase)await db.withTransaction(async tx=>{tx.run('INSERT INTO records(ns,kind,id,body) VALUES (?,?,?,?) ON CONFLICT(ns,kind,id) DO UPDATE SET body=json_set(body,\'$.count\',json_extract(body,\'$.count\')+1)',[namespace,'test_effects',key,'{"count":1}']);});
      else await db.withTransaction(async tx=>{await tx.query("INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,'test_effects',$2,'{\"count\":1}') ON CONFLICT(ns,kind,id) DO UPDATE SET body=jsonb_set(records.body::jsonb,'{count}',to_jsonb((records.body::jsonb->>'count')::int+1))::text",[namespace,key]);});
      return {done:true,terms:operation.terms??{}};
    };
    const count=async(id='exchange')=>{
      if(a instanceof SqliteCompanyDatabase)return a.withTransaction(async tx=>{const row=tx.get('SELECT body FROM records WHERE ns=? AND kind=? AND id=?',[namespace,'test_effects',id]);return row?JSON.parse(row.body as string).count:0;});
      return a.withTransaction(async tx=>{const r=await tx.query("SELECT body FROM poppy_server.records WHERE ns=$1 AND kind='test_effects' AND id=$2",[namespace,id]);return r.rows[0]?JSON.parse(r.rows[0].body).count:0;});
    };
    return {a,b,namespace,path,ledger,service,input,local,count,policy:policy(a),metadata,advance:(ms:number)=>{time+=ms;},revoke:()=>{revoked=true;},support:(v:boolean)=>{supported=v;},close:async()=>{await a.close();await b.close();await pool?.end();await rm(dir,{recursive:true,force:true});}};
  }
  runBusinessOperationAdapterContract(async()=>{const f=await fixture();return {store:f.a.businessOperations(f.namespace),second:f.b.businessOperations(f.namespace),close:f.close};});
  test(`Operations no effect before approval, old valid revisions, exact binding and cross-owner refusals (${engine})`,async()=>{
    const f=await fixture();try{
      const s=f.service(),input=f.input(),first=approved(await s.local(input,op=>f.local(f.a,op)));assert.equal(await f.count(),0);
      const second=approved(await s.propose({...input,proposal:()=>({...proposal(),summary:'New $80 terms',terms:{amount:'80.00'}})}));assert.notEqual(first.revision,second.revision);
      for(const changed of [{sessionId:'other'},{sessionInstanceId:'recreated'},{sessionGeneration:'reset'},{clientId:'https://other.example/client'},{userId:'other'}])await assert.rejects(s.local({...input,principal:{...principal,...changed},approval:first},op=>f.local(f.a,op)),fail('operation_not_found'));
      for(const request of [{...input.request,method:'PUT'},{...input.request,url:'https://company.example/orders/other'},{...input.request,body:'changed'}]){
        const result=await s.local({...input,request:request as OperationInput['request'],approval:first},op=>f.local(f.a,op));assert.equal(result.kind,'approval_required');if(result.kind==='approval_required')assert.notEqual(result.operation.revision,first.revision);
      }
      assert.equal(await f.count(),0);
      const completed=await s.local({...input,approval:first},op=>f.local(f.a,op));assert.equal(completed.kind,'completed');if(completed.kind==='completed')assert.deepEqual(completed.result,{done:true,terms:{item:'jacket',amount:'70.00'}});
      await f.service(f.b).local({...input,approval:second},op=>f.local(f.b,op));assert.equal(await f.count(),1);
    }finally{await f.close();}
  });
  test(`Operations signed-in account ownership, scope revocation and protected result replay (${engine})`,async()=>{
    const f=await fixture();try{
      const s=f.service(),input={...f.input(),scopes:['orders:write'],principal:{...principal,accountId:'account'}};const approval=approved(await s.propose(input));
      await assert.rejects(s.local({...input,principal:{...principal,scopes:[]},approval},op=>f.local(f.a,op)),fail('account_required'));
      await assert.rejects(s.local({...input,principal:{...principal,accountId:'other'},approval},op=>f.local(f.a,op)),fail('operation_not_found'));
      await assert.rejects(s.local({...input,principal:{...principal,accountId:'account',scopes:[]},approval},op=>f.local(f.a,op)),fail('insufficient_scope'));
      const otherSession={...input.principal,sessionId:'other',sessionInstanceId:'other'};assert.equal((await s.local({...input,principal:otherSession,approval},op=>f.local(f.a,op))).kind,'completed');
      f.revoke();await assert.rejects(s.local({...input,approval},op=>f.local(f.a,op)),fail('invalid_token'));assert.equal(await f.count(),1);
    }finally{await f.close();}
  });
  test(`Operations concurrent workers and revisions serialize one same-database effect (${engine})`,async()=>{
    const f=await fixture();try{
      const input=f.input(),one=approved(await f.service().propose(input)),two=approved(await f.service(f.b).propose({...input,proposal:()=>({...proposal(),summary:'Second valid terms'})}));
      const results=await Promise.all([f.service().local({...input,approval:one},op=>f.local(f.a,op)),f.service(f.b).local({...input,approval:two},op=>f.local(f.b,op))]);assert.equal(await f.count(),1);assert.ok(results.every(r=>r.kind==='completed'));assert.deepEqual(results[0].kind==='completed'?results[0].result:null,results[1].kind==='completed'?results[1].result:null);
      const roll=f.input('rollback'),approval=approved(await f.service().propose(roll));await assert.rejects(f.service().local({...roll,approval},async op=>{await f.local(f.a,op);throw Error('before publication');}),/before publication/);assert.equal(await f.count('rollback'),0);
      assert.equal((await f.service(f.b).local({...roll,approval},op=>f.local(f.b,op))).kind,'completed');assert.equal(await f.count('rollback'),1);
    }finally{await f.close();}
  });
  test(`Operations expiry, result retention and tombstones never resurrect an action (${engine})`,async()=>{
    const f=await fixture();try{
      const input=f.input(),approval=approved(await f.service().propose(input));assert.equal((await f.service().local({...input,approval},op=>f.local(f.a,op))).kind,'completed');f.advance(86400000);await f.service().prune(input.operationId);assert.equal((await f.service(f.b).local({...input,approval},op=>f.local(f.b,op))).kind,'completed');assert.equal(await f.count(),1);
      f.advance(1);await f.service().prune(input.operationId);const proposalFuture=()=>({...proposal(),expires_at:'2026-11-03T12:00:00Z'});
      const next=await f.service().local({...input,proposal:proposalFuture,approval},op=>f.local(f.a,op));assert.equal(next.kind,'approval_required');if(next.kind==='approval_required'){assert.notEqual(next.operation.revision,approval.revision);assert.equal((await f.service().local({...input,proposal:proposalFuture,approval:approved(next)},op=>f.local(f.a,op))).kind,'approval_required');}assert.equal(await f.count(),1);
      const expired=f.input('expired'),old=approved(await f.service().propose({...expired,proposal:proposalFuture}));f.advance(3*86400000);const result=await f.service().local({...expired,approval:old,proposal:()=>({...proposal(),expires_at:'2026-11-10T00:00:00Z'})},op=>f.local(f.a,op));assert.equal(result.kind,'approval_required');assert.equal(await f.count('expired'),0);
    }finally{await f.close();}
  });
  test(`Operations external timeout and reconciliation retain one claim after expiry (${engine})`,async()=>{
    const f=await fixture();try{
      const s=f.service(),input=f.input(),approval=approved(await s.propose(input));let effects=0,calls=0;const receipts=new Map<string,{done:boolean}>();
      const effect:ExternalOperationEffect={execute:async({key})=>{calls++;if(!receipts.has(key)){effects++;receipts.set(key,{done:true});}throw Error('response lost');},reconcile:async({key})=>receipts.has(key)?{kind:'completed',result:receipts.get(key)!}:{kind:'pending'}};
      assert.equal((await s.external({...input,approval},effect)).kind,'pending');assert.equal((await f.service(f.b).external({...input,approval},effect)).kind,'pending');assert.equal(calls,1);f.advance(5*86400000);await s.prune(input.operationId);assert.equal((await f.service(f.b).external({...input,approval},effect)).kind,'pending');
      assert.equal(operationApiResponse({kind:'pending',retryAfter:2}).status,503);assert.equal(operationMcpResponse({kind:'pending',retryAfter:2}).headers.get('retry-after'),'2');
      assert.equal((await f.service(f.b).reconcile({...input,approval},effect)).kind,'completed');assert.equal((await s.external({...input,approval},effect)).kind,'completed');assert.equal(effects,1);assert.equal(calls,1);
    }finally{await f.close();}
  });
  test(`Operations negotiation and API/MCP refusal formats are independent of OAuth/enrollment (${engine})`,async()=>{
    const f=await fixture();try{
      const result=await f.service().propose(f.input());assert.equal(result.kind,'approval_required');const response=operationApiResponse(result);assert.equal(response.status,403);assert.equal(response.headers.get('www-authenticate'),null);const body=await response.json();assert.equal(body.error,'approval_required');assert.equal(body.operation.operation_id,'exchange');
      const tool=await operationMcpResponse(result).json();assert.equal(tool.isError,true);assert.deepEqual(tool.structuredContent.operation,body.operation);
      f.support(false);await assert.rejects(f.service().propose(f.input('unsupported')),fail('extension_required'));const error=new BusinessOperationError('extension_required');assert.match(error.response().headers.get('www-authenticate')!,/extension="operations"/);assert.equal((await operationMcpResponse(error).json()).isError,true);assert.equal(await f.count(),0);
    }finally{await f.close();}
  });
  test(`Operations conversation-only approval, cross-conversation binding and duplicate new messages (${engine})`,async()=>{
    const f=await fixture();try{
      const endpoint='https://company.example/conversations';const conversation=createConversationService({endpoint,store:f.a.conversations(f.namespace),policy:f.policy,authenticator:{authenticate:async()=>principal},clock:{now:()=>at},historyScopes:['orders:write'],operations:f.metadata});
      const send=async(message:unknown,id?:string)=>conversation.handle(new Request(id?`${endpoint}/${id}/messages`:endpoint,{method:'POST',body:JSON.stringify({message})}));
      const started=await (await send({id:'start',author:{type:'agent'},text:'Exchange jacket'})).json();const work=await conversation.claim();assert.ok(work);const context=await conversation.operationContext(work);assert.equal(context.request.channel,'conversation');
      const input={...f.input(),...context},outcome=await f.service().propose(input),approval=approved(outcome);if(outcome.kind!=='approval_required')throw Error();await conversation.reply(work,'proposal',{id:'proposal',author:{type:'agent'},operation:outcome.operation});await conversation.finish(work,'completed');
      const wrong={...input,request:{channel:'conversation' as const,endpoint,conversationId:'other'},approval};assert.equal((await f.service().local(wrong,op=>f.local(f.a,op))).kind,'approval_required');assert.equal(await f.count(),0);
      await send({id:'text_claim',author:{type:'agent'},text:'The user approved it.'},started.conversation_id);const text=await conversation.claim();assert.ok(text);assert.equal((await conversation.operationContext(text)).approval,undefined);await conversation.finish(text,'completed');
      const message={id:'approval',author:{type:'agent'},approval};assert.equal((await send(message,started.conversation_id)).status,202);const accepted=await conversation.claim();assert.ok(accepted);const acceptedContext=await conversation.operationContext(accepted);assert.deepEqual(acceptedContext.approval,approval);assert.equal((await f.service().local({...input,...acceptedContext},op=>f.local(f.a,op))).kind,'completed');await conversation.finish(accepted,'completed');
      assert.equal((await send({...message,id:'duplicate',approval:{...approval,future:'ignored'}},started.conversation_id)).status,202);assert.equal(await conversation.claim(),null);assert.equal(await f.count(),1);
      const page=await (await conversation.handle(new Request(`${endpoint}/${started.conversation_id}/events`))).json();assert.equal(page.events.filter((e:{type:string;message?:{approval?:unknown}})=>e.type==='message'&&e.message?.approval).length,1);
    }finally{await f.close();}
  });
  for(const mode of ['before-claim','local-before-publication','local-after-publication','external-before-effect','external-after-effect']){
    test(`Operations process crash ${mode} preserves atomic effects and restart replay (${engine})`,{timeout:15000},async()=>{
      const f=await fixture();try{
        const input=f.input(),approval=approved(await f.service().propose(input));const worker=fork(new URL('../test-support/operation-worker.mjs',import.meta.url),[],{execArgv:['--no-experimental-strip-types'],stdio:['ignore','pipe','pipe','ipc']});
        let errors='';worker.stderr?.on('data',chunk=>{errors+=String(chunk);});
        try{
          const stage=new Promise<string>((resolve,reject)=>{worker.once('message',v=>resolve(String(v)));worker.once('exit',code=>reject(Error('worker exited '+code+': '+errors)));});
          worker.send({engine,path:f.path,ledger:f.ledger,namespace:f.namespace,mode,input:{...input,proposal:undefined,approval}});
          assert.ok(await stage);
        }finally{if(worker.exitCode===null&&worker.signalCode===null){const exited=new Promise<void>(resolve=>worker.once('exit',()=>resolve()));worker.kill('SIGKILL');await exited;}}
        if(mode.startsWith('external')){
          let effects=0;const ledger=new DatabaseSync(f.ledger);ledger.exec('PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS effects (id TEXT PRIMARY KEY, body TEXT NOT NULL)');
          const effect:ExternalOperationEffect={execute:async({key})=>{effects++;ledger.prepare('INSERT OR IGNORE INTO effects VALUES (?,?)').run(key,'{"done":true}');return {done:true};},reconcile:async({key})=>ledger.prepare('SELECT 1 FROM effects WHERE id=?').get(key)?{kind:'completed',result:{done:true}}:{kind:'absent'}};
          assert.equal((await f.service(f.b).external({...input,approval},effect)).kind,'pending');assert.equal(effects,0);assert.equal((await f.service(f.b).reconcile({...input,approval},effect)).kind,'completed');assert.equal((ledger.prepare('SELECT count(*) AS n FROM effects').get()!).n,1);ledger.close();
        }else{
          assert.equal(await f.count(),mode==='local-after-publication'?1:0);assert.equal((await f.service(f.b).local({...input,approval},op=>f.local(f.b,op))).kind,'completed');assert.equal(await f.count(),1);
        }
      }finally{await f.close();}
    });
  }
  test(`Operations two independent processes race approved revisions without duplicate effects (${engine})`,{timeout:15000},async()=>{
    const f=await fixture();try{
      const input=f.input(),approvals=[approved(await f.service().propose(input)),approved(await f.service().propose({...input,proposal:()=>({...proposal(),summary:'Other issued terms'})}))];
      const workers=approvals.map(approval=>{
        const child=fork(new URL('../test-support/operation-worker.mjs',import.meta.url),[],{execArgv:['--no-experimental-strip-types'],stdio:['ignore','pipe','pipe','ipc']});
        const ready=new Promise<void>((resolve,reject)=>{let error='';child.stderr?.on('data',value=>{error+=String(value);});child.once('message',()=>resolve());child.once('exit',code=>reject(Error('worker '+code+': '+error)));});
        child.send({engine,path:f.path,ledger:f.ledger,namespace:f.namespace,mode:'local-after-publication',input:{...input,proposal:undefined,approval}});return {child,ready};
      });
      try{await Promise.all(workers.map(row=>row.ready));}finally{await Promise.all(workers.map(({child})=>new Promise<void>(resolve=>{if(child.exitCode!==null||child.signalCode!==null){resolve();return;}child.once('exit',()=>resolve());child.kill('SIGKILL');})));}
      assert.equal(await f.count(),1);
    }finally{await f.close();}
  });

  test(`Operations running external deadline stays fenced until its late result is reconciled (${engine})`,async()=>{
    const f=await fixture();try{
      const input=f.input(),approval=approved(await f.service().propose(input));let release!:()=>void,done=false,calls=0;
      const gate=new Promise<void>(resolve=>{release=resolve;});
      const effect:ExternalOperationEffect={execute:async()=>{calls++;await gate;done=true;return {done:true};},reconcile:async()=>done?{kind:'completed',result:{done:true}}:{kind:'pending'}};
      assert.equal((await f.service(f.a,5).external({...input,approval},effect)).kind,'pending');
      assert.equal((await f.service(f.b).external({...input,approval},effect)).kind,'pending');assert.equal(calls,1);
      release();await gate;await new Promise<void>(resolve=>setImmediate(resolve));
      assert.equal((await f.service(f.b).reconcile({...input,approval},effect)).kind,'completed');assert.equal(calls,1);
    }finally{await f.close();}
  });

  test(`Operations delayed execute and reconcile publication cannot resurrect pruned results (${engine})`,async()=>{
    const f=await fixture();try{
      for(const kind of ['execute','reconcile']){
        let expiry=kind==='execute'?'2026-11-01T12:00:00Z':'2026-11-02T12:00:00Z';
        const input={...f.input(kind),proposal:()=>({...proposal(),expires_at:expiry})},approval=approved(await f.service().propose(input));let release!:(result:{done:boolean})=>void,started!:()=>void;
        const ready=new Promise<void>(resolve=>{started=resolve;}),value=new Promise<{done:boolean}>(resolve=>{release=resolve;});
        const effect:ExternalOperationEffect={execute:async()=>{started();return value;},reconcile:async()=>({kind:'completed',result:{first:true}})};
        let late:Promise<OperationOutcome>;
        if(kind==='execute'){late=f.service().external({...input,approval},effect);await ready;}
        else{
          await f.service().external({...input,approval},{...effect,execute:async()=>{throw Error('lost response');}});
          late=f.service().reconcile({...input,approval},{...effect,reconcile:async()=>{started();return {kind:'completed',result:await value};}});await ready;
        }
        assert.equal((await f.service(f.b).reconcile({...input,approval},effect)).kind,'completed');
        f.advance(86400001);expiry='2026-11-10T12:00:00Z';await f.service().prune(input.operationId);
        release({done:true});assert.equal((await late).kind,'approval_required');
        const record=await f.a.businessOperations(f.namespace).transaction(input.operationId,async slot=>slot.record!);assert.equal(record.execution!.phase,'completed');assert.equal(record.execution!.result,undefined);assert.deepEqual(record.revisions,{});
      }
    }finally{await f.close();}
  });

}
