import {DatabaseSync} from 'node:sqlite';
import {createBusinessOperations} from '../dist/index.js';
import type {OperationInput,AuthorityPolicy,Principal} from '../dist/index.js';
import type {MetadataResolver} from '../dist/network/discovery.js';
import {SqliteCompanyDatabase} from '../dist/sqlite.js';
import {PostgresCompanyDatabase} from '../dist/postgres.js';
import {testPool} from './postgres.mjs';
const principal:Principal={issuer:'https://company.example',clientId:'https://agent.example/client',userId:'user',sessionId:'session',sessionInstanceId:'instance',sessionGeneration:'generation',scopes:[],sessionVersion:1,tokenExpiresAt:9e12};
const message=await new Promise<{engine:string;path:string;ledger:string;namespace:string;mode:string;input:OperationInput}>(resolve=>process.once('message',resolve));
const pool=message.engine==='Postgres'?testPool():undefined,db=pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(message.path);
const policy:AuthorityPolicy={withCurrent:(_p,_s,action)=>db.run(action),withAccepted:(_a,_s,action)=>db.run(action)};
const metadata={resolveClient:async()=>({extensions:{operations:{version:'2'}}})} as unknown as MetadataResolver;
const service=createBusinessOperations({companyId:principal.issuer,store:db.businessOperations(message.namespace),policy,metadata,now:()=>Date.parse('2026-10-31T12:00:00Z')});
const hold=async(stage:string)=>{process.send?.(stage);await new Promise(()=>{});};
const input={...message.input,principal};
if(message.mode==='before-claim')await hold('before-claim');
if(message.mode.startsWith('local')){
  await service.local(input,async()=>{
    if(db instanceof SqliteCompanyDatabase)await db.withTransaction(async tx=>tx.run('INSERT INTO records(ns,kind,id,body) VALUES (?,?,?,?)',[message.namespace,'test_effects',input.operationId,'{"count":1}']));
    else await db.withTransaction(async tx=>{await tx.query("INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,'test_effects',$2,'{\"count\":1}')",[message.namespace,input.operationId]);});
    if(message.mode==='local-before-publication')await hold('local-effect');
    return {done:true};
  });
  await hold('result-committed');
}else{
  await service.external(input,{
    execute:async({key})=>{
      if(message.mode==='external-before-effect')await hold('claimed');
      const ledger=new DatabaseSync(message.ledger);ledger.exec('PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS effects (id TEXT PRIMARY KEY, body TEXT NOT NULL)');ledger.prepare('INSERT OR IGNORE INTO effects VALUES (?,?)').run(key,'{"done":true}');ledger.close();
      await hold('external-effect');return {done:true};
    },reconcile:async()=>({kind:'pending'}),
  });
}
