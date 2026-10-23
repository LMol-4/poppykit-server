import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { runConversationAdapterContract } from '../../dist/adapter-contract.js';
import { PostgresCompanyDatabase } from '../../dist/postgres.js';
import type { ConversationStoreState,ConversationRecord } from '../../dist/conversation/service.js';
import { initialConversationState } from '../../dist/conversation/service.js';
import type { PostgresConnection } from '../../dist/postgres.js';
import { testPool } from '../../test-support/postgres.mjs';

if(process.env.D1_POSTGRES!=='1')test.skip('Postgres conversation adapter contract requires explicit database test setup',()=>{});
else runConversationAdapterContract(async()=>{
  // Admit the artificial 20-admin backlog; production's 3s acquisition may correctly reject overload.
  const pool=testPool(30000),a=new PostgresCompanyDatabase(pool),b=new PostgresCompanyDatabase(pool),ns=(process.env.D1_NAMESPACE??'d1')+':'+randomUUID();
  await a.conversations(ns).read({});
  const serialize=(value:unknown)=>JSON.stringify(value,(_key,item)=>{if(item===undefined||typeof item==='function'||typeof item==='bigint'||(typeof item==='number'&&!Number.isFinite(item)))throw new TypeError('non-JSON fixture record');return item;});
  const handle=(db:PostgresCompanyDatabase)=>{
    const store=db.conversations(ns);
    const load=async(connection:PostgresConnection)=>{
      const state=initialConversationState();
      const records=(await connection.query<{kind:string;id:string;body:string}>('SELECT kind,id,body FROM poppy_server.records WHERE ns=$1',[ns])).rows;
      for(const row of records){
        const value:unknown=JSON.parse(row.body);
        if(row.kind==='conversation_meta')Object.assign(state,value);
        else if(row.kind==='conversations')state.conversations[row.id]={...(value as ConversationRecord),events:[]};
        else if(row.kind==='bindings')state.bindings[row.id]=value as ConversationStoreState['bindings'][string];
        else if(row.kind==='messages')state.messages[row.id]=value as ConversationStoreState['messages'][string];
        else if(row.kind==='work')state.work.push(value as ConversationStoreState['work'][number]);
      }
      for(const row of (await connection.query<{conversation:string;body:string}>('SELECT conversation,body FROM poppy_server.events WHERE ns=$1 ORDER BY conversation,seq',[ns])).rows)state.conversations[row.conversation].events.push(JSON.parse(row.body));
      return state;
    };
    const inspect=()=>db.withTransaction(load);
    // Offline administration exists only in this fresh test namespace, never in the adapter API.
    const adminTransaction=<T,>(change:(draft:ConversationStoreState)=>T)=>db.withTransaction(async connection=>{
      await connection.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[ns+':test-admin']);
      const state=await load(connection),generation=state.generation;
      const result=change(state);if(result&&typeof(result as {then?:unknown}).then==='function')throw new TypeError('async fixture transaction');serialize(state);
      if(state.generation!==generation){
        for(const table of ['records','events','event_cursors'])await connection.query(`DELETE FROM poppy_server.${table} WHERE ns=$1`,[ns]);
        await connection.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'conversation_meta','meta',serialize({version:state.version,generation:state.generation})]);
      }else{
        await connection.query("DELETE FROM poppy_server.records WHERE ns=$1 AND kind='bindings'",[ns]);
        const rows=Object.entries(state.bindings).map(([id,value])=>({id,body:serialize(value)}));
        if(rows.length)await connection.query("INSERT INTO poppy_server.records(ns,kind,id,body) SELECT $1,'bindings',id,body FROM jsonb_to_recordset($2::jsonb) AS d(id text,body text)",[ns,serialize(rows)]);
      }
      return structuredClone(result);
    });
    return {...store,inspect,adminTransaction};
  };
  return {store:handle(a),second:handle(b),close:async()=>{await a.close();await b.close();await pool.end();}};
});
