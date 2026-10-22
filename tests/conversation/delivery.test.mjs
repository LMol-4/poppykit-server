import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { SqliteCompanyDatabase } from '../../dist/sqlite.js';
import { createConversationNotifications } from '../../dist/index.js';
import { parseEventStream } from '../../dist/protocol/sse.js';
import { setup, hello, endpoint } from './support.mjs';

function hints() { const adapter=createConversationNotifications();let subscriptions=0,publishes=0;return {get subscriptions(){return subscriptions;},get publishes(){return publishes;},subscribe(id,wake){subscriptions++;const off=adapter.subscribe(id,wake);return()=>{subscriptions--;off();};},publish(id){publishes++;adapter.publish(id);}}; }
function request(id,{cursor,signal,stream=false,last}={}) {const url=new URL(`${endpoint}/${id}/events`);url.searchParams.set('wait','2');if(cursor)url.searchParams.set('cursor',cursor);return new Request(url,{signal,headers:{authorization:'DPoP alice',...(stream?{accept:'text/event-stream'}:{}),...(last?{'last-event-id':last}:{})}});}

test('subscription setup wake cannot be lost, and cancellation cleans listener',async()=>{
  const notifications=hints(),env=setup({notifications,pollIntervalMs:1000});const id=(await env.start(hello)).body.conversation_id;const cursor=(await env.read(id)).body.cursor;
  const hook={...notifications,subscribe(conversation,wake){const off=notifications.subscribe(conversation,wake);queueMicrotask(()=>env.service.reply(work,'out',{id:'reply',sender:'agent',text:'news'}));return off;}};
  const work=await env.service.claim();const reader=setup({store:env.store,notifications:hook}).service;
  const page=await(await reader.handle(request(id,{cursor}))).json();assert.equal(page.events[0].message.text,'news');assert.equal(notifications.subscriptions,0);
  const abort=new AbortController(),pending=env.service.handle(request(id,{cursor:page.cursor,signal:abort.signal}));await env.store.untilReads(env.store.reads+1);abort.abort();await assert.rejects(pending);assert.equal(notifications.subscriptions,0);
});

test('committed output survives a lost notification and reconciliation does bounded reads',async()=>{
  const notifications=hints(),lost={subscribe:notifications.subscribe,publish(){throw new Error('lost hint');}};
  const db=new SqliteCompanyDatabase(':memory:');try{
    const store=db.conversations('test'),env=setup({store,notifications:lost,pollIntervalMs:20,pageSize:2});const id=(await env.start(hello)).body.conversation_id;const cursor=(await env.read(id)).body.cursor,work=await env.service.claim();
    const pending=env.service.handle(request(id,{cursor}));await new Promise(resolve=>setTimeout(resolve,5));await env.service.reply(work,'out',{id:'reply',sender:'agent',text:'durable'});
    const page=await(await pending).json();assert.equal(page.events[0].message.text,'durable');assert.equal(notifications.subscriptions,0);
    const before=db.metrics.rowsRead;await env.read(id,{query:`?cursor=${page.cursor}`});const baseline=db.metrics.rowsRead-before;
    for(let i=0;i<75;i++)await env.send(id,{id:'context_'+i,sender:'agent',context:{n:i}});
    const latest=(await env.read(id,{query:`?cursor=${page.cursor}`})).body;assert.ok(latest.events.length<=2);
    db.metrics.rowsRead=0;const newest=(await store.read({conversationId:id})).conversations[id].events.at(-1).id;db.metrics.rowsRead=0;await env.read(id,{query:`?cursor=${newest}`});assert.equal(db.metrics.rowsRead,baseline,'empty read operation count independent of own history');
  }finally{db.close();}
});

test('waiting reconciliation reads stay targeted as unrelated histories grow',async t=>{
  const counts=[];
  for(const unrelated of [0,100]){
    const db=new SqliteCompanyDatabase(':memory:');try{
      const store=db.conversations('bench');let env,id,work,measuring=false,reads=0,published;
      const measured={...store,async read(selection){
        if(measuring&&selection.conversationId===id&&++reads===4)published=env.service.reply(work,'durable',{id:'bench_reply',sender:'agent',text:'Committed without a notification'});
        return store.read(selection);
      }};
      env=setup({store:measured,pollIntervalMs:5,notifications:{subscribe(){return()=>{};},publish(){}}});
      id=(await env.start({id:'bench_target',sender:'agent',text:'Neutral target'})).body.conversation_id;
      const cursor=(await env.read(id)).body.cursor;work=await env.service.claim();
      for(let i=0;i<unrelated;i++)await env.start({id:'unrelated_'+i,sender:'agent',text:'Unrelated'});
      db.metrics.rowsRead=0;measuring=true;
      const response=await env.service.handle(request(id,{cursor}));const page=await response.json();await published;measuring=false;
      assert.equal(page.events.at(-1).message.id,'bench_reply');counts.push({unrelated,waitingReads:reads,rowsRead:db.metrics.rowsRead});
    }finally{db.close();}
  }
  assert.equal(counts[0].waitingReads,counts[1].waitingReads);assert.equal(counts[0].rowsRead,counts[1].rowsRead);t.diagnostic(JSON.stringify({waitingReader:counts}));
});

test('maximum encoded client/company events fit JSON pages and SSE frames; one byte over rolls back',async()=>{
  for(const maxPageBytes of [2048,4096,1048576]){
    const maxEventBytes=maxPageBytes-1025,env=setup({maxPageBytes,maxFrameBytes:maxPageBytes,maxEventBytes,pageSize:100});
    const base={id:'m',sender:'agent',text:''};const record={id:'evt_'+'a'.repeat(22),created_at:'2026-10-19T12:00:00.000Z',type:'message',message:{...base,role:'user'}};
    const room=maxEventBytes-Buffer.byteLength(JSON.stringify(record));const text='☕'.repeat(Math.floor(room/3))+'x'.repeat(room%3);const message={...base,text};
    const started=await env.start(message);assert.equal(started.status,201);const id=started.body.conversation_id;
    const page=await env.read(id);assert.ok(Buffer.byteLength(JSON.stringify(page.body))<=maxPageBytes);assert.equal(Buffer.byteLength(JSON.stringify(page.body.events[0])),maxEventBytes);
    assert.equal((await env.send(id,{...message,id:'n',text:text+'x'})).status,400);
    const work=await env.service.claim(),companyBase={...base,id:'r'};const companyRoom=maxEventBytes-Buffer.byteLength(JSON.stringify({...record,message:{...companyBase,role:'company'}}));const reply={...companyBase,text:'é'.repeat(Math.floor(companyRoom/2))+'x'.repeat(companyRoom%2)};
    await env.service.reply(work,'out',reply);await assert.rejects(env.service.reply(work,'too_big',{...reply,text:reply.text+'x'}),{field:'event.size'});
    const response=await env.service.handle(request(id,{stream:true,last:page.body.cursor,cursor:'invalid'}));const frames=parseEventStream(response.body,{maxFrameBytes:maxPageBytes});let found;try{for await(const frame of frames){if(frame.event.message?.role==='company'){found=frame.event.message.text;break;}}}finally{await frames.return();}assert.equal(found,reply.text);
    assert.ok((await env.read(id,{query:`?cursor=${page.body.cursor}`})).body.events.length>=1);
  }
});

test('SSE backpressure reads only on pull; cancellation and unattended expiry release subscriptions',async()=>{
  const notifications=hints(),env=setup({notifications,streamMs:20});const id=(await env.start(hello)).body.conversation_id;
  const before=env.store.reads,response=await env.service.handle(request(id,{stream:true}));const initial=env.store.reads;assert.equal(initial-before,1);
  await new Promise(resolve=>setTimeout(resolve,5));assert.equal(env.store.reads,initial,'no read-ahead without consumer');await response.body.cancel();assert.equal(notifications.subscriptions,0);
  const unused=await env.service.handle(request(id,{stream:true}));assert.equal(notifications.subscriptions,1);await new Promise(resolve=>setTimeout(resolve,30));assert.equal(notifications.subscriptions,0);await unused.body.cancel();
});

test('retention protects active work, expires cursors, keeps old message receipts, and orders concurrent append',async()=>{
  const db=new SqliteCompanyDatabase(':memory:');try{
    const store=db.conversations('test'),env=setup({store});const start=await env.start(hello),id=start.body.conversation_id,cursor=(await env.read(id)).body.events[0].id;
    assert.equal(await store.pruneEvents(id,env.clock.now()+1),0);const work=await env.service.claim();await env.service.finish(work,'completed');
    const [removed,sent]=await Promise.all([store.pruneEvents(id,env.clock.now()+1,1),env.send(id,{id:'next',sender:'agent',context:{user_available:false}})]);assert.equal(removed,1);assert.equal(sent.status,202);
    assert.equal((await env.read(id,{query:`?cursor=${cursor}`})).body.error,'cursor_expired');assert.equal((await env.read(id,{query:'?cursor=foreign'})).body.error,'invalid_cursor');
    assert.deepEqual((await env.start(hello)).body,start.body);assert.equal((await env.start({...hello,text:'changed'})).body.error,'message_id_conflict');
    const retained=(await env.read(id)).body;assert.ok(retained.events.length);assert.ok(retained.events.some(event=>event.message?.id==='next'));
  }finally{db.close();}
});

test('Device-only and Mediated-only company scopes can request conversation authorization',async()=>{
  for(const method of ['device','mediated']){const env=setup({supportedScopes:[`${method}:read`]});await env.start(hello);const work=await env.service.claim();await env.service.requestAuthorization(work,'auth',[`${method}:read`]);const events=(await env.service.history(work));assert.equal(events.at(-1).scope,`${method}:read`);}
});

test('separate processes receive committed updates through durable reconciliation without a broker',{timeout:10000},async t=>{
  const dir=await mkdtemp(join(tmpdir(),'poppy-j3-')),path=join(dir,'db');const db=new SqliteCompanyDatabase(path);const store=db.conversations('test'),env=setup({store});const id=(await env.start(hello)).body.conversation_id,cursor=(await env.read(id)).body.cursor;
  const children=[];t.after(async()=>{for(const child of children)if(child.exitCode===null)child.kill();db.close();await rm(dir,{recursive:true,force:true});});
  const spawn=()=>{const child=fork(new URL('../../test-support/delivery-worker.mjs',import.meta.url),[path,id,cursor],{windowsHide:true,stdio:['ignore','ignore','pipe','ipc']});children.push(child);const messages=[];const ready=new Promise((resolve,reject)=>{child.on('message',msg=>{messages.push(msg);if(msg.ready)resolve();});child.on('error',reject);});const exited=once(child,'exit');return {child,messages,ready,exited};};
  const readers=[spawn(),spawn()];await Promise.all(readers.map(r=>r.ready));const work=await env.service.claim();await env.service.reply(work,'out',{id:'cross_process',sender:'agent',text:'committed, no broker'});
  await Promise.all(readers.map(r=>r.exited));for(const reader of readers){assert.equal(reader.child.exitCode,0);assert.equal(reader.messages.at(-1).message,'cross_process');}
});

test('SQLite human lifecycle uses the last user message and closed SSE drains every page',async()=>{
  const db=new SqliteCompanyDatabase(':memory:');try{
    const store=db.conversations('test'),env=setup({store,pageSize:1,authorizeOperator:async operator=>{assert.equal(operator,'staff');}});const id=(await env.start(hello)).body.conversation_id;
    await env.handoff(id);const person=await env.service.joinHuman('staff',id);assert.equal(person.message.id,hello.id);await env.service.reply(person,'out',{id:'human_reply',sender:'human',text:'A person answered.'});await env.service.returnToAgent('staff',id);
    await env.close(id);const full=(await store.read({conversationId:id})).conversations[id].events;const response=await env.service.handle(request(id,{stream:true}));const ids=[];for await(const frame of parseEventStream(response.body))ids.push(frame.event.id);assert.deepEqual(ids,full.map(event=>event.id));
  }finally{db.close();}
});

test('waited POST distinguishes expired and foreign cursors without accepting the rejected write',async()=>{
  const db=new SqliteCompanyDatabase(':memory:');try{
    const store=db.conversations('test'),env=setup({store});const id=(await env.start(hello)).body.conversation_id,cursor=(await env.read(id)).body.events[0].id;const work=await env.service.claim();await env.service.finish(work,'completed');await store.pruneEvents(id,env.clock.now()+1,1);
    const message={id:'waited',sender:'agent',text:'new'};
    assert.equal((await env.send(id,message,{query:`?wait=1&cursor=${cursor}`})).status,410);
    assert.equal((await env.send(id,message,{query:'?wait=1&cursor=foreign'})).body.error,'invalid_cursor');
    assert.equal((await env.send(id,message)).status,202);
  }finally{db.close();}
});

import { readFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { Readable } from 'node:stream';
import { createNodeTransport } from '../../dist/network/transport.js';
test('HTTPS JSON and streaming paths deliver the same durable conversation end to end',async t=>{
  const key=await readFile(new URL('../network/fixtures/localhost-key.pem',import.meta.url)),cert=await readFile(new URL('../network/fixtures/localhost-cert.pem',import.meta.url));let env,url;
  const server=createServer({key,cert},async(q,r)=>{
    const abort=new AbortController();q.on('aborted',()=>abort.abort());r.on('close',()=>abort.abort());
    try{const chunks=[];for await(const chunk of q)chunks.push(chunk);const request=new Request(url+q.url,{method:q.method,headers:q.headers,body:q.method==='GET'?undefined:Buffer.concat(chunks),signal:abort.signal});const response=await env.service.handle(request);r.writeHead(response.status,Object.fromEntries(response.headers));if(response.body){const body=Readable.fromWeb(response.body);body.on('error',()=>r.destroy());body.pipe(r);}else r.end();}catch{r.destroy();}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));url=`https://localhost:${server.address().port}`;
  const db=new SqliteCompanyDatabase(':memory:');env=setup({endpoint:url+'/conversations',store:db.conversations('test'),pageSize:2});
  const transport=createNodeTransport({ca:cert.toString(),localExceptions:[{hostname:'localhost',addresses:['127.0.0.1']}]});t.after(()=>{transport.close();server.closeAllConnections();server.close();db.close();});
  const post=(path,body)=>transport.fetch(new Request(url+'/conversations'+path,{method:'POST',headers:{authorization:'DPoP alice','content-type':'application/json'},body:JSON.stringify(body)}));
  const first=await post('',{message:hello});assert.equal(first.status,201);const id=(await first.json()).conversation_id,work=await env.service.claim();await env.service.reply(work,'out',{id:'reply_tls',sender:'agent',text:'Through HTTPS'});await env.service.finish(work,'completed');await post(`/${id}/close`,{});
  let cursor;const jsonIds=[];for(;;){const response=await transport.fetch(new Request(url+`/conversations/${id}/events`+(cursor?'?cursor='+cursor:''),{headers:{authorization:'DPoP alice'}}));const page=await response.json();jsonIds.push(...page.events.map(event=>event.id));cursor=page.cursor;if(!page.has_more)break;}
  const response=await transport.stream(new Request(url+`/conversations/${id}/events`,{headers:{authorization:'DPoP alice',accept:'text/event-stream'}}));const streamIds=[];for await(const frame of parseEventStream(response.body))streamIds.push(frame.event.id);assert.deepEqual(streamIds,jsonIds);assert.ok(jsonIds.length>2);
});

test('idle SSE lifetime closes normally and concurrent retention/read/append stays coherent',async t=>{
  const notifications=hints(),local=setup({notifications,streamMs:10}),localId=(await local.start(hello)).body.conversation_id,cursor=(await local.read(localId)).body.cursor;
  const response=await local.service.handle(request(localId,{stream:true,cursor}));const frames=[];for await(const frame of parseEventStream(response.body))frames.push(frame);assert.deepEqual(frames,[]);assert.equal(notifications.subscriptions,0);
  const dir=await mkdtemp(join(tmpdir(),'poppy-retention-')),path=join(dir,'db'),a=new SqliteCompanyDatabase(path),b=new SqliteCompanyDatabase(path);t.after(async()=>{a.close();b.close();await rm(dir,{recursive:true,force:true});});
  const one=setup({store:a.conversations('test')}),two=setup({store:b.conversations('test')}),start=await one.start(hello),id=start.body.conversation_id,old=(await one.read(id)).body.events[0].id;const work=await one.service.claim();await one.service.finish(work,'completed');
  const [read,removed,sent]=await Promise.all([two.read(id,{query:'?cursor='+old}),a.conversations('test').pruneEvents(id,one.clock.now()+1,1),one.send(id,{id:'racing',sender:'agent',context:{user_available:false}})]);assert.ok([200,410].includes(read.status));assert.equal(removed,1);assert.equal(sent.status,202);assert.equal((await two.read(id,{query:'?cursor='+old})).status,410);assert.deepEqual((await two.start(hello)).body,start.body);
});

test('event reads and appends keep row counts constant as own history grows',async t=>{
  const db=new SqliteCompanyDatabase(':memory:');try{const store=db.conversations('test'),env=setup({store,pageSize:2}),id=(await env.start(hello)).body.conversation_id;let cursor=(await store.read({conversationId:id})).conversations[id].events.at(-1).id;
    const read=async()=>{db.metrics.rowsRead=0;await env.read(id,{query:'?cursor='+cursor});return db.metrics.rowsRead;};
    const append=async suffix=>{db.metrics.rowsRead=0;await env.send(id,{id:suffix,sender:'agent',context:{n:suffix}});return db.metrics.rowsRead;};
    const beforeRead=await read(),beforeAppend=await append('base');for(let i=0;i<75;i++)await env.send(id,{id:'c'+i,sender:'agent',context:{n:i}});cursor=(await store.read({conversationId:id})).conversations[id].events.at(-1).id;const afterRead=await read(),afterAppend=await append('after');assert.equal(afterRead,beforeRead);assert.equal(afterAppend,beforeAppend);t.diagnostic(JSON.stringify({emptyReadRows:[beforeRead,afterRead],appendRows:[beforeAppend,afterAppend]}));
  }finally{db.close();}
});
