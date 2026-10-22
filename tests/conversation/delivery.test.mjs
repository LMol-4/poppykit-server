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
