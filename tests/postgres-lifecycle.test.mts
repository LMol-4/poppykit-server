import baseTest from 'node:test';
import assert from 'node:assert/strict';
import { PostgresCompanyDatabase, migratePostgres, createPostgresPool } from '../dist/postgres.js';
import type { PostgresConnection } from '../dist/postgres.js';
import { testPool } from '../test-support/postgres.mjs';
const test=process.env.D1_POSTGRES==='1'?baseTest:baseTest.skip;
baseTest('Postgres pool rejects TLS downgrade through pg connection-string overrides',()=>{
  for (const parameter of ['ssl=no-verify','sslmode=no-verify','sslmode=disable','uselibpqcompat=true']) assert.throws(()=>createPostgresPool({connectionString:'postgres://example.test/database?'+parameter}),/TLS/);
  assert.throws(()=>createPostgresPool({ssl:{rejectUnauthorized:false}}),/verification/);
});
test('Postgres lifecycle: savepoints, escaped handles, explicit schema versions and caller pool ownership',{timeout:15000},async()=>{
  const pool=testPool(), db=new PostgresCompanyDatabase(pool),ns=(process.env.D1_NAMESPACE??'d1')+':lifecycle';
  let rollbackWindow:(()=>Promise<void>)|undefined;
  pool.on('connect',client=>{
    client.query=new Proxy(client.query,{apply(query,receiver,args:unknown[]){
      const result:unknown=Reflect.apply(query,receiver,args);
      if(rollbackWindow&&typeof args[0]==='string'&&args[0].startsWith('ROLLBACK TO SAVEPOINT ')){
        const window=rollbackWindow;rollbackWindow=undefined;
        return (result as Promise<unknown>).then(async value=>{await window();return value;});
      }
      return result;
    }});
  });
  try {
    let escaped: PostgresConnection | undefined;
    await db.withTransaction(async connection=>{
      escaped=connection;
      await connection.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','outer','{}']);
      await assert.rejects(db.withTransaction(async nested=>{
        await nested.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','inner','{}']);
        throw new Error('abort nested');
      }),/abort nested/);
      assert.deepEqual((await connection.query('SELECT id FROM poppy_server.records WHERE ns=$1 ORDER BY id',[ns])).rows.map(row=>row.id),['outer']);
    });
    assert.ok(escaped); await assert.rejects(escaped.query('SELECT 1'),/expired/);
    let late: Promise<void> | undefined,releaseLate!:()=>void,enteredLate!:()=>void;
    const lateGate=new Promise<void>(resolve=>{releaseLate=resolve;}),lateReady=new Promise<void>(resolve=>{enteredLate=resolve;});
    await assert.rejects(db.withTransaction(async()=>{
      late=db.withTransaction(async nested=>{enteredLate();await lateGate;await nested.query('SELECT 1');});
      await lateReady;
    }),/unawaited nested/);
    releaseLate();assert.ok(late);await assert.rejects(late,/expired/);
    assert.equal((await pool.query('SELECT 1 AS n')).rows[0].n,1,'late child must not use a released connection');
    await db.withTransaction(async outer=>{
      let descendant:Promise<unknown>|undefined,entered!:()=>void,release!:()=>void,resumed!:()=>void;
      const ready=new Promise<void>(resolve=>{entered=resolve;}),gate=new Promise<void>(resolve=>{release=resolve;}),attempted=new Promise<void>(resolve=>{resumed=resolve;});
      await assert.rejects(db.withTransaction(async()=>{
        descendant=db.withTransaction(async nested=>{
          await nested.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','descendant-before','{}']);
          entered();await gate;
          try{await nested.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','descendant-after','{}']);}finally{resumed();}
        }).then(()=>null,error=>error as unknown);
        await ready;
        rollbackWindow=async()=>{release();await attempted;};
      }),/unawaited nested/);
      await outer.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','outer-after-catch','{}']);
      assert.ok(descendant);const error=await descendant;assert.ok(error instanceof Error);assert.match(error.message,/expired/);
      assert.deepEqual((await outer.query('SELECT id FROM poppy_server.records WHERE ns=$1 ORDER BY id',[ns])).rows.map(row=>row.id),['outer','outer-after-catch']);
    });
    await db.withTransaction(async connection=>{
      let entered!:()=>void,release!:()=>void;
      const ready=new Promise<void>(resolve=>{entered=resolve;}),gate=new Promise<void>(resolve=>{release=resolve;});
      const first=db.withTransaction(async nested=>{
        await nested.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','overlap-a','{}']);
        entered();await gate;throw new Error('abort overlap');
      });
      await ready;
      await assert.rejects(db.withTransaction(async nested=>{await nested.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','overlap-b','{}']);}),/concurrent nested/);
      release();await assert.rejects(first,/abort overlap/);
      await db.withTransaction(async()=>{
        await db.withTransaction(async recursive=>{await recursive.query('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4)',[ns,'business','recursive','{}']);});
      });
      assert.deepEqual((await connection.query('SELECT id FROM poppy_server.records WHERE ns=$1 ORDER BY id',[ns])).rows.map(row=>row.id),['outer','outer-after-catch','recursive']);
    });
    await pool.query('UPDATE poppy_server.schema_version SET version=2');
    try {
      await assert.rejects(db.run(async()=>{}),/unsupported.*version/);
      await assert.rejects(migratePostgres(pool,'poppy_server'),/unsupported.*version/);
    } finally {await pool.query('UPDATE poppy_server.schema_version SET version=1');}
    await migratePostgres(pool,'poppy_server');
    await db.close(); await assert.rejects(db.run(async()=>{}),/closed/);
    assert.equal((await pool.query('SELECT 1 AS n')).rows[0].n,1,'adapter close must leave caller pool usable');
    assert.throws(()=>createPostgresPool({ssl:{rejectUnauthorized:false}}),/verification/);
  } finally {await db.close();await pool.end();}
});
