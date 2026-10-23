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
test('Postgres lifecycle: savepoints, escaped handles, explicit schema versions and caller pool ownership',async()=>{
  const pool=testPool(), db=new PostgresCompanyDatabase(pool),ns=(process.env.D1_NAMESPACE??'d1')+':lifecycle';
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
      assert.deepEqual((await connection.query('SELECT id FROM poppy_server.records WHERE ns=$1 ORDER BY id',[ns])).rows.map(row=>row.id),['outer','recursive']);
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
