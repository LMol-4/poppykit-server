import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createPostgresPool, migratePostgres, postgresMigration } from '../dist/postgres.js';
const schemas = ['poppy_client','poppy_provider','poppy_server'] as const;
const inspect = process.argv.includes('--inspect');
assert.ok(inspect || process.argv.includes('--allow-disposable-schema'), 'explicit disposable-schema permission required');
const env=process.env, local=env.D1_LOCAL==='1';
assert.ok(env.D1_CLIENT_DIR,'D1_CLIENT_DIR required');
const clientAdapters = await import(pathToFileURL(resolve(env.D1_CLIENT_DIR,'dist/postgres.js')).href) as Pick<typeof import('../dist/postgres.js'),'postgresMigration'|'migratePostgres'>;
if(!local) {
  assert.equal(env.PGHOST,'aws-0-eu-west-1.pooler.supabase.com'); assert.equal(env.PGPORT,'6543');
  assert.equal(env.PGUSER,'postgres.lcdgtqscexzzxmvggjtt'); assert.equal(env.PGDATABASE,'postgres'); assert.ok(env.PGPASSWORD);
} else { assert.equal(env.PGHOST,'127.0.0.1'); assert.equal(env.PGUSER,'postgres'); }
const pool=createPostgresPool({host:env.PGHOST,port:Number(env.PGPORT),user:env.PGUSER,password:env.PGPASSWORD,database:env.PGDATABASE,
  ssl:local?false:{ca:readFileSync(env.PGSSLROOTCERT!,'utf8'),rejectUnauthorized:true},max:2,application_name:'poppykit-d1-check'});
pool.on('error',()=>{process.exitCode=1;});
const owned = new Map<string,number>(), marker='d1_'+randomUUID();
const receipt: Record<string,unknown>={marker,target:local?'plain-postgres':'supabase-transaction-pooler',status:'FAIL',cleanup:'NOT_RUN'};
async function execute(cwd:string,files:string[]) {
  const code=await new Promise<number>((done,reject)=>{const child=spawn(process.execPath,['--no-experimental-strip-types','--test','--test-concurrency=1',...files],{cwd,env:{...env,D1_POSTGRES:'1',D1_NAMESPACE:marker},stdio:'inherit',windowsHide:true});child.on('error',reject);child.on('close',n=>done(n??1));});
  assert.equal(code,0,`Postgres contract suite failed in ${cwd}`);
}
try {
  const client=await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const identity=(await client.query("SELECT current_setting('server_version') AS version,ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")).rows[0];
    assert.equal(identity.ssl,!local); receipt.server=identity;
    receipt.schemas=(await client.query('SELECT nspname FROM pg_namespace WHERE nspname=ANY($1)',[schemas])).rows.map(row=>row.nspname);
    await client.query('COMMIT');
  } finally { client.release(); }
  receipt.migrations=await Promise.all(schemas.map(async schema=>({schema,sha256:createHash('sha256').update(await (schema==='poppy_server'?postgresMigration(schema):clientAdapters.postgresMigration(schema))).digest('hex')})));
  if(!inspect) {
    assert.deepEqual(receipt.schemas,[],'refuse pre-existing SDK schemas; no writes performed');
    for(const schema of schemas) {
      const migrate=schema==='poppy_server'?migratePostgres:clientAdapters.migratePostgres;
      const sql=await (schema==='poppy_server'?postgresMigration(schema):clientAdapters.postgresMigration(schema));
      const client=await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query("SET LOCAL statement_timeout='5s'");
        // CREATE SCHEMA fails on an intervening creator; never adopt its objects.
        await client.query(sql);
        const oid=Number((await client.query('SELECT oid FROM pg_namespace WHERE nspname=$1',[schema])).rows[0].oid);
        await client.query('COMMIT'); owned.set(schema,oid);
      } catch(error) {await client.query('ROLLBACK').catch(()=>{});throw error;} finally {client.release();}
      await migrate(pool,schema); // Idempotent explicit migration, no request-time DDL.
    }
    if(process.argv.includes('--lifecycle-only'))await execute(process.cwd(),['tests/postgres-lifecycle.test.mjs']);
    else if(process.argv.includes('--conversation-only'))await execute(process.cwd(),['tests/conversation/postgres-adapter-contract.test.mjs']);
    else if(!process.argv.includes('--client-only'))await execute(process.cwd(),['tests/postgres-storage.test.mjs','tests/postgres-lifecycle.test.mjs','tests/issuer-contract.test.mjs','tests/conversation/postgres-adapter-contract.test.mjs']);
    assert.ok(env.D1_CLIENT_DIR,'D1_CLIENT_DIR required');
    if(!process.argv.includes('--conversation-only')&&!process.argv.includes('--lifecycle-only'))await execute(resolve(env.D1_CLIENT_DIR),['tests/provider.test.mjs','tests/postgres.test.mjs','tests/adapter-contract.test.mjs']);
    receipt.status='PASS';
  } else receipt.status='PASS_READ_ONLY';
} catch(error) {
  receipt.error=error instanceof Error?{name:error.name,message:error.message,code:'code' in error?error.code:undefined}:{name:'unknown'};
  process.exitCode=1;
} finally {
  try {
    for(const [schema,oid] of owned) {
      const client=await pool.connect();
      try {
        await client.query('BEGIN');
        assert.equal(Number((await client.query('SELECT oid FROM pg_namespace WHERE nspname=$1',[schema])).rows[0]?.oid),oid,'schema ownership changed');
        const tables=(await client.query("SELECT tablename FROM pg_tables WHERE schemaname=$1",[schema])).rows.map(row=>row.tablename as string);
        const expected=schema==='poppy_server'?['records','events','event_cursors','schema_version']:schema==='poppy_client'?['records','outbound','checkpoints','schema_version']:['records','schema_version'];
        assert.deepEqual([...tables].sort(),expected.sort(),'unexpected schema object; refuse cleanup');
        for(const table of tables) if(table!=='schema_version') {
          assert.equal(Number((await client.query(`SELECT count(*) AS n FROM ${schema}.${table} WHERE position($1 in ns)=0`,[marker])).rows[0].n),0,'unowned namespace; refuse cleanup');
          await client.query(`DROP TABLE ${schema}.${table}`);
        }
        await client.query(`DROP TABLE ${schema}.schema_version`);
        await client.query(`DROP SCHEMA ${schema}`);
        await client.query('COMMIT');
      } catch(error) {await client.query('ROLLBACK');throw error;} finally {client.release();}
    }
    if(owned.size) assert.equal((await pool.query('SELECT nspname FROM pg_namespace WHERE nspname=ANY($1)',[[...owned.keys()]])).rowCount,0);
    receipt.cleanup=owned.size?'PASS_VERIFIED':'NO_WRITES';
  } catch(error) {receipt.cleanup='FAIL';receipt.cleanupError=error instanceof Error?error.message:'unknown';process.exitCode=1;}
  await pool.end(); console.log(JSON.stringify(receipt,null,2));
}
