import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { runIssuerAdapterContract } from '../dist/adapter-contract.js';
import { SqliteCompanyDatabase } from '../dist/sqlite.js';
import { PostgresCompanyDatabase } from '../dist/postgres.js';
import { testPool } from '../test-support/postgres.mjs';
runIssuerAdapterContract(async()=>{
  const dir=await mkdtemp(join(tmpdir(),'issuer-contract-')),path=join(dir,'db.sqlite'),a=new SqliteCompanyDatabase(path),b=new SqliteCompanyDatabase(path);
  return {store:a.issuer('contract'),second:b.issuer('contract'),close:async()=>{a.close();b.close();await rm(dir,{recursive:true});}};
});
if(process.env.D1_POSTGRES==='1')runIssuerAdapterContract(async()=>{
  const pool=testPool(),a=new PostgresCompanyDatabase(pool),b=new PostgresCompanyDatabase(pool),namespace=(process.env.D1_NAMESPACE??'d1')+':'+randomUUID();
  return {store:a.issuer(namespace),second:b.issuer(namespace),close:async()=>{await a.close();await b.close();await pool.end();}};
});
