import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {runSessionAdapterContract,runBrowserCookieAdapterContract} from '../dist/adapter-contract.js';
import {SqliteCompanyDatabase} from '../dist/sqlite.js';
import {PostgresCompanyDatabase} from '../dist/postgres.js';
import {testPool} from '../test-support/postgres.mjs';
for(const engine of ['SQLite',...(process.env.D1_POSTGRES==='1'?['Postgres']:[])]){
  const fixture=async()=>{
    const dir=await mkdtemp(join(tmpdir(),'session-contract-')),pool=engine==='Postgres'?testPool():undefined,path=join(dir,'db.sqlite'),namespace=randomUUID();
    const a=pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(path),b=pool?new PostgresCompanyDatabase(pool):new SqliteCompanyDatabase(path);
    return {a,b,namespace,close:async()=>{await a.close();await b.close();await pool?.end();await rm(dir,{recursive:true,force:true});}};
  };
  runSessionAdapterContract(async()=>{const f=await fixture();return {store:f.a.sessions(f.namespace),second:f.b.sessions(f.namespace),close:f.close};});
  runBrowserCookieAdapterContract(async()=>{const f=await fixture();return {store:f.a.browserCookies(f.namespace),second:f.b.browserCookies(f.namespace),close:f.close};});
}
