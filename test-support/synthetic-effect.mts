// Application-owned idempotency, separate from protocol acceptance/publication receipts.
// Contract: exact payload bytes + tenant + stable work ID; retain through every retry.
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { createHash } from 'node:crypto';
import type { PathLike } from 'fs';
export function effect(path: PathLike,tenant: SQLInputValue,key: SQLInputValue,payload: { record: string; value: number; }){
  const db=new DatabaseSync(path),digest=createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  try{
    db.exec('PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS effects (tenant TEXT, id TEXT, digest TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(tenant,id)); BEGIN IMMEDIATE');
    const previous=db.prepare('SELECT digest,result FROM effects WHERE tenant=? AND id=?').get(tenant,key);
    if(previous&&previous.digest!==digest)throw new Error('effect_payload_conflict');
    const result=previous?.result??'opaque-result-'+digest;
    if(!previous)db.prepare('INSERT INTO effects VALUES (?,?,?,?)').run(tenant,key,digest,result);
    db.exec('COMMIT');return result;
  }catch(error){if(db.isTransaction)db.exec('ROLLBACK');throw error;}finally{db.close();}
}
