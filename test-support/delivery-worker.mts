import { expectValue } from './assertions.mjs';
import { SqliteCompanyDatabase } from '../dist/sqlite.js';
import { setup, endpoint } from '../tests/conversation/support.mjs';
const [path,id,cursor]=process.argv.slice(2),db=new SqliteCompanyDatabase(path);
try{const env=setup({store:db.conversations('test'),pollIntervalMs:30});expectValue(process.send).call(process, {ready:true});const response=await env.service.handle(new Request(`${endpoint}/${id}/events?cursor=${cursor}&wait=2`,{headers:{authorization:'DPoP alice'}}));const page=await response.json();expectValue(process.send).call(process, {message:page.events[0]?.message?.id});}finally{db.close();process.disconnect();}
