import {validateContents} from './package-contents.mjs';
import assert from 'node:assert/strict';
import {readFile,access} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
const consumer=resolve(process.argv[2]),directory=join(consumer,'node_modules/@poppykit/server');
const pkg=JSON.parse(await readFile(join(directory,'package.json'),'utf8'));
assert.equal(pkg.license,'MIT');assert.equal(pkg.private,false);assert.equal(pkg.publishConfig?.access,'public');
await validateContents(directory,pkg);
for(const entry of Object.values(pkg.exports)){assert.ok(entry&&typeof entry==='object'&&'types' in entry&&typeof entry.types==='string'&&'import' in entry&&typeof entry.import==='string');await access(join(directory,entry.types));await import(pathToFileURL(join(directory,entry.import)).href);}
const {SqliteCompanyDatabase}=await import(pathToFileURL(join(directory,pkg.exports['./sqlite'].import)).href);
const db=new SqliteCompanyDatabase(':memory:');db.close();
for(const path of pkg.files)await access(join(directory,path));
const result=spawnSync(process.execPath,[join(directory,'examples/quickstart.mjs')],{stdio:'inherit',windowsHide:true});assert.equal(result.status,0);
console.log(JSON.stringify({platform:process.platform,node:process.version,package:pkg.name,version:pkg.version,checks:['exports','declarations-present','packaged-documents','SQLite','executable-quickstart']}));
