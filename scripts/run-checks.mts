import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
const groups:Record<string,string[]>=JSON.parse(await readFile(new URL('../.github/test-groups.json',import.meta.url),'utf8'));
async function files(dir:string):Promise<string[]>{const out=[];for(const entry of await readdir(dir,{withFileTypes:true})){const path=dir+'/'+entry.name;if(entry.isDirectory())out.push(...await files(path));else if(entry.name.endsWith('.test.mts'))out.push(path);}return out;}
const listed=Object.values(groups).flat();assert.equal(new Set(listed).size,listed.length,'test listed twice');
assert.deepEqual([...listed].sort(),(await files('tests')).sort(),'unassigned test file');
const group=process.argv[2];assert.ok(group&&(group==='all'||Object.hasOwn(groups,group)),'unknown test group');
const selected=group==='all'?listed:groups[group];
if(selected.length){const result=spawnSync(process.execPath,['--no-experimental-strip-types','--test',...selected.map(path=>path.replace(/\.mts$/,'.mjs'))],{stdio:'inherit',windowsHide:true});if(result.error)throw result.error;process.exitCode=result.status??1;}
else console.log('Cross-package integration uses installed candidate scripts in this job.');
