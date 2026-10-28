import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdir,cp} from 'node:fs/promises';
import {resolve,relative,dirname,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
assert.equal(resolve(process.cwd()),root,'run harness-artifact from repository root');
const mode=process.argv[2];assert.ok(mode==='write'||mode==='check','expected write or check');
const tip=spawnSync('git',['-c','safe.directory='+root.replaceAll('\\','/'),'rev-parse','HEAD'],{cwd:root,encoding:'utf8',windowsHide:true});assert.equal(tip.status,0,tip.stderr);
const commit=tip.stdout.trim();if(process.env.GITHUB_SHA)assert.equal(commit,process.env.GITHUB_SHA,'harness checkout differs from CI source');
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
function local(path:string){const absolute=resolve(root,path),value=relative(root,absolute);assert.ok(value&&!isAbsolute(value)&&!value.startsWith('..'),'harness path escapes repository');return absolute;}
interface Entry{source:string;sourceSha256:string;output:string;outputSha256:string;}
interface Manifest{schema:1;commit:string;node:string;minimumNode:string;typescript:string;files:Entry[];}
function manifest(value:unknown):asserts value is Manifest{
 assert.ok(value&&typeof value==='object'&&'schema' in value&&value.schema===1&&'commit' in value&&typeof value.commit==='string'&&'node' in value&&typeof value.node==='string'&&'typescript' in value&&typeof value.typescript==='string'&&'files' in value&&Array.isArray(value.files));
 for(const file of value.files)assert.ok(file&&typeof file==='object'&&typeof file.source==='string'&&typeof file.output==='string'&&typeof file.sourceSha256==='string'&&typeof file.outputSha256==='string');
}
const destination=resolve(root,'.test-build/harness');
const {readdir}=await import('node:fs/promises');
async function entries(directory:string):Promise<string[]>{const files:string[]=[];for(const entry of await readdir(local(directory),{withFileTypes:true})){const path=directory+'/'+entry.name;if(entry.isDirectory())files.push(...await entries(path));else if(entry.name.endsWith('.mts'))files.push(path);}return files;}
const sources=(await Promise.all(['scripts','tests','test-support'].map(entries))).flat().sort();
// Hash the exact LF checkout bytes on every supported OS, enforced by Git attributes.
for(const source of sources)assert.ok(!(await readFile(local(source),'utf8')).includes('\r'),'canonical .mts must use LF: '+source);
if(mode==='write'){
 const files:Entry[]=[];
 for(const source of sources){const output=source.replace(/\.mts$/,'.mjs'),bytes=await readFile(local(output));files.push({source,sourceSha256:hash(await readFile(local(source))),output,outputSha256:hash(bytes)});const target=resolve(destination,output);assert.ok(relative(destination,target)&&!relative(destination,target).startsWith('..'));await mkdir(dirname(target),{recursive:true});await cp(local(output),target);}
 const compiler:unknown=JSON.parse(await readFile(local('node_modules/typescript/package.json'),'utf8'));assert.ok(compiler&&typeof compiler==='object'&&'version' in compiler&&typeof compiler.version==='string');
 const record:Manifest={schema:1,commit,node:process.version,minimumNode:(await readFile(local('.node-version'),'utf8')).trim(),typescript:compiler.version,files};await writeFile(resolve(destination,'harness-manifest.json'),JSON.stringify(record,null,2)+'\n');
 console.log(JSON.stringify({status:'written',commit,files:files.length,destination}));
}else{
 const record:unknown=JSON.parse(await readFile(local('harness-manifest.json'),'utf8'));manifest(record);assert.equal(record.commit,commit,'harness compiled from another commit');assert.equal(record.node,process.version,'harness runtime changed');assert.equal(record.minimumNode,(await readFile(local('.node-version'),'utf8')).trim(),'runtime baseline changed');assert.equal(record.typescript,'5.9.3');
 const seen=new Set<string>();for(const file of record.files){assert.match(file.source,/^(?:scripts|tests|test-support)\/.+\.mts$/);assert.equal(file.output,file.source.replace(/\.mts$/,'.mjs'));assert.ok(!seen.has(file.source),'duplicate harness entry');seen.add(file.source);assert.equal(hash(await readFile(local(file.source))),file.sourceSha256,'harness source changed: '+file.source);assert.equal(hash(await readFile(local(file.output))),file.outputSha256,'harness output changed: '+file.output);}
 assert.deepEqual([...seen].sort(),sources,'harness omitted or added canonical sources');
 console.log(JSON.stringify({status:'checked',commit,files:record.files.length}));
}
