import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdir,rm,readFile,readdir,writeFile} from 'node:fs/promises';
import {resolve,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=resolve(fileURLToPath(new URL('..',import.meta.url))),directory=resolve(root,'coverage');
assert.equal(resolve(process.cwd()),root,'run coverage from repository root');
assert.equal(relative(root,directory),'coverage');assert.ok(!isAbsolute(relative(root,directory)));
// Coverage is a generated local report, never part of the npm package allowlist.
await rm(directory,{recursive:true,force:true});await mkdir(directory,{recursive:true});
const groups:Record<string,string[]>=JSON.parse(await readFile('.github/test-groups.json','utf8'));
const files=Object.values(groups).flat();assert.equal(new Set(files).size,files.length);
const arguments_=['--no-experimental-strip-types','--experimental-test-coverage','--test-coverage-include=**/dist/**/*.js','--test-coverage-exclude=**/node_modules/**','--test-reporter=spec','--test-reporter-destination='+resolve(directory,'summary.txt'),'--test-reporter=lcov','--test-reporter-destination='+resolve(directory,'lcov.info'),'--test',...files.map(file=>file.replace(/\.mts$/,'.mjs'))];
const run=spawnSync(process.execPath,arguments_,{cwd:root,env:{...process.env,NODE_V8_COVERAGE:resolve(directory,'raw')},encoding:'utf8',windowsHide:true});
await writeFile(resolve(directory,'runner.log'),run.stdout+run.stderr);if(run.error)throw run.error;
assert.equal(run.status,0,'coverage suite failed; see coverage/runner.log and summary.txt');
interface Counts{found:number;hit:number;percent:number|null;}
const count=(found:number,hit:number):Counts=>({found,hit,percent:found?Number((100*hit/found).toFixed(4)):null});
interface Covered{path:string;sha256:string;line:Counts;branch:Counts;function:Counts;uncoveredLines:number[];}
const covered:Covered[]=[];const lcov=await readFile(resolve(directory,'lcov.info'),'utf8');
for(const block of lcov.split('end_of_record')){
 const source=block.match(/^SF:(.+)$/m)?.[1]?.trim();if(!source)continue;
 const path=source.replaceAll('\\','/');assert.ok(path.startsWith('dist/')&&!path.includes('/node_modules/'),'unexpected coverage source '+path);
 const integer=(tag:string)=>Number(block.match(new RegExp('^'+tag+':(\\d+)$','m'))?.[1]??0);
 covered.push({path,sha256:createHash('sha256').update(await readFile(resolve(root,path))).digest('hex'),line:count(integer('LF'),integer('LH')),branch:count(integer('BRF'),integer('BRH')),function:count(integer('FNF'),integer('FNH')),uncoveredLines:[...block.matchAll(/^DA:(\d+),0(?:,.*)?$/gm)].map(match=>Number(match[1]))});
}
async function production(directory='dist'):Promise<string[]>{const paths:string[]=[];for(const entry of await readdir(directory,{withFileTypes:true})){const path=directory+'/'+entry.name;if(entry.isDirectory())paths.push(...await production(path));else if(path.endsWith('.js'))paths.push(path);}return paths;}
const all=await production(),loaded=new Set(covered.map(file=>file.path));
const totals=(kind:'line'|'branch'|'function')=>count(covered.reduce((n,file)=>n+file[kind].found,0),covered.reduce((n,file)=>n+file[kind].hit,0));
const report={runtime:process.version,platform:process.platform,command:[process.execPath,...arguments_],scope:'First-party compiled production dist JavaScript loaded by this source suite. Third-party node_modules excluded. Unloaded modules listed separately, not silently counted as covered.',sourceMaps:'Production tsconfig emits no source maps. Metrics and uncovered line numbers refer to compiled dist JS; no claim of remapping to TypeScript. Raw V8 source-map-cache retained when the runtime supplies one.',subprocess:'NODE_V8_COVERAGE inherited by child processes; raw files retained. Native runner summary may not include arbitrary child-process execution. Killed/crashed workers may not flush counters. Installed-candidate checks are separate evidence, not merged into source-suite percentages.',exclusions:['node_modules: third-party dependencies','tests, test-support, scripts: harness/build/release tooling outside first-party production dist'],line:totals('line'),branch:totals('branch'),function:totals('function'),covered,unloaded:all.filter(path=>!loaded.has(path)).sort()};
await writeFile(resolve(directory,'report.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({line:report.line,branch:report.branch,function:report.function,loaded:covered.length,unloaded:report.unloaded,status:'passed'}));
