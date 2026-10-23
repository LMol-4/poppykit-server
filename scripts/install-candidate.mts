import assert from 'node:assert/strict';
import {readFile,mkdir,cp,access} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
const [directory,mode='clean']=process.argv.slice(2);assert.ok(directory,'candidate directory required');assert.ok(mode==='clean'||mode==='source','unknown candidate install mode');const base=resolve(directory),manifest=JSON.parse(await readFile(join(base,'release-manifest.json'),'utf8'));
const target=join(base,'clean install ü');await mkdir(target,{recursive:true});await writePackage();
async function writePackage(){const {writeFile}=await import('node:fs/promises');await writeFile(join(target,'package.json'),JSON.stringify({name:'poppykit-candidate-check',private:true,type:'module'}));}
const npmCli=process.env.npm_execpath??join(dirname(process.execPath),'node_modules/npm/bin/npm-cli.js');
if(process.platform==='win32')await access(npmCli);
const executable=process.platform==='win32'?process.execPath:'npm';
const prefix=process.platform==='win32'?[npmCli]:[];
const result=spawnSync(executable,[...prefix,'install','--prefix',target,'--ignore-scripts','--no-package-lock','--no-audit','--no-fund',...manifest.files.map((row:{name:string})=>join(base,row.name))],{stdio:'inherit',windowsHide:true});
assert.equal(result.status,0,'candidate install failed');
if(mode==='source')await cp(join(target,'node_modules',manifest.package,'dist'),resolve('dist'),{recursive:true});
console.log(target);
