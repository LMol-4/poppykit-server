import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,mkdir,readFile,writeFile,cp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
test('compiled harness binds complete LF source inventory and unchanged emitted bytes',async()=>{
 const root=await mkdtemp(join(tmpdir(),'typed harness ü '));
 const run=(mode:string,env:NodeJS.ProcessEnv={})=>spawnSync(process.execPath,[join(root,'scripts/harness-artifact.mjs'),mode],{cwd:root,env:{...process.env,GITHUB_SHA:'',...env},encoding:'utf8',windowsHide:true});
 const git=(args:string[])=>{const result=spawnSync('git',['-c','safe.directory='+root,...args],{cwd:root,encoding:'utf8',windowsHide:true});assert.equal(result.status,0,result.stderr);return result.stdout.trim();};
 try{
  for(const path of ['scripts','tests','test-support','node_modules/typescript'])await mkdir(join(root,path),{recursive:true});
  await writeFile(join(root,'node_modules/typescript/package.json'),JSON.stringify({version:'5.9.3'}));
  await writeFile(join(root,'.node-version'),process.version.slice(1)+'\n');
  await cp(new URL('../scripts/harness-artifact.mjs',import.meta.url),join(root,'scripts/harness-artifact.mjs'));
  await writeFile(join(root,'scripts/harness-artifact.mts'),'// canonical manifest tool fixture data\n');
  await writeFile(join(root,'tests/example.mts'),'// canonical test fixture data\n');await writeFile(join(root,'tests/example.mjs'),'// emitted fixture data\n');
  git(['init','--quiet']);git(['-c','user.name=Harness test','-c','user.email=harness@example.invalid','commit','--quiet','--allow-empty','-m','Fixture']);
  const commit=git(['rev-parse','HEAD']);assert.equal(run('write').status,0);
  await cp(join(root,'.test-build/harness/harness-manifest.json'),join(root,'harness-manifest.json'));
  const manifest=await readFile(join(root,'harness-manifest.json'),'utf8');
  assert.equal(run('check').status,0,run('check').stderr);assert.notEqual(run('check',{GITHUB_SHA:'0'.repeat(40)}).status,0);
  await writeFile(join(root,'.node-version'),'24.99.0\n');assert.notEqual(run('check').status,0,'changed runtime baseline fails');await writeFile(join(root,'.node-version'),process.version.slice(1)+'\n');
  const changed: {commit:string;files:unknown[]}=JSON.parse(manifest);changed.commit='0'.repeat(40);await writeFile(join(root,'harness-manifest.json'),JSON.stringify(changed));assert.notEqual(run('check').status,0);
  changed.commit=commit;changed.files.pop();await writeFile(join(root,'harness-manifest.json'),JSON.stringify(changed));assert.notEqual(run('check').status,0,'omitted canonical source fails');await writeFile(join(root,'harness-manifest.json'),manifest);
  await writeFile(join(root,'tests/example.mjs'),'// tampered output\n');assert.notEqual(run('check').status,0);await writeFile(join(root,'tests/example.mjs'),'// emitted fixture data\n');
  await writeFile(join(root,'tests/example.mts'),'// tampered source\n');assert.notEqual(run('check').status,0);await writeFile(join(root,'tests/example.mts'),'// canonical test fixture data\r\n');assert.notEqual(run('check').status,0,'CRLF checkout violates exact source-byte contract');
  await writeFile(join(root,'tests/example.mts'),'// canonical test fixture data\n');assert.equal(run('check').status,0);
  assert.match(await readFile(new URL('../.gitattributes',import.meta.url),'utf8'),/^\*\.mts text eol=lf$/m);
 }finally{await rm(root,{recursive:true,force:true});}
});
