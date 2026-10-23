import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,delimiter} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mandatory,successful,identity,inspect,check} from '../scripts/release-candidate.mjs';
const commit='a'.repeat(40);
test('release requires every allowlisted prerequisite success',()=>{
  const good=Object.fromEntries(mandatory.map(name=>[name,{result:'success'}]));successful(good);
  for(const name of mandatory){
    for(const result of ['failure','cancelled','skipped','pending','',null,undefined])assert.throws(()=>successful({...good,[name]:{result}}),name+':'+result);
    const missing={...good};delete missing[name];assert.throws(()=>successful(missing),name+':missing');
  }
  assert.throws(()=>successful(null));
});
test('release identity rejects wrong commit version tag ref and repository',()=>{
  const good={commit,expectedCommit:commit,version:'1.2.3',expectedVersion:'1.2.3',tag:'v1.2.3',ref:'refs/tags/v1.2.3',release:true,repository:'o/r',expectedRepository:'o/r'};identity(good);
  for(const [key,value] of [['commit','b'.repeat(40)],['expectedCommit',''],['version','1.2.4'],['expectedVersion','2.0.0'],['tag','latest'],['ref','refs/heads/main'],['repository','attacker/r']])assert.throws(()=>identity({...good,[key]:value}),key);
});
test('real candidate checks reject missing artifacts tampering and changed manifests',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'release gate ü '));
  const originalPath=process.env.PATH;
  // Git Bash selects GNU tar, whose archive parser treats a drive colon as a remote host.
  if(process.platform==='win32'){const tools=join(process.env.ProgramFiles??'C:/Program Files','Git/usr/bin');await access(join(tools,'tar.exe'));process.env.PATH=tools+delimiter+(originalPath??'');}
  const old=process.env.GITHUB_SHA;process.env.GITHUB_SHA=commit;
  try{
    const root=new URL('../',import.meta.url),pkg=JSON.parse(await readFile(new URL('package.json',root),'utf8'));
    const specs=[pkg];
    if(pkg.name==='@poppykit/cli')for(const name of ['client','server']){
      const pin=JSON.parse(await readFile(new URL(`.github/${name}-candidate.json`,root),'utf8'));
      specs.push({name:`@poppykit/${name}`,version:pin.version??'0.0.0',repository:{url:`https://github.com/LMol-4/poppykit-${name}.git`}});
    }
    for(const spec of specs){
      const source=join(dir,spec.name.split('/')[1]);await mkdir(join(source,'package'),{recursive:true});await writeFile(join(source,'package/package.json'),JSON.stringify(spec));
      const tar=spawnSync('tar',['-czf',`${spec.name.replace('@','').replace('/','-')}-${spec.version}.tgz`,'-C',source,'package'],{cwd:dir,windowsHide:true,encoding:'utf8'});assert.equal(tar.status,0,tar.stderr);
    }
    const manifest=await inspect(dir),bytes=JSON.stringify(manifest),sha=createHash('sha256').update(bytes).digest('hex');await writeFile(join(dir,'release-manifest.json'),bytes);
    await t.test('GNU tar inspects absolute space and Unicode candidate paths',async()=>assert.deepEqual(await check(dir,sha),manifest));
    // Exercise the real gate executable and its output boundary without any publisher.
    const actualCommit=spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8',windowsHide:true}).stdout.trim();
    process.env.GITHUB_SHA=actualCommit;
    const actual=await inspect(dir),actualBytes=JSON.stringify(actual),actualSha=createHash('sha256').update(actualBytes).digest('hex');
    await writeFile(join(dir,'release-manifest.json'),actualBytes);
    const output=join(dir,'outputs'),script=new URL('../scripts/release-candidate.mjs',import.meta.url);
    const good=Object.fromEntries(mandatory.map(name=>[name,{result:'success'}]));
    const env={...process.env,GITHUB_SHA:actualCommit,EXPECTED_SHA:actualCommit,RELEASE_VERSION:pkg.version,RELEASE_TAG:'v'+pkg.version,RELEASE_CONTEXT:'false',GITHUB_REPOSITORY:actual.repository,EXPECTED_MANIFEST_SHA:actualSha,NEEDS_JSON:JSON.stringify(good),GITHUB_OUTPUT:output};
    const gate=async(extra={})=>{await writeFile(output,'');const result=spawnSync(process.execPath,[script.pathname.replace(/^\/(\w:)/,'$1'),'gate',dir],{env:{...env,...extra},encoding:'utf8',windowsHide:true});return {status:result.status,output:await readFile(output,'utf8'),error:result.stderr};};
    const passed=await gate();assert.equal(passed.status,0,passed.error);assert.equal(passed.output,'ready=true\n');
    for(const result of ['failure','cancelled','skipped',null]){const value=await gate({NEEDS_JSON:JSON.stringify({...good,contracts:{result}})});assert.notEqual(value.status,0);assert.equal(value.output,'');}
    const missing={...good};delete missing.fast;
    for(const extra of [{NEEDS_JSON:JSON.stringify(missing)},{NEEDS_JSON:''},{EXPECTED_SHA:'b'.repeat(40)},{RELEASE_VERSION:'9.9.9'},{RELEASE_TAG:'wrong'},{EXPECTED_MANIFEST_SHA:'0'.repeat(64)},{RELEASE_CONTEXT:'true',GITHUB_REF:'refs/heads/main'}]){const value=await gate(extra);assert.notEqual(value.status,0);assert.equal(value.output,'');}
    for(const name of ['EXPECTED_SHA','RELEASE_VERSION','RELEASE_TAG','GITHUB_REPOSITORY'])for(const empty of ['',undefined]){const value=await gate({RELEASE_CONTEXT:'true',GITHUB_REF:'refs/tags/v'+pkg.version,[name]:empty});assert.notEqual(value.status,0);assert.equal(value.output,'');}
    const actualFile=join(dir,actual.files[0].name),savedFile=await readFile(actualFile);
    await rm(actualFile);let rejected=await gate();assert.notEqual(rejected.status,0);assert.equal(rejected.output,'');await writeFile(actualFile,savedFile);
    await writeFile(actualFile,Buffer.concat([savedFile,Buffer.from('tampered')]));rejected=await gate();assert.notEqual(rejected.status,0);assert.equal(rejected.output,'');await writeFile(actualFile,savedFile);
    process.env.GITHUB_SHA=commit;await writeFile(join(dir,'release-manifest.json'),bytes);
    await assert.rejects(check(dir,''));await assert.rejects(check(dir,'0'.repeat(64)));
    const file=join(dir,manifest.files[0].name),original=await readFile(file);
    await rm(file);await assert.rejects(check(dir,sha));await writeFile(file,original);
    await writeFile(file,Buffer.concat([original,Buffer.from('tampered')]));await assert.rejects(check(dir,sha));await writeFile(file,original);
    await writeFile(join(dir,'release-manifest.json'),bytes+' ');await assert.rejects(check(dir,sha));
  }finally{if(originalPath===undefined)delete process.env.PATH;else process.env.PATH=originalPath;if(old===undefined)delete process.env.GITHUB_SHA;else process.env.GITHUB_SHA=old;await rm(dir,{recursive:true,force:true});}
});
