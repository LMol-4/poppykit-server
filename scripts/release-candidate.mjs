import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile,writeFile,readdir} from 'node:fs/promises';
import {join,resolve,dirname,basename} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const root=fileURLToPath(new URL('../',import.meta.url));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
export const mandatory=['candidate','fast','contracts','postgres','integration','packaged-linux','packaged-windows','packaged-macos','validation'];
const sha=value=>assert.match(value??'',/^[a-f0-9]{40}$/,'exact source SHA required');
export function successful(needs){
  assert.ok(needs&&typeof needs==='object','missing prerequisites');
  for(const name of mandatory)assert.equal(needs[name]?.result,'success',`required job ${name} did not succeed`);
}
export function identity({commit,expectedCommit,version,expectedVersion,tag,ref,release,repository,expectedRepository}){
  sha(commit);sha(expectedCommit);assert.equal(commit,expectedCommit,'wrong commit');
  assert.match(version,/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/,'invalid release version');
  assert.equal(version,expectedVersion,'wrong version');assert.equal(tag,`v${version}`,'wrong tag');
  assert.equal(repository,expectedRepository,'wrong repository');
  if(release)assert.equal(ref,`refs/tags/${tag}`,'release must dispatch the exact tag');
}
async function expected(){
  const pkg=JSON.parse(await readFile(join(root,'package.json'),'utf8'));
  const repository=new URL(pkg.repository.url.replace(/\.git$/,'')).pathname.slice(1);
  const sources={[pkg.name]:{commit:process.env.GITHUB_SHA,version:pkg.version}};
  for(const name of ['client','server']){
    if(pkg.name!=='@poppykit/cli')continue;
    const pin=JSON.parse(await readFile(join(root,`.github/${name}-candidate.json`),'utf8'));
    assert.equal(pin.repository,`LMol-4/poppykit-${name}`,'unexpected dependency repository');sha(pin.ref);
    sources[`@poppykit/${name}`]={commit:pin.ref,version:pin.version??'0.0.0'};
  }
  for(const row of Object.values(sources))sha(row.commit);
  return {pkg,repository,sources};
}
function metadata(path){
  const result=spawnSync('tar',['-xOf',basename(path),'package/package.json'],{cwd:dirname(resolve(path)),encoding:'utf8',windowsHide:true,maxBuffer:1024*1024});
  assert.equal(result.status,0,'unreadable candidate tarball: '+(result.error?.message??result.stderr));return JSON.parse(result.stdout);
}
export async function inspect(directory){
  const {pkg,repository,sources}=await expected();
  const files=[];
  for(const name of (await readdir(directory)).filter(name=>name.endsWith('.tgz')).sort()){
    assert.match(name,/^[a-z0-9][a-z0-9.-]*\.tgz$/,'invalid artifact filename');
    const bytes=await readFile(join(directory,name)),manifest=metadata(join(directory,name)),source=sources[manifest.name];
    assert.ok(source,'unexpected package');assert.equal(manifest.version,source.version,'artifact version mismatch');
    assert.equal(manifest.repository?.url,`https://github.com/LMol-4/poppykit-${manifest.name.split('/')[1]}.git`,'artifact repository mismatch');
    assert.equal(name,`${manifest.name.replace('@','').replace('/','-')}-${manifest.version}.tgz`,'artifact filename mismatch');
    assert.ok(!Object.values(manifest.dependencies??{}).some(value=>/^(?:file:|workspace:|link:)/.test(value)),'local dependency in artifact');
    if(manifest.name==='@poppykit/cli')assert.equal(manifest.dependencies?.['@poppykit/client'],sources['@poppykit/client'].version,'CLI/client version mismatch');
    if(manifest.name===pkg.name)assert.deepEqual(manifest,pkg,'packed package metadata changed');
    files.push({name,package:manifest.name,version:manifest.version,commit:source.commit,sha256:digest(bytes),integrity:'sha512-'+createHash('sha512').update(bytes).digest('base64'),bytes:bytes.length});
  }
  assert.equal(files.length,Object.keys(sources).length,'missing artifact');
  assert.equal(new Set(files.map(row=>row.package)).size,files.length,'duplicate package');
  return {format:1,repository,commit:process.env.GITHUB_SHA,package:pkg.name,version:pkg.version,files};
}
export async function check(directory,expectedDigest){
  assert.match(expectedDigest??'',/^[a-f0-9]{64}$/,'missing trusted manifest digest');
  const bytes=await readFile(join(directory,'release-manifest.json'));
  assert.equal(digest(bytes),expectedDigest,'manifest digest mismatch');
  const manifest=JSON.parse(bytes);assert.deepEqual(manifest,await inspect(directory),'candidate identity/digest mismatch');
  return manifest;
}
export async function run(mode,directory){
  const {pkg,repository}=await expected();
  const head=spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8',windowsHide:true});
  assert.equal(head.status,0,'source checkout unavailable');assert.equal(head.stdout.trim(),process.env.GITHUB_SHA,'source checkout commit mismatch');
  if(process.env.RELEASE_CONTEXT==='true')for(const name of ['EXPECTED_SHA','RELEASE_VERSION','RELEASE_TAG','GITHUB_REPOSITORY'])assert.ok(process.env[name],'missing release input '+name);
  const context={commit:process.env.GITHUB_SHA,expectedCommit:process.env.EXPECTED_SHA||process.env.GITHUB_SHA,version:pkg.version,expectedVersion:process.env.RELEASE_VERSION||pkg.version,tag:process.env.RELEASE_TAG||`v${pkg.version}`,ref:process.env.GITHUB_REF,release:process.env.RELEASE_CONTEXT==='true',repository:process.env.GITHUB_REPOSITORY||repository,expectedRepository:repository};
  identity(context);
  if(mode==='write'){
    const bytes=Buffer.from(JSON.stringify(await inspect(directory),null,2)+'\n');
    await writeFile(join(directory,'release-manifest.json'),bytes);
    if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,`manifest-sha=${digest(bytes)}\n`,{flag:'a'});
    console.log(digest(bytes));return;
  }
  const manifest=await check(directory,process.env.EXPECTED_MANIFEST_SHA);
  if(mode==='gate'){
    successful(JSON.parse(process.env.NEEDS_JSON??'null'));
    if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,'ready=true\n',{flag:'a'});
  }else if(mode==='publish-check'){
    assert.equal(process.env.RELEASE_CONTEXT,'true','not a release context');
    assert.equal(process.env.NPM_PUBLISH_ENABLED,'true','owner has not enabled publication');
    assert.equal(pkg.private,false,'package remains private');
    assert.ok(pkg.license&&pkg.license!=='UNLICENSED','public license decision missing');
    assert.notEqual(pkg.version,'0.0.0','development version cannot publish');
    assert.ok(process.env.GITHUB_RUN_ID&&process.env.GITHUB_RUN_ATTEMPT,'missing trusted run identity');
    // Ref resolution is checked again after environment approval; a moved tag fails closed.
    const tag=spawnSync('git',['rev-parse','--verify',`${context.tag}^{commit}`],{cwd:root,encoding:'utf8',windowsHide:true});
    assert.equal(tag.status,0,'missing release tag');assert.equal(tag.stdout.trim(),context.commit,'moved tag');
    const own=manifest.files.find(row=>row.package===pkg.name);assert.ok(own);
    if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,`tarball=${join(directory,own.name)}\n`,{flag:'a'});
  }else assert.equal(mode,'check','unknown mode');
  console.log(`Candidate ${mode} passed: ${manifest.commit}`);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [mode,directory]=process.argv.slice(2);assert.ok(mode&&directory,'usage: release-candidate write|check|gate|publish-check DIRECTORY');await run(mode,directory);
}
