import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export function absent(result){
  if(result.status===0)throw new Error('version already published; do not overwrite or republish');
  const value=JSON.parse(result.stdout||'null');
  assert.equal(value?.error?.code,'E404','registry unavailable or unauthorized; refusing publication');
}
export function toolchain(node,npm){
  const atLeast=(value,minimum)=>{const parts=value.trim().replace(/^v/,'').split('.').map(Number);return parts.every(Number.isInteger)&&parts.length===3&&parts.some((part,i)=>part>minimum[i]&&parts.slice(0,i).every((v,j)=>v===minimum[j]))||parts.join('.')===minimum.join('.');};
  assert.ok(/^v?24\./.test(node.trim()) && atLeast(node,[24,22,1]),'unsupported publishing Node');
  assert.ok(atLeast(npm,[11,5,1]),'npm trusted publishing requires npm >=11.5.1');
}
export function dependencyIntegrity(actual,expected){assert.equal(actual,expected,'published dependency differs from tested candidate');}
async function main(directory){
  const version=spawnSync('npm',['--version'],{encoding:'utf8'});assert.equal(version.status,0);toolchain(process.versions.node,version.stdout);
  const manifest=JSON.parse(await readFile(join(directory,'release-manifest.json'),'utf8'));
  const result=spawnSync('npm',['view',`${manifest.package}@${manifest.version}`,'--json','--registry=https://registry.npmjs.org'],{encoding:'utf8',timeout:30000});
  absent(result);
  if(manifest.package==='@poppykit/cli'){
    const client=manifest.files.find(row=>row.package==='@poppykit/client');assert.ok(client);
    const published=spawnSync('npm',['view',`${client.package}@${client.version}`,'dist.integrity','--json','--registry=https://registry.npmjs.org'],{encoding:'utf8',timeout:30000});
    assert.equal(published.status,0,'publish required client dependency first');dependencyIntegrity(JSON.parse(published.stdout),client.integrity);
  }
  console.log('Registry version absent; required dependency bytes match.');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main(process.argv[2]);
