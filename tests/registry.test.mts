import test from 'node:test';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {absent,toolchain,dependencyIntegrity} from '../scripts/registry-check.mjs';
test('registry uncertainty and existing versions fail closed',()=>{
  absent({status:1,stdout:JSON.stringify({error:{code:'E404'}})});
  for(const value of [{status:0,stdout:'{}'},{status:1,stdout:'{}'},{status:1,stdout:'not JSON'},{status:null,stdout:''},{status:1,stdout:JSON.stringify({error:{code:'E401'}})}])assert.throws(()=>absent(value));
  toolchain('24.21.0','11.5.1');toolchain('24.23.0','11.21.1');
  for(const values of [['24.20.99','11.21.1'],['25.0.0','11.21.1'],['26.0.0','11.21.1'],['23.99.0','11.21.1'],['24.11.9','11.21.1'],['24.21.0','11.5.0'],['24.21.0','broken']])assert.throws(()=>toolchain(...values));
  dependencyIntegrity('sha512-tested','sha512-tested');assert.throws(()=>dependencyIntegrity('sha512-other','sha512-tested'));
});

test('Node version file matches the consumer engine range',()=>{
  const minimum=readFileSync(new URL('../.node-version',import.meta.url),'utf8').trim();
  assert.match(minimum,/^24\.\d+\.\d+$/);
  const pkg=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8'));
  assert.equal(pkg.engines.node,`>=${minimum} <25`);
  toolchain(minimum,'11.5.1');
});
