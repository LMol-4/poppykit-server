import test from 'node:test';
import assert from 'node:assert/strict';
import {absent,toolchain,dependencyIntegrity} from '../scripts/registry-check.mjs';
test('registry uncertainty and existing versions fail closed',()=>{
  absent({status:1,stdout:JSON.stringify({error:{code:'E404'}})});
  for(const value of [{status:0,stdout:'{}'},{status:1,stdout:'{}'},{status:1,stdout:'not JSON'},{status:null,stdout:''},{status:1,stdout:JSON.stringify({error:{code:'E401'}})}])assert.throws(()=>absent(value));
  toolchain('24.12.0','11.5.1');toolchain('24.13.0','11.21.1');
  for(const values of [['24.11.9','11.21.1'],['24.12.0','11.5.0'],['24.12.0','broken']])assert.throws(()=>toolchain(...values));
  dependencyIntegrity('sha512-tested','sha512-tested');assert.throws(()=>dependencyIntegrity('sha512-other','sha512-tested'));
});
