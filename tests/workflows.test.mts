import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {mandatory} from '../scripts/release-candidate.mjs';
test('actual workflow wiring keeps reporting and publication separate',async()=>{
 const verify=await readFile(new URL('../.github/workflows/verify.yml',import.meta.url),'utf8');
 const release=await readFile(new URL('../.github/workflows/release.yml',import.meta.url),'utf8');
 const ci=await readFile(new URL('../.github/workflows/ci.yml',import.meta.url),'utf8');
 const candidate=verify.slice(verify.indexOf('  candidate:'),verify.indexOf('  fast:'));
 assert.ok(candidate.indexOf('npm run build:tests')>=0&&candidate.indexOf('npm run build:tests')<candidate.indexOf('npm pack'),'strict harness build precedes candidate pack');
 assert.ok(candidate.includes('name: test-harness')&&candidate.includes('path: .test-build/harness/'),'harness is a separate artifact');
 for(const job of mandatory.filter(name=>name!=='candidate')){
  const block=verify.slice(verify.indexOf('  '+job+':')).split(/\n  [a-z][a-z-]+:/)[0];
  assert.ok(block.includes('name: test-harness')&&block.includes('node scripts/harness-artifact.mjs check'),'unchecked harness in '+job);
 }
 assert.ok(!release.includes('name: test-harness'),'publisher never consumes executable test harness');

 for(const job of mandatory)assert.ok(verify.includes('  '+job+':'),'missing '+job);
 assert.ok(verify.includes('needs: ['+mandatory.join(', ')+']'));
 assert.ok(verify.includes('if: always()'));assert.ok(verify.includes('NEEDS_JSON: '+String.fromCharCode(36)+'{{ toJSON(needs) }}'));
 assert.ok(release.includes("needs.verify.result == 'success' && needs.verify.outputs.ready == 'true'"));
 assert.ok(release.includes('id-token: write'));assert.ok(!verify.includes('id-token: write'));assert.ok(!ci.includes('id-token: write'));
 assert.ok(!release.includes('pull_request:'));assert.ok(!release.includes('workflow_run:'));assert.ok(!release.includes('cancel-in-progress: true'));
 assert.ok(release.includes('publish-check'));assert.ok(release.includes('--ignore-scripts'));assert.ok(release.includes('--provenance'));
 assert.ok(!release.includes('npm run build'));assert.ok(!release.includes('npm install'));assert.ok(!release.includes('npm pack'));
 assert.ok(!verify.includes('paths:'));assert.ok(!ci.includes('paths:'));
});
