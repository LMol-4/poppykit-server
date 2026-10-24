import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {mandatory} from '../scripts/release-candidate.mjs';
import {checkPostgresTap} from '../scripts/postgres-ci.mjs';
test('Postgres runner refuses missing discovery, skips, cancellation and missing contract sentinels', () => {
 const tap='ok 1 - required contract\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
 assert.equal(checkPostgresTap(tap,1,['required contract']),1);
 for(const broken of [tap.replace('# tests 1','# tests 0'),tap.replace('# skipped 0','# skipped 1'),tap.replace('# cancelled 0','# cancelled 1'),tap.replace('# pass 1','# pass 0'),tap.replace('required contract','wrong contract'),tap.replace('# tests 1',''),tap+'# tests 1\n'])assert.throws(()=>checkPostgresTap(broken,1,['required contract']));
});
test('actual workflow wiring keeps reporting and publication separate',async()=>{
 const verify=await readFile(new URL('../.github/workflows/verify.yml',import.meta.url),'utf8');
 const release=await readFile(new URL('../.github/workflows/release.yml',import.meta.url),'utf8');
 const ci=await readFile(new URL('../.github/workflows/ci.yml',import.meta.url),'utf8');
 const candidate=verify.slice(verify.indexOf('  candidate:'),verify.indexOf('  fast:'));
 assert.ok(candidate.indexOf('npm run build:tests')>=0&&candidate.indexOf('npm run build:tests')<candidate.indexOf('npm pack'),'strict harness build precedes candidate pack');
 assert.ok(candidate.includes('name: test-harness')&&candidate.includes('path: .test-build/harness/'),'harness is a separate artifact');
 const postgres=verify.slice(verify.indexOf('  postgres:')).split(/\n  integration:/)[0];
 assert.ok(postgres.includes('image: postgres:17.11@sha256:')&&postgres.includes('POPPY_DISPOSABLE_POSTGRES:'));
 assert.ok(postgres.includes('node scripts/install-candidate.mjs .candidate/artifacts source')&&postgres.includes('node scripts/postgres-ci.mjs'));
 assert.ok(!postgres.includes('SUPABASE')&&!postgres.includes('id-token: write'));
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
