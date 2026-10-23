import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {mandatory} from '../scripts/release-candidate.mjs';
test('actual workflow wiring keeps reporting and publication separate',async()=>{
 const verify=await readFile(new URL('../.github/workflows/verify.yml',import.meta.url),'utf8');
 const release=await readFile(new URL('../.github/workflows/release.yml',import.meta.url),'utf8');
 const ci=await readFile(new URL('../.github/workflows/ci.yml',import.meta.url),'utf8');
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
