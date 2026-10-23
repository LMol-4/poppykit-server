import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
const consumer=resolve(process.argv[2]),pkg=JSON.parse(await readFile('package.json','utf8'));
const lines=Object.keys(pkg.exports).map((key,i)=>`import * as p${i} from ${JSON.stringify(pkg.name+(key==='.'?'':key.slice(1)))}; export const e${i}=p${i};`);
const fixture=join(consumer,'declarations.mts');await writeFile(fixture,lines.join('\n'));
const result=spawnSync(process.execPath,[resolve('node_modules/typescript/bin/tsc'),'--noEmit','--strict','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2023','--typeRoots',resolve('node_modules/@types'),fixture],{stdio:'inherit',windowsHide:true});
assert.equal(result.status,0,'installed declarations do not typecheck');
