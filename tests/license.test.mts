import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {validateContents} from '../scripts/package-contents.mjs';
test('public MIT packages ship the reviewed complete license and reject missing or changed rights',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'MIT candidate ü ')),manifest={files:['LICENSE'],license:'MIT'};
 try{
  const license=await readFile(new URL('../LICENSE',import.meta.url),'utf8');
  await assert.rejects(validateContents(directory,manifest),'missing license is rejected');
  await writeFile(join(directory,'LICENSE'),license);await validateContents(directory,manifest);
  await assert.rejects(validateContents(directory,{...manifest,files:[]}),'license must be explicitly allowlisted');
  await writeFile(join(directory,'LICENSE'),'MIT License\nCopyright changed; permission missing\n');await assert.rejects(validateContents(directory,manifest),'changed/truncated license is rejected');
  await writeFile(join(directory,'LICENSE'),license.replace(/\r?\n/g,'\r\n'));await validateContents(directory,manifest);
 }finally{await rm(directory,{recursive:true,force:true});}
});
