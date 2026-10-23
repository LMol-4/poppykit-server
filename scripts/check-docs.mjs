import assert from 'node:assert/strict';
import {readFile,readdir,access} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
async function visit(directory){
  for(const entry of await readdir(directory,{withFileTypes:true})){
    if(['.git','node_modules','dist','.candidate','.run'].includes(entry.name))continue;
    const path=resolve(directory,entry.name);
    if(entry.isDirectory())await visit(path);
    else if(entry.name.endsWith('.md')){
      const text=await readFile(path,'utf8');
      assert.equal((text.match(/^```/gm)??[]).length%2,0,'unbalanced code fences: '+path);
      for(const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)){
        const target=match[1].split('#')[0];
        if(!target||/^[a-z]+:/i.test(target))continue;
        await access(resolve(dirname(path),decodeURIComponent(target)));
      }
    }
  }
}
await visit('.');
console.log('Markdown file links and fences passed');
