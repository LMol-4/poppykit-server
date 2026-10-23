import assert from 'node:assert/strict';
import {readFile,writeFile,readdir,access} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
export async function validateContents(directory,manifest){
  async function visit(relative=''){
    for(const entry of await readdir(join(directory,relative),{withFileTypes:true})){
      const path=(relative?relative+'/':'')+entry.name;
      assert.ok(!entry.isSymbolicLink(),'package contains a symlink');
      const allowed=path==='package.json'||/^LICENSE(?:\.[\w-]+)?$/i.test(path)||manifest.files.some(prefix=>path===prefix||path.startsWith(prefix+'/'));
      assert.ok(allowed,'unexpected package path: '+path);
      assert.ok(!/(?:^|\/)(?:tests?|test-support|fixtures?)(?:\/|$)/i.test(path),'test fixture in package: '+path);
      assert.ok(!/(?:^|\/)(?:\.env(?:\..*)?|[^/]+\.(?:pem|key|sqlite|db|log|tgz))$/i.test(path),'private/state file in package: '+path);
      if(entry.isDirectory())await visit(path);
      else{
        if(path.startsWith('dist/'))assert.ok(/\.(?:js|d\.ts)(?:\.map)?$/.test(path),'non-code artifact in dist: '+path);
        const bytes=await readFile(join(directory,path));
        assert.ok(!/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|PRIVATE_PASSWORD|PRIVATE_BACKEND_FAILURE/.test(bytes.toString('utf8')),'private material in package: '+path);
      }
    }
  }
  await visit();
}
