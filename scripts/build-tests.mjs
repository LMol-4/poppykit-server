import ts from 'typescript';
import assert from 'node:assert/strict';
import {writeFileSync,mkdirSync,existsSync,unlinkSync} from 'node:fs';
import {dirname,resolve,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url));
assert.equal(resolve(process.cwd()),resolve(root),'run build:tests from the repository root');
const configPath=resolve(root,'tsconfig.tests.json');
const loaded=ts.readConfigFile(configPath,ts.sys.readFile);
if(loaded.error)throw new Error(ts.flattenDiagnosticMessageText(loaded.error.messageText,'\n'));
const config=ts.parseJsonConfigFileContent(loaded.config,ts.sys,root,{noEmit:false});
const outputRoot=resolve(root,'.test-build');
assert.equal(resolve(config.options.rootDir??''),resolve(root),'unexpected test rootDir');
assert.equal(resolve(config.options.outDir??''),outputRoot,'unexpected test outDir');
function inside(path){const local=relative(root,path);assert.ok(local&&!isAbsolute(local)&&!local.startsWith('..'),'test path escapes repository');return local;}
const canonical=config.fileNames.filter(path=>path.endsWith('.mts'));
for(const path of canonical)assert.match(inside(path).replaceAll('\\','/'),/^(?:tests|test-support|scripts)\/.+\.mts$/);
// Remove only exact canonical output paths before checking. Failed typechecks
// cannot leave stale runnable tests; production/release JavaScript is preserved.
for(const path of canonical)for(const output of [path.slice(0,-4)+'.mjs',path.slice(0,-4)+'.mjs.map']){inside(output);if(existsSync(output))unlinkSync(output);}
const program=ts.createProgram(config.fileNames,config.options);
const diagnostics=[...config.errors,...ts.getPreEmitDiagnostics(program)];
if(diagnostics.length){console.error(ts.formatDiagnosticsWithColorAndContext(diagnostics,{getCanonicalFileName:p=>p,getCurrentDirectory:ts.sys.getCurrentDirectory,getNewLine:()=> '\n'}));process.exit(1);}
// Emit the same fully checked program; no transpile-only or type-stripping path.
for(const path of canonical){const source=program.getSourceFile(path);assert.ok(source);const expected=path.slice(0,-4)+'.mjs';const result=program.emit(source,(output,text)=>{const local=relative(outputRoot,output);assert.ok(local&&!isAbsolute(local)&&!local.startsWith('..'),'compiler output escapes test build');const target=resolve(root,local);assert.equal(target,resolve(expected),'unexpected compiler output');inside(target);mkdirSync(dirname(target),{recursive:true});writeFileSync(target,text);});if(result.emitSkipped)throw new Error('test compiler skipped '+path);}
console.log(canonical.length+' TypeScript test/harness files checked and compiled');
