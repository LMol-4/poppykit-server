import assert from 'node:assert/strict';
export function expectValue<T>(value:T|null|undefined):T { assert.ok(value!==null&&value!==undefined,'expected fixture value');return value; }

export async function publicEcJwk(key:CryptoKey){const jwk=await crypto.subtle.exportKey('jwk',key);const {kty,crv,x,y}=jwk;assert.ok(kty&&crv&&x&&y);return {kty,crv,x,y,ext:jwk.ext??true,key_ops:jwk.key_ops??['verify']};}

type Json=null|boolean|number|string|Json[]|{[key:string]:Json};
function assertJson(value:unknown):asserts value is Json{if(value===null||typeof value==='string'||typeof value==='boolean')return;if(typeof value==='number'){assert.ok(Number.isFinite(value));return;}assert.ok(value&&typeof value==='object');for(const item of Object.values(value))assertJson(item);}
export function jsonObject(value:unknown):{[key:string]:Json}{assertJson(value);assert.ok(value&&typeof value==='object'&&!Array.isArray(value));return value;}

type FixtureMessage={id:string;sender:'agent'|'human';text?:string;[key:string]:unknown};
function isMessage(value:unknown):value is FixtureMessage{return !!value&&typeof value==='object'&&'id' in value&&typeof value.id==='string'&&'sender' in value&&(value.sender==='agent'||value.sender==='human')&&(!('text' in value)||typeof value.text==='string');}
export function messageValue(value:unknown):FixtureMessage{assert.ok(isMessage(value));return value;}
export function optionalMessage(value:unknown):FixtureMessage|undefined{return value===null||value===undefined?undefined:messageValue(value);}
