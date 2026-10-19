import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import {createAppAuth} from '@octokit/auth-app';
import {Registration} from './registration.mts';
test('official SDK creates a verifiable short-lived App JWT using an ephemeral test key',async()=>{
  const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const pem=privateKey.export({type:'pkcs1',format:'pem'}).toString();
  const auth=createAppAuth({appId:1,privateKey:pem});
  const {token}=await auth({type:'app'});
  const [header,payload,signature]=token.split('.');assert.ok(header&&payload&&signature);
  const h=JSON.parse(Buffer.from(header,'base64url').toString()) as {alg:string};
  const p=JSON.parse(Buffer.from(payload,'base64url').toString()) as {iss:string|number,iat:number,exp:number};
  assert.equal(h.alg,'RS256');assert.equal(String(p.iss),'1');
  assert.ok(p.exp>p.iat&&p.exp-p.iat<=660);
  assert.ok(verify('RSA-SHA256',Buffer.from(`${header}.${payload}`),publicKey,Buffer.from(signature,'base64url')));
});
test('registration session has no serializable key, App/JWT client or logger state',()=>{
  const registration=new Registration('example/project',1,2,()=>{});
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(registration))).sort(),
    ['owner','ownerId','repoId','repositories','repository','slug']);
  registration.dispose();
});
