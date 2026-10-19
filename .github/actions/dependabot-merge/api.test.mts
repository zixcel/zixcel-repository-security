import test from 'node:test';
import assert from 'node:assert/strict';
import {api} from './api.mts';
test('reject credential, release, rules, secret and cross-host mutation routes before any network call',async()=>{
  const before=globalThis.fetch;let calls=0;
  globalThis.fetch=async()=>{++calls;throw Error('must not contact API');};
  try{
    for(const [path,method]of [['repos/example/project/releases','POST'],
      ['repos/example/project/rulesets/1','PUT'],['repos/example/project/actions/secrets/key','PUT'],
      ['installation/repositories?per_page=100','DELETE'],['app/installations/1/access_tokens','POST'],
      ['https://foreign.test/repos/example/project','GET'],['repos/example/../project','GET']])
      await assert.rejects(api(path!,method!),/Invalid API path|Only a normal/);
    assert.equal(calls,0);
  }finally{globalThis.fetch=before;}
});
