import test from 'node:test';
import assert from 'node:assert/strict';
import {api} from './api.mts';
test('reject credential, release, rules, secret and cross-host mutation routes before any network call',async()=>{
  const before=globalThis.fetch;let calls=0;
  const original=process.env.GITHUB_REPOSITORY;process.env.GITHUB_REPOSITORY='example/project';
  globalThis.fetch=async()=>{++calls;throw Error('must not contact API');};
  try{
    for(const [path,method]of [['repos/example/project/releases','POST'],
      ['repos/example/project/rulesets/1','PUT'],['repos/example/project/actions/secrets/key','PUT'],
      ['installation/repositories?per_page=100','DELETE'],['app/installations/1/access_tokens','POST'],
      ['https://foreign.test/repos/example/project','GET'],['repos/example/../project','GET'],
      ['repos/example/other/pulls/1/merge','PUT'],['repos/example/other/pulls/1','GET'],
      ['repos/example/project/%2e%2e/other','GET']])
      await assert.rejects(api(path!,method!),/Invalid API path|Only a normal/);
    assert.equal(calls,0);
  }finally{globalThis.fetch=before;
    if(original===undefined)delete process.env.GITHUB_REPOSITORY;else process.env.GITHUB_REPOSITORY=original;}
});
test('GitHub permission or conflict refusal is never retried or bypassed',async()=>{
  const before=globalThis.fetch,env={...process.env};
  process.env.GITHUB_REPOSITORY='example/project';process.env.GH_TOKEN='synthetic-workflow-token';
  try {
    for(const status of [401,403,409]) {
      let calls=0;
      globalThis.fetch=async(url,init)=>{
        ++calls;assert.equal(String(url),'https://api.github.com/repos/example/project/pulls/1/merge');
        assert.equal(init?.method,'PUT');assert.equal(init?.redirect,'error');
        return new Response('{}',{status});
      };
      await assert.rejects(api('repos/example/project/pulls/1/merge','PUT',{sha:'a'.repeat(40)}),
        new RegExp(`HTTP ${status}`));
      assert.equal(calls,1);
    }
  }finally{globalThis.fetch=before;
    for(const name of ['GITHUB_REPOSITORY','GH_TOKEN'])
      if(env[name]===undefined)delete process.env[name];else process.env[name]=env[name];}
});
