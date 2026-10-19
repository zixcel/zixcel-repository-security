import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyTokens,type Wire} from './tokens.mts';
import {permissions,type Json} from './model.mts';
import {HttpFailure,type Client} from './github.mts';
async function run(mode:'success'|'scope'|'permissions'|'expired'|'cleanup') {
  const calls: string[] = [];let created=0,revoked=0;
  const app: Client = async (path,method,body) => {
    assert.equal(path,'app/installations/4/access_tokens');assert.equal(method,'POST');
    ++created;calls.push(`create:${created}`);
    assert.deepEqual(body?.permissions,created===1?{metadata:'read'}:permissions);
    assert.deepEqual(body?.repository_ids,created===1?undefined:[3]);
    return {token:`synthetic-${created}`,permissions:mode==='permissions'?{...permissions,issues:'write'}:body?.permissions,
      expires_at:new Date(Date.now()+(mode==='expired'?-1000:3_000_000)).toISOString()};
  };
  const wire: Wire = async (path,method,_body,token) => {
    assert.equal(token,`synthetic-${created}`);
    if (path==='installation/token') {calls.push(`revoke:${created}`);assert.equal(method,'DELETE');
      if (mode==='cleanup') throw Error('synthetic revocation failure');revoked=created;return null;}
    if(revoked===created)throw new HttpFailure(401);
    if (path==='installation/repositories?per_page=100') return {total_count:mode==='scope'?2:1,
      repositories:[{id:3,full_name:'example/project'}]};
    if (path==='repos/example/project') return {id:3};
    assert.equal(path,'repos/example/project/rules/branches/main');return [];
  };
  const stages: string[] = [];
  await verifyTokens(app,wire,4,'example/project',3,(s,_d?:Json)=>stages.push(s));
  return {calls,stages};
}
test('discovery and repository-scoped tokens are verified then revoked', async () => {
  const {calls,stages}=await run('success');
  assert.deepEqual(calls,['create:1','revoke:1','create:2','revoke:2']);
  assert.equal(stages.filter(s=>s==='probe_token_revoked').length,2);
});
for (const mode of ['scope','permissions','expired','cleanup'] as const)
  test(`fail closed on ${mode}`,async()=>{await assert.rejects(run(mode));});
test('failed admission revokes the known token without retrying issuance',async()=>{
  const calls:string[]=[];
  await assert.rejects(verifyTokens(async()=>{calls.push('create');return {token:'synthetic',
    permissions:{issues:'write'},expires_at:new Date(Date.now()+3_000_000).toISOString()};},
  async(path)=>{calls.push(path);if(path==='installation/token')return null;throw new HttpFailure(401);},
    4,'example/project',3,()=>{}));
  assert.deepEqual(calls,['create','installation/token','installation/repositories?per_page=100']);
});
