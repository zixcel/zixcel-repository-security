import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyPrivateAdmission} from './private-admission.mts';
import {configuredPrivateRepositories,target} from './selection.mts';
import {HttpFailure,type Client} from './github.mts';
const repository='example/project',sha='a'.repeat(40);
const rules=[{type:'pull_request'},{type:'deletion'},{type:'non_fast_forward'},
  {type:'required_status_checks',parameters:{strict_required_status_checks_policy:true,
    required_status_checks:[{context:'test',integration_id:15368}]}}];
function api(change:Record<string,unknown>={}):Client {
  return async(path,method='GET')=>{
    assert.equal(method,'GET');
    if(path.endsWith('/actions/permissions'))return {enabled:true};
    if(path.endsWith('/rules/branches/main'))return change.rules ?? rules;
    if(path.endsWith('/git/ref/heads/main'))return {object:{type:'commit',sha}};
    return change.checks ?? {total_count:1,check_runs:[{id:1,name:'test',app:{id:15368},head_sha:sha,
      status:'completed',conclusion:'success'}]};
  };
}
test('private admission uses effective protections and trusted successful current main CI',async()=>{
  await verifyPrivateAdmission(repository,api());
});
test('unsupported plan stops before any credential or Environment write',async()=>{
  const calls:string[]=[];
  await assert.rejects(verifyPrivateAdmission(repository,async(path,method='GET')=>{
    calls.push(path);assert.equal(method,'GET');
    if(path.endsWith('/actions/permissions'))return {enabled:true};
    throw new HttpFailure(403);
  }),HttpFailure);
  assert.equal(calls.length,2);
});
test('missing protection, non-strict or unbound checks cannot admit a private target',async()=>{
  for(const missing of ['pull_request','deletion','non_fast_forward','required_status_checks'])
    await assert.rejects(verifyPrivateAdmission(repository,api({rules:rules.filter(r=>r.type!==missing)})));
  for(const parameters of [{strict_required_status_checks_policy:false,required_status_checks:[{context:'test',integration_id:15368}]},
    {strict_required_status_checks_policy:true,required_status_checks:[]},
    {strict_required_status_checks_policy:true,required_status_checks:[{context:'test',integration_id:null}]}])
    await assert.rejects(verifyPrivateAdmission(repository,api({rules:[...rules.slice(0,3),{type:'required_status_checks',parameters}]})));
});
test('failed, absent, stale, spoofed, pending and policy-only CI fail closed',async()=>{
  const base={id:1,name:'test',app:{id:15368},head_sha:sha,status:'completed',conclusion:'success'};
  for(const patch of [{conclusion:'failure'},{status:'in_progress'},{head_sha:'b'.repeat(40)},
    {app:{id:99}},{name:'repository-policy'}])
    await assert.rejects(verifyPrivateAdmission(repository,api({checks:{total_count:1,check_runs:[{...base,...patch}]}})));
  await assert.rejects(verifyPrivateAdmission(repository,api({checks:{total_count:0,check_runs:[]}})));
});
test('private visibility requires explicit selection and account ownership stays bound',()=>{
  const config={repositories:[repository],privateRepositories:[repository]};
  assert.deepEqual(configuredPrivateRepositories(config,[repository]),[repository]);
  assert.deepEqual(configuredPrivateRepositories({},[repository]),[]);
  for(const names of [[repository,repository],['other/repo']])
    assert.throws(()=>configuredPrivateRepositories({privateRepositories:names},[repository]));
  const r={id:3,full_name:repository,owner:{id:2,type:'User'},private:true,archived:false,
    default_branch:'main',permissions:{admin:true}};
  assert.equal(target(r,repository,true,'User').repoId,3);
  assert.throws(()=>target(r,repository));
  assert.throws(()=>target({...r,private:false},repository,true,'User'));
  assert.throws(()=>target(r,repository,true,'Organization'));
});
