import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareEnvironment,verifyEnvironment} from './environment.mts';
import {Missing,type Client} from './github.mts';
const prefix='repos/example/project/environments/dependency-maintenance';
const env={name:'dependency-maintenance',deployment_branch_policy:{protected_branches:false,
  custom_branch_policies:true},protection_rules:[{type:'branch_policy'}]};
test('create a main-only branch policy and verify before touching credentials',async()=>{
  let exists=false,policy=false;const writes:string[]=[];
  const api:Client=async(path,method='GET',body)=>{
    if(method==='PUT'){assert.equal(path,prefix);exists=true;writes.push(path);return env;}
    if(method==='POST'){assert.equal(path,prefix+'/deployment-branch-policies');
      assert.deepEqual(body,{name:'main',type:'branch'});policy=true;writes.push(path);return {};}
    if(path===prefix){if(!exists)throw new Missing();return env;}
    if(path===prefix+'/deployment-branch-policies?per_page=100')return {total_count:1,
      branch_policies:policy?[{name:'main',type:'branch'}]:[]};
    throw new Missing();
  };
  await prepareEnvironment('example/project',api);assert.equal(writes.length,2);
});
test('never replace existing broad or tag-only environment policy',async()=>{
  for(const name of ['*','release/*','main']){
    const api:Client=async(path,method='GET')=>{assert.equal(method,'GET');return path===prefix?env:
      {total_count:1,branch_policies:[{name,type:'tag'}]};};
    await assert.rejects(verifyEnvironment('example/project',api),/Only the main/);
  }
});
test('existing private keys stop setup instead of being overwritten',async()=>{
  const api:Client=async(path,method='GET')=>{
    assert.equal(method,'GET');if(path===prefix)return env;
    if(path.includes('/actions/variables/'))throw new Missing();
    if(path.includes('deployment-branch-policies'))return {total_count:1,branch_policies:[{name:'main',type:'branch'}]};
    return {name:'DEPENDENCY_MERGE_PRIVATE_KEY'};
  };
  await assert.rejects(prepareEnvironment('example/project',api),/Existing configuration/);
});
test('an active merger cannot enter registration or change its Environment',async()=>{
  const calls:string[]=[];
  await assert.rejects(prepareEnvironment('example/project',async(path,method='GET')=>{
    calls.push(path);assert.equal(method,'GET');return {value:'true'};
  }),/requires inactive/);
  assert.deepEqual(calls,['repos/example/project/actions/variables/DEPENDABOT_AUTOMERGE_ENABLED']);
});
