import test from 'node:test';
import assert from 'node:assert/strict';
import {configuredRepositories,target,validateSelection} from './selection.mts';
import {verifyTokens,type Wire} from './tokens.mts';
import {permissions} from './model.mts';
import {HttpFailure,type Client} from './github.mts';
const targets=[{repository:'example/one',repoId:3,ownerId:2},{repository:'example/two',repoId:4,ownerId:2}];
test('one owner selection rejects ambiguity, duplicates, empty and cross-owner inputs',()=>{
  assert.deepEqual(configuredRepositories({repository:'example/one'}),['example/one']);
  assert.deepEqual(configuredRepositories({repositories:targets.map(t=>t.repository)}),targets.map(t=>t.repository));
  for(const config of [{},{repositories:[]},{repository:'example/one',repositories:['example/two']},
    {repositories:['example/one','other/two']},{repositories:['example/one','example/one']}])
    assert.throws(()=>configuredRepositories(config));
});
test('installation scope is an exact unordered set, including both ID and full name',()=>{
  const repos=targets.map(t=>({id:t.repoId,full_name:t.repository}));
  validateSelection({total_count:2,repositories:[...repos].reverse()},targets);
  for(const v of [{total_count:3,repositories:repos},{total_count:2,repositories:[repos[0],repos[0]]},
    {total_count:2,repositories:[repos[0],{id:4,full_name:'other/two'}]},
    {total_count:1,repositories:[repos[0]]}]) assert.throws(()=>validateSelection(v,targets));
});
test('repository setup refuses archived, private, non-admin and unexpected default branches',()=>{
  const repo={id:3,full_name:'example/one',owner:{id:2,type:'Organization'},private:false,
    archived:false,default_branch:'main',permissions:{admin:true}};
  assert.deepEqual(target(repo,'example/one'),targets[0]);
  for(const change of [{private:true},{archived:true},{default_branch:'other'},
    {permissions:{admin:false}},{owner:{id:2,type:'User'}}])
    assert.throws(()=>target({...repo,...change},'example/one'));
});
test('multi-repository discovery never expands the write token beyond each current repository',async()=>{
  const issued:unknown[]=[];let sequence=0,revoked=0;
  const app:Client=async(_p,_m,body)=>{
    issued.push(body);sequence++;
    return {token:`synthetic-${sequence}`,permissions:body!.permissions,
      expires_at:new Date(Date.now()+3_000_000).toISOString()};
  };
  const wire:Wire=async(path,method)=>{
    if(method==='DELETE'){revoked=sequence;return null;}
    if(revoked===sequence)throw new HttpFailure(401);
    const selected=sequence===1?targets:[targets[sequence-2]!];
    if(path.startsWith('installation/repositories'))return {total_count:selected.length,
      repositories:selected.map(t=>({id:t.repoId,full_name:t.repository}))};
    if(path.endsWith('/rules/branches/main'))return [];
    return {id:targets[sequence-2]!.repoId};
  };
  for(const [i,t] of targets.entries())
    await verifyTokens(app,wire,5,t.repository,t.repoId,()=>{},targets,i===0);
  assert.deepEqual(issued,[{permissions:{metadata:'read'}},
    {permissions,repository_ids:[3]},{permissions,repository_ids:[4]}]);
  assert.equal(revoked,3);
});
