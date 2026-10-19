import test from 'node:test';
import assert from 'node:assert/strict';
import {manifest,permissions,validateApp,validateInstallation,validateScope,repositoryName} from './model.mts';
const app = {id:1,owner:{id:2},slug:'example-dependency-merge',client_id:'Iv1exampleclient',
  permissions,events:[],public:false};
test('manifest has only reviewed permissions and no callbacks to public infrastructure', () => {
  const m = manifest('example','http://127.0.0.1:1234/registered/nonce');
  assert.equal(m.public,false);assert.deepEqual(m.default_permissions,permissions);
  assert.deepEqual(m.default_events,[]);assert.deepEqual(m.hook_attributes,
    {active:false,url:'https://github.com/zixcel/zixcel-repository-security'});
  assert.equal(m.setup_url,'http://127.0.0.1:1234/installed/nonce');
  for (const url of ['https://external.test/callback','http://0.0.0.0:1234/callback','http://localhost:1234/callback'])
    assert.throws(()=>manifest('example',url));
});
test('App metadata is bound to the approved owner, slug and exact permissions', () => {
  assert.equal(validateApp(app,2,app.slug).id,1);
  for (const changed of [{owner:{id:3}},{slug:'other'}, {permissions:{...permissions,administration:'write'}},
    {events:['push']},{public:true}]) assert.throws(()=>validateApp({...app,...changed},2,app.slug));
});
test('installation rejects all-repository selection, suspension, excess rights and foreign owner', () => {
  const i = {id:4,account:{id:2},app_id:1,repository_selection:'selected',suspended_at:null,permissions};
  assert.equal(validateInstallation(i,2,1),4);
  for (const change of [{repository_selection:'all'},{account:{id:3}},{app_id:9},
    {suspended_at:'now'},{permissions:{...permissions,workflows:'write'}}])
    assert.throws(()=>validateInstallation({...i,...change},2,1));
});
test('pilot selects exactly one canonical repository', () => {
  validateScope({total_count:1,repositories:[{id:3,full_name:'example/project'}]},'example/project',3);
  for (const v of [{total_count:2,repositories:[]},{total_count:1,repositories:[{id:4,full_name:'example/project'}]},
    {total_count:1,repositories:[{id:3,full_name:'example/other'}]}])
    assert.throws(()=>validateScope(v,'example/project',3));
});
test('repository input cannot introduce routes or shell arguments', () => {
  assert.equal(repositoryName('example/project'),'example/project');
  for (const s of ['example/../other','example/project --env other','https://example/repo','Example/repo'])
    assert.throws(()=>repositoryName(s));
});
