import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyCredentials, type Identity} from './credentials.mts';
const identity: Identity = {mode:'github-app',installation:'123',expectedInstallation:'123',
  slug:'example-dependency-merge',expectedSlug:'example-dependency-merge'};
const repo = 'example/project';
test('accept a verified single-repository App token', async () => {
  await verifyCredentials(repo,identity,async path => {
    assert.equal(path,'installation/repositories?per_page=100');
    return {total_count:1,repositories:[{full_name:repo}]};
  });
});
for (const [name,change] of Object.entries({unknown:{mode:'unknown'},installation:{installation:'124'},
  empty:{expectedInstallation:''},slug:{slug:'foreign-app'},unbound:{expectedSlug:''}})) {
  test(`reject ${name} before using the credential`, async () => {
    await assert.rejects(verifyCredentials(repo,{...identity,...change},async () => {
      throw Error('must not contact API');
    }),/identity mismatch/);
  });
}
for (const response of [{total_count:2,repositories:[{full_name:repo},{full_name:'example/other'}]},
  {total_count:1,repositories:[{full_name:'example/other'}]},
  {total_count:1,repositories:[]},{total_count:0,repositories:[]}]) {
  test(`reject incomplete or excessive repository scope ${JSON.stringify(response)}`, async () => {
    await assert.rejects(verifyCredentials(repo,identity,async () => response),/restricted/);
  });
}
test('workflow-token mode cannot silently accept App identity', async () => {
  await assert.rejects(verifyCredentials(repo,{...identity,mode:'github-token'},async () => null),/identity supplied/);
});
test('existing workflow-token callers do not need an App', async () => {
  await verifyCredentials(repo,{mode:'github-token',installation:'',expectedInstallation:'',slug:'',expectedSlug:''},
    async () => {throw Error('must not contact API');});
});
