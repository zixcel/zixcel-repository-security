import { test } from 'node:test';
import assert from 'node:assert/strict';
import { merge, type Client } from './orchestrate.mts';
const repo = 'example/project', sha = 'a'.repeat(40), merged = 'b'.repeat(40);
interface Scenario { failure?: string; major?: boolean; scripts?: boolean; conflict?: boolean; pending?: boolean; staleBase?: boolean; foreignActor?: boolean; foreignHead?: boolean; noWorkflow?: boolean; missingWorkflow?: boolean; missingContract?: boolean; disabledWorkflow?: boolean; actualMajor?: boolean; }
function scenario(options: Scenario = {}) {
  let writes = 0;
  const api: Client = async (path, method) => {
    if (method === 'PUT') {
      writes++;
      if (options.conflict) throw Error('GitHub API PUT HTTP 409; no retry or bypass');
      return { merged: true, sha: merged };
    }
    if (path.endsWith('/pulls/1')) return { state: writes ? 'closed' : 'open', draft: false,
      user: { login: 'dependabot[bot]', id: 49699333 }, changed_files: 1, commits: 1,
      head: { repo: { full_name: repo }, ref: 'dependabot/npm/example', sha },
      base: { repo: { full_name: repo }, ref: 'main', sha: 'c'.repeat(40) }, merged: writes > 0, merge_commit_sha: merged };
    if (path.endsWith('/git/ref/heads/main')) return { object: { type: 'commit', sha: 'd'.repeat(40) } };
    if (path.includes('/commits?')) return [{ committer: { login: 'web-flow', id: 19864447 }, author: { login: 'dependabot[bot]', id: 49699333 },
      commit: { verification: { verified: true, reason: 'valid' }, message: `Bumps x from 1.0.0 to ${options.major ? '2.0.0' : '1.0.1'}\n\n---\nupdated-dependencies:\n- dependency-name: x\n  update-type: version-update:semver-${options.major ? 'major' : 'patch'}\n...` } }];
    if (path.includes('/files?')) return [{ filename: 'package.json', status: 'modified' }];
    if (path.includes('/check-runs?')) return { total_count: 1, check_runs: [{ name: 'test', app: { id: 15368 },
      status: 'completed', conclusion: options.failure ?? 'success' }] };
    if (path.endsWith('/status')) return { total_count: 0, state: 'pending' };
    if (path.includes('/actions/workflows?')) return { total_count: 1, workflows: [{ id: 5, name: 'CI', state: options.disabledWorkflow ? 'disabled_manually' : 'active', path: '.github/workflows/ci.yml' }] };
    if (path.includes('/actions/runs?')) return { total_count: options.noWorkflow ? 0 : 1,
      workflow_runs: options.noWorkflow ? [] : [{ workflow_id: options.missingWorkflow ? 6 : 5,
        event: 'pull_request', head_sha: options.foreignHead ? 'e'.repeat(40) : sha,
        actor: options.foreignActor ? { login: 'contributor', id: 42 } : { login: 'dependabot[bot]', id: 49699333 },
        status: options.pending ? 'in_progress' : 'completed', conclusion: 'success' }] };
    if (path.includes('/compare/')) return { behind_by: options.staleBase && path.includes('d'.repeat(40)) ? 1 : 0 };
    throw Error('Unexpected test API path');
  };
  let manifests = 0;
  const content = async () => {
    const after = manifests++ > 0;
    return { scripts: { test: options.scripts && after ? 'skip' : 'test' },
      dependencies: { x: after ? (options.actualMajor ? '2.0.0' : '1.0.1') : '1.0.0' } };
  };
  return { run: () => merge(repo, 1, api, content, options.missingContract ? [] : ['CI']), writes: () => writes };
}
test('successful CI merges once without paid protection API calls and independently reads back', async () => {
  const s = scenario(); assert.equal(await s.run(), `merged: ${merged}`); assert.equal(s.writes(), 1);
});
test('failure and pending CI cannot perform a write', async () => {
  for (const options of [{ failure: 'failure' }, { pending: true }]) {
    const s = scenario(options); assert.match(await s.run(), /^waiting:/); assert.equal(s.writes(), 0);
  }
});
test('major and package behavior changes need individual review', async () => {
  for (const options of [{ major: true }, { scripts: true }]) {
    const s = scenario(options); assert.match(await s.run(), /^manual:/); assert.equal(s.writes(), 0);
  }
});
test('a conflicting or stale write is never replayed or bypassed', async () => {
  const s = scenario({ conflict: true }); await assert.rejects(s.run(), /409/); assert.equal(s.writes(), 1);
});

test('stale PR base metadata cannot authorize a merge against an older main', async () => {
  const s = scenario({ staleBase: true });
  assert.match(await s.run(), /rebase against current main/);
  assert.equal(s.writes(), 0);
});

test('successful checks cannot replace CI attesting the current Bot head', async () => {
  for (const options of [{ foreignActor: true }, { foreignHead: true }, { noWorkflow: true }, { disabledWorkflow: true }]) {
    const s = scenario(options);
    assert.match(await s.run(), /^(manual|waiting):/);
    assert.equal(s.writes(), 0);
  }
});
test('a fake passing check cannot replace a required validation workflow', async () => {
  const s = scenario({ missingWorkflow: true });
  assert.match(await s.run(), /^(manual|waiting):/);
  assert.equal(s.writes(), 0);
});

test('a trusted workflow contract is required and actual manifest majors cannot be hidden', async () => {
  for (const options of [{ missingContract: true }, { actualMajor: true }]) {
    const s = scenario(options);
    assert.match(await s.run(), /^manual:/);
    assert.equal(s.writes(), 0);
  }
});
