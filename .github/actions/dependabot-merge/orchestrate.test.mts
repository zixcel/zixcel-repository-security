import { test } from 'node:test';
import assert from 'node:assert/strict';
import { merge, type Client } from './orchestrate.mts';
const repo = 'example/project', sha = 'a'.repeat(40), merged = 'b'.repeat(40);
interface Scenario { failure?: string; unprotected?: boolean; major?: boolean; scripts?: boolean; conflict?: boolean; pending?: boolean; }
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
    if (path.endsWith('/rules/branches/main')) return options.unprotected ? [] : [{ type: 'pull_request' },
      { type: 'required_status_checks', parameters: { strict_required_status_checks_policy: true, required_status_checks: [{}] } }];
    if (path.includes('/commits?')) return [{ author: { login: 'dependabot[bot]', id: 49699333 },
      commit: { verification: { verified: true }, message: `Bumps x from 1.0.0 to ${options.major ? '2.0.0' : '1.0.1'}\n\n---\nupdated-dependencies:\n- dependency-name: x\n  update-type: version-update:semver-${options.major ? 'major' : 'patch'}\n...` } }];
    if (path.includes('/files?')) return [{ filename: 'package.json', status: 'modified' }];
    if (path.includes('/check-runs?')) return { total_count: 1, check_runs: [{ name: 'test', app: { id: 15368 },
      status: 'completed', conclusion: options.failure ?? 'success' }] };
    if (path.endsWith('/status')) return { total_count: 0, state: 'pending' };
    if (path.includes('/actions/runs?')) return { total_count: 1, workflow_runs: [{ status: options.pending ? 'in_progress' : 'completed', conclusion: 'success' }] };
    if (path.includes('/compare/')) return { behind_by: 0 };
    throw Error('Unexpected test API path');
  };
  let manifests = 0;
  const content = async () => ({ scripts: { test: options.scripts && manifests++ ? 'skip' : 'test' } });
  return { run: () => merge(repo, 1, api, content), writes: () => writes };
}
test('a complete successful scenario merges once and independently reads back', async () => {
  const s = scenario(); assert.equal(await s.run(), `merged: ${merged}`); assert.equal(s.writes(), 1);
});
test('failure and pending CI cannot perform a write', async () => {
  for (const options of [{ failure: 'failure' }, { pending: true }]) {
    const s = scenario(options); assert.match(await s.run(), /^waiting:/); assert.equal(s.writes(), 0);
  }
});
test('unprotected, major and package behavior changes need individual review', async () => {
  for (const options of [{ unprotected: true }, { major: true }, { scripts: true }]) {
    const s = scenario(options); assert.match(await s.run(), /^manual:/); assert.equal(s.writes(), 0);
  }
});
test('a conflicting or stale write is never replayed or bypassed', async () => {
  const s = scenario({ conflict: true }); await assert.rejects(s.run(), /409/); assert.equal(s.writes(), 1);
});
