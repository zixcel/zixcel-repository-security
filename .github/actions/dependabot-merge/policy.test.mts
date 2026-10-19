import { test } from 'node:test';
import assert from 'node:assert/strict';
import { admitPull, admitFiles, admitChecks, signedCompatibleUpdate, unchangedNpmStructure } from './policy.mts';
const commit = (from = '1.2.0', to = '1.3.0', kind = 'minor') => ({
  author: { login: 'dependabot[bot]', id: 49699333 },
  commit: { verification: { verified: true }, message: `Bumps package from ${from} to ${to}\n\n---\nupdated-dependencies:\n- dependency-name: package\n  update-type: version-update:semver-${kind}\n...` },
});
test('signed patch and compatible minor updates are accepted', () => {
  assert.equal(signedCompatibleUpdate(commit()), true);
  assert.equal(signedCompatibleUpdate(commit('0.4.1', '0.4.2', 'patch')), true);
});
test('major, zero-major minor, downgrade and unclassified updates are refused', () => {
  for (const args of [['1.2.0', '2.0.0', 'major'], ['0.4.1', '0.5.0', 'minor'], ['1.3.0', '1.2.9', 'patch']])
    assert.equal(signedCompatibleUpdate(commit(...args)), false);
  const c = commit(); c.commit.message = 'Updates are safe';
  assert.equal(signedCompatibleUpdate(c), false);
});
test('unverified or impersonated bot commits are refused', () => {
  const c = commit(); c.commit.verification.verified = false;
  assert.equal(signedCompatibleUpdate(c), false);
  const d = commit(); d.author.id = 42;
  assert.equal(signedCompatibleUpdate(d), false);
});
test('group metadata cannot hide a major or unmatched dependency', () => {
  const c = commit(); c.commit.message += '\n- dependency-name: other\n  update-type: version-update:semver-major';
  assert.equal(signedCompatibleUpdate(c), false);
});
const pull = () => ({ state: 'open', draft: false, user: { login: 'dependabot[bot]', id: 49699333 },
  head: { repo: { full_name: 'example/project' }, ref: 'dependabot/npm/example', sha: 'a'.repeat(40) },
  base: { repo: { full_name: 'example/project' }, ref: 'main' } });
test('only same-repository bot PRs to main qualify', () => {
  assert.equal(admitPull(pull(), 'example/project'), true);
  const p = pull(); p.head.repo.full_name = 'other/project';
  assert.equal(admitPull(p, 'example/project'), false);
  assert.equal(admitPull({ ...pull(), draft: true }, 'example/project'), false);
});
test('source, workflow, added files, oversized and truncated sets are refused', () => {
  assert.equal(admitFiles([{ filename: 'ui/package.json', status: 'modified' }], 1), true);
  for (const filename of ['src/main.rs', '.github/workflows/ci.yml', '../package.json'])
    assert.equal(admitFiles([{ filename, status: 'modified' }], 1), false);
  assert.equal(admitFiles([{ filename: 'package.json', status: 'added' }], 1), false);
  assert.equal(admitFiles([], 1), false);
});
test('dependency version changes cannot change scripts, engines or overrides', () => {
  assert.equal(unchangedNpmStructure({ scripts: { test: 'test' }, dependencies: { x: '1' } },
    { dependencies: { x: '2' }, scripts: { test: 'test' } }), true);
  assert.equal(unchangedNpmStructure({ scripts: { test: 'test' } }, { scripts: { test: 'skip' } }), false);
  assert.equal(unchangedNpmStructure({}, { engines: { node: '26' } }), false);
});
const check = (conclusion = 'success', id = 15368) => ({ status: 'completed', conclusion, name: 'test', app: { id } });
test('checks must be complete, successful, trusted and include real validation', () => {
  assert.equal(admitChecks({ total_count: 1, check_runs: [check()] }), true);
  for (const r of [{ total_count: 0, check_runs: [] }, { total_count: 2, check_runs: [check()] },
    { total_count: 1, check_runs: [check('failure')] }, { total_count: 1, check_runs: [check('success', 42)] },
    { total_count: 1, check_runs: [{ ...check(), name: 'repository-policy' }] }]) assert.equal(admitChecks(r), false);
});
test('malformed API objects fail closed', () => {
  for (const f of [() => admitChecks(null), () => admitPull({}, 'example/project'), () => admitFiles({}, 1)]) assert.throws(f);
});
