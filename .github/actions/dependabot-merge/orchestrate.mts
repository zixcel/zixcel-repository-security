import { object, array, text, admitPull, admitFiles, admitChecks, signedCompatibleUpdate, admitNpmUpdate } from './policy.mts';
export type Client = (path: string, method?: string, body?: unknown) => Promise<unknown>;
export type Content = (repository: string, path: string, ref: string) => Promise<unknown>;
export async function merge(repository: string, number: number, api: Client, content: Content,
  requiredWorkflows: readonly string[]): Promise<string> {
  const prefix = `repos/${repository}`;
  if (!Number.isSafeInteger(number) || number < 1) throw Error('Invalid pull request number');
  if (!requiredWorkflows.length || requiredWorkflows.length > 20
    || new Set(requiredWorkflows).size !== requiredWorkflows.length
    || requiredWorkflows.some(name => !name.trim() || name.length > 160)) return 'manual: required CI workflow contract missing';
  const p = object(await api(`${prefix}/pulls/${number}`));
  if (!admitPull(p, repository)) return 'manual: author, branch or origin admission';
  const rules = array(await api(`${prefix}/rules/branches/main`)).map(object);
  if (!rules.some(r => r.type === 'pull_request') || !rules.some(r => r.type === 'required_status_checks'
    && object(r.parameters).strict_required_status_checks_policy === true
    && array(object(r.parameters).required_status_checks).length > 0)) return 'manual: strict required PR checks absent';
  const head = object(p.head), sha = text(head.sha);
  const commits = array(await api(`${prefix}/pulls/${number}/commits?per_page=100`));
  if (commits.length !== 1 || p.commits !== 1 || !signedCompatibleUpdate(commits[0])) return 'manual: unverified, major or unknown update';
  const files = array(await api(`${prefix}/pulls/${number}/files?per_page=100`));
  if (!admitFiles(files, p.changed_files)) return 'manual: change outside dependency definitions';
  const main = object(object(await api(`${prefix}/git/ref/heads/main`)).object);
  if (main.type !== 'commit' || !/^[a-f0-9]{40}$/.test(text(main.sha))) throw Error('Invalid live main identity');
  const baseSha = text(main.sha);
  const compare = object(await api(`${prefix}/compare/${baseSha}...${sha}`));
  if (compare.behind_by !== 0) return 'waiting: rebase against current main';
  for (const file of files) {
    const path = text(object(file).filename);
    if (path.endsWith('package.json') && !admitNpmUpdate(
      await content(repository, path, baseSha), await content(repository, path, sha))) return 'manual: package behavior changed';
  }
  if (!admitChecks(await api(`${prefix}/commits/${sha}/check-runs?per_page=100`))) return 'waiting: CI failure, absent, untrusted or incomplete';
  const status = object(await api(`${prefix}/commits/${sha}/status`));
  if (status.total_count !== 0 && status.state !== 'success') return 'waiting: legacy status checks';
  const runs = object(await api(`${prefix}/actions/runs?event=pull_request&head_sha=${sha}&per_page=100`));
  const workflowRuns = array(runs.workflow_runs).map(object);
  if (!workflowRuns.length || workflowRuns.length !== runs.total_count
    || workflowRuns.some(r => r.status !== 'completed' || r.conclusion !== 'success')) return 'waiting: PR workflows not all successful';
  if (workflowRuns.some(r => r.head_sha !== sha || r.event !== 'pull_request'
    || object(r.actor).login !== 'dependabot[bot]' || object(r.actor).id !== 49699333)) return 'manual: CI does not attest the current Bot head';
  const registry = object(await api(`${prefix}/actions/workflows?per_page=100`));
  const workflows = array(registry.workflows).map(object);
  if (workflows.length !== registry.total_count) return 'manual: incomplete workflow registry';
  for (const name of requiredWorkflows) {
    const matching = workflows.filter(w => w.name === name && w.state === 'active'
      && text(w.path).startsWith('.github/workflows/'));
    if (matching.length !== 1 || !Number.isSafeInteger(matching[0]!.id)) return 'manual: required workflow absent or ambiguous';
    if (!workflowRuns.some(r => r.workflow_id === matching[0]!.id)) return 'waiting: required validation workflow absent';
  }

  // The normal endpoint enforces rulesets. It has no admin/bypass mode.
  const result = object(await api(`${prefix}/pulls/${number}/merge`, 'PUT', { sha, merge_method: 'squash' }));
  const observed = object(await api(`${prefix}/pulls/${number}`));
  if (result.merged !== true || observed.merged !== true || observed.merge_commit_sha !== result.sha) throw Error('Merge result unverified; do not retry writes');
  return `merged: ${text(result.sha)}`;
}
