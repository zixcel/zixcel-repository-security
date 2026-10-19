import { object, array, text, admitPull, admitFiles, admitChecks, signedCompatibleUpdate, unchangedNpmStructure } from './policy.mts';
export type Client = (path: string, method?: string, body?: unknown) => Promise<unknown>;
export type Content = (repository: string, path: string, ref: string) => Promise<unknown>;
export async function merge(repository: string, number: number, api: Client, content: Content): Promise<string> {
  const prefix = `repos/${repository}`;
  if (!Number.isSafeInteger(number) || number < 1) throw Error('Invalid pull request number');
  const p = object(await api(`${prefix}/pulls/${number}`));
  if (!admitPull(p, repository)) return 'manual: author, branch or origin admission';
  const rules = array(await api(`${prefix}/rules/branches/main`)).map(object);
  if (!rules.some(r => r.type === 'pull_request') || !rules.some(r => r.type === 'required_status_checks'
    && object(r.parameters).strict_required_status_checks_policy === true
    && array(object(r.parameters).required_status_checks).length > 0)) return 'manual: strict required PR checks absent';
  const head = object(p.head), sha = text(head.sha), base = object(p.base);
  const commits = array(await api(`${prefix}/pulls/${number}/commits?per_page=100`));
  if (commits.length !== 1 || p.commits !== 1 || !signedCompatibleUpdate(commits[0])) return 'manual: unverified, major or unknown update';
  const files = array(await api(`${prefix}/pulls/${number}/files?per_page=100`));
  if (!admitFiles(files, p.changed_files)) return 'manual: change outside dependency definitions';
  for (const file of files) {
    const path = text(object(file).filename);
    if (path.endsWith('package.json') && !unchangedNpmStructure(
      await content(repository, path, text(base.sha)), await content(repository, path, sha))) return 'manual: package behavior changed';
  }
  if (!admitChecks(await api(`${prefix}/commits/${sha}/check-runs?per_page=100`))) return 'waiting: CI failure, absent, untrusted or incomplete';
  const status = object(await api(`${prefix}/commits/${sha}/status`));
  if (status.total_count !== 0 && status.state !== 'success') return 'waiting: legacy status checks';
  const runs = object(await api(`${prefix}/actions/runs?event=pull_request&head_sha=${sha}&per_page=100`));
  const workflowRuns = array(runs.workflow_runs).map(object);
  if (workflowRuns.length !== runs.total_count || workflowRuns.some(r => r.status !== 'completed' || r.conclusion !== 'success')) return 'waiting: PR workflows not all successful';
  const compare = object(await api(`${prefix}/compare/${text(base.sha)}...${sha}`));
  if (compare.behind_by !== 0) return 'waiting: rebase against current main';
  // The normal endpoint enforces rulesets. It has no admin/bypass mode.
  const result = object(await api(`${prefix}/pulls/${number}/merge`, 'PUT', { sha, merge_method: 'squash' }));
  const observed = object(await api(`${prefix}/pulls/${number}`));
  if (result.merged !== true || observed.merged !== true || observed.merge_commit_sha !== result.sha) throw Error('Merge result unverified; do not retry writes');
  return `merged: ${text(result.sha)}`;
}
