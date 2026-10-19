export const object = (x: unknown): Record<string, unknown> => {
  if (!x || typeof x !== 'object' || Array.isArray(x)) throw Error('Invalid API object');
  return x as Record<string, unknown>;
};
export const array = (x: unknown): unknown[] => {
  if (!Array.isArray(x)) throw Error('Invalid API array');
  return x;
};
export const text = (x: unknown): string => {
  if (typeof x !== 'string') throw Error('Invalid API string');
  return x;
};
function compatibleVersion(from: string, to: string): boolean {
  const valid = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
  if (!valid.test(from) || !valid.test(to)) return false;
  const a = from.split('.').map(Number), b = to.split('.').map(Number);
  return [...a, ...b].every(Number.isSafeInteger) && a[0] === b[0] && (a[0] !== 0 || a[1] === b[1])
    && (b[1]! > a[1]! || (b[1] === a[1] && b[2]! > a[2]!));
}
export function signedCompatibleUpdate(value: unknown): boolean {
  const commit = object(value), author = object(commit.author), committer = object(commit.committer);
  const detail = object(commit.commit), verification = object(detail.verification);
  const trustedCommitter = (committer.login === 'web-flow' && committer.id === 19864447)
    || (committer.login === 'dependabot[bot]' && committer.id === 49699333);
  if (author.login !== 'dependabot[bot]' || author.id !== 49699333 || !trustedCommitter
    || verification.verified !== true || verification.reason !== 'valid') return false;
  const message = text(detail.message);
  const metadata = message.split('\nupdated-dependencies:\n')[1]?.split('\n...')[0];
  if (!metadata) return false;
  const names = [...metadata.matchAll(/^- dependency-name:/gm)];
  const types = [...metadata.matchAll(/^\s+update-type: version-update:semver-(\w+)\s*$/gm)];
  const pairs = [...message.split('\n---\n')[0]!.matchAll(/\bfrom (\d+\.\d+\.\d+) to (\d+\.\d+\.\d+)(?=\s|$)/g)];
  if ([...message.matchAll(/^- dependency-name:/gm)].length !== names.length) return false;
  if (!names.length || types.length !== names.length || pairs.length !== names.length) return false;
  if (types.some(t => !['patch', 'minor'].includes(t[1]!))) return false;
  return pairs.every(pair => compatibleVersion(pair[1]!, pair[2]!));
}
export function admitPull(value: unknown, repository: string): boolean {
  const p = object(value), user = object(p.user), head = object(p.head), base = object(p.base);
  return p.state === 'open' && p.draft === false && user.login === 'dependabot[bot]' && user.id === 49699333
    && object(head.repo).full_name === repository && object(base.repo).full_name === repository
    && base.ref === 'main' && /^dependabot\//.test(text(head.ref)) && /^[a-f0-9]{40}$/.test(text(head.sha));
}
export function admitFiles(value: unknown, count: unknown): boolean {
  const files = array(value);
  return Number.isSafeInteger(count) && files.length === count && files.length > 0 && files.length <= 40
    && files.every(value => {
      const f = object(value), path = text(f.filename);
      return f.status === 'modified' && /^[A-Za-z0-9._/-]+$/.test(path) && !path.startsWith('/') && !path.split('/').includes('..')
        && /(^|\/)(package\.json|pnpm-lock\.ya?ml|package-lock\.json|Cargo\.(toml|lock)|pom\.xml|go\.(mod|sum))$/.test(path);
    });
}
export function admitNpmUpdate(before: unknown, after: unknown): boolean {
  const fields = ['dependencies', 'devDependencies', 'optionalDependencies'];
  const clean = (x: unknown): unknown => Object.fromEntries(Object.entries(object(x))
    .filter(([key]) => !fields.includes(key)));
  const canonical = (x: unknown): string => JSON.stringify(x, (_, v: unknown) =>
    v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort()) : v);
  if (canonical(clean(before)) !== canonical(clean(after))) return false;
  return fields.every(field => {
    const a = object(object(before)[field] ?? {}), b = object(object(after)[field] ?? {});
    return Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(name =>
      Object.hasOwn(b, name) && (a[name] === b[name] || (typeof a[name] === 'string'
        && typeof b[name] === 'string' && compatibleVersion(a[name], b[name]))));
  });
}
export function admitChecks(value: unknown): boolean {
  const response = object(value), checks = array(response.check_runs).map(object);
  return checks.length > 0 && checks.length === response.total_count
    && checks.every(c => c.status === 'completed' && object(c.app).id === 15368
      && ['success', 'neutral', 'skipped'].includes(text(c.conclusion)))
    && checks.some(c => c.conclusion === 'success' && c.name !== 'repository-policy');
}
