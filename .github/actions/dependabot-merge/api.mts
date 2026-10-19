import { object, text } from './policy.mts';
export async function api(path: string, method = 'GET', body?: unknown): Promise<unknown> {
  const repository = process.env.GITHUB_REPOSITORY ?? '';
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository) || !path.startsWith(`repos/${repository}/`)
    || path.includes('..') || path.includes('://') || path.split('?')[0]!.includes('%'))
    throw Error('Invalid API path or repository scope');
  if (method !== 'GET' && !(method === 'PUT' && /^repos\/[\w.-]+\/[\w.-]+\/pulls\/[1-9]\d*\/merge$/.test(path)))
    throw Error('Only a normal pull request merge may mutate GitHub');
  const token = process.env.GH_TOKEN;
  if (!token) throw Error('Missing owner workflow token');
  const response = await fetch(`https://api.github.com/${path}`, {
    method, redirect: 'error', signal: AbortSignal.timeout(30000),
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) throw Error(`GitHub API ${method} HTTP ${response.status}; no retry or bypass`);
  const reader = response.body?.getReader();
  if (!reader) throw Error('Missing API response body');
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    while (true) {
      const part = await reader.read(); if (part.done) break;
      length += part.value.length;
      if (length > 8_000_000) throw Error('API response exceeded admission bound');
      chunks.push(part.value);
    }
  } finally { await reader.cancel(); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}
export async function content(repository: string, path: string, ref: string): Promise<unknown> {
  if (!/^[a-f0-9]{40}$/.test(ref)) throw Error('Invalid immutable source');
  const value = object(await api(`repos/${repository}/contents/${path}?ref=${ref}`));
  if (value.encoding !== 'base64') throw Error('Unsupported manifest encoding');
  return JSON.parse(Buffer.from(text(value.content), 'base64').toString('utf8')) as unknown;
}
