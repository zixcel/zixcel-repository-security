import {execFileSync} from 'node:child_process';
import {object, type Json} from './model.mts';
export type Client = (path: string, method?: string, body?: Json) => Promise<unknown>;
export class Missing extends Error {}
export class HttpFailure extends Error {
  readonly status: number;
  constructor(status: number) {super(`GitHub HTTP ${status}; do not replay writes`);this.status=status;}
}
function pathAllowed(path: string): void {
  if (!/^(repos|orgs|app|app-manifests|installation)(\/|$)/.test(path)
    || path.includes('..') || path.includes('://')) throw Error('Invalid API route');
}
export const gh: Client = async (path,method='GET',body) => {
  pathAllowed(path);
  try {
    const result = execFileSync('gh',['api',path,'--method',method,...(body ? ['--input','-'] : [])],
      {encoding:'utf8',input:body ? JSON.stringify(body) : undefined,maxBuffer:4_000_000,
        timeout:45000,stdio:['pipe','pipe','pipe']});
    return result.trim() ? JSON.parse(result) as unknown : null;
  } catch (error) {
    const output = object(error).stdout;
    try {
      const status = Number(object(JSON.parse(String(output))).status);
      if (status === 404) throw new Missing('Not found');
      if (Number.isInteger(status) && status >= 400 && status <= 599) throw new HttpFailure(status);
    } catch (e) {if (e instanceof Missing || e instanceof HttpFailure) throw e;}
    throw Error('GitHub management request failed; do not replay writes');
  }
};
export async function request(path: string, method='GET', body?: Json, token?: string): Promise<unknown> {
  pathAllowed(path);
  try {
    const response = await fetch(`https://api.github.com/${path}`,{method,redirect:'error',
      signal:AbortSignal.timeout(30000),headers:{Accept:'application/vnd.github+json',
        'X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json',
        ...(token ? {Authorization:`Bearer ${token}`} : {})},
      ...(body ? {body:JSON.stringify(body)} : {})});
    if (!response.ok) throw new HttpFailure(response.status);
    if (response.status === 204) return null;
    const reader = response.body?.getReader();
    if (!reader) throw Error('Missing body');
    const parts: Uint8Array[] = []; let bytes = 0;
    try {
      while (true) {const p = await reader.read(); if (p.done) break;
        bytes += p.value.length; if (bytes > 1_000_000) throw Error('Response bound'); parts.push(p.value);}
    } finally {await reader.cancel();}
    return JSON.parse(Buffer.concat(parts).toString('utf8')) as unknown;
  } catch (e) {if (e instanceof HttpFailure) throw e;
    throw Error('GitHub App request failed; no credential or response logged');}
}
export async function absent(path: string, client: Client): Promise<void> {
  try {await client(path);} catch (e) {if (e instanceof Missing) return; throw e;}
  throw Error('Existing configuration must be reviewed before replacement');
}
export function installSecret(repository: string,environment: string,key: string): void {
  try {
    execFileSync('gh',['secret','set','DEPENDENCY_MERGE_PRIVATE_KEY','--repo',repository,'--env',environment],
      {input:key,stdio:['pipe','pipe','pipe'],timeout:60000,maxBuffer:100000});
  } catch {throw Error('Secret registration unverified; do not replay writes');}
}
