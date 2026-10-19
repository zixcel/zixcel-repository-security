export const permissions = Object.freeze({contents:'write',pull_requests:'write',checks:'read',
  statuses:'read',actions:'read',metadata:'read'});
export type Json = Record<string, unknown>;
export const object = (x: unknown): Json => {
  if (!x || typeof x !== 'object' || Array.isArray(x)) throw Error('Invalid object');
  return x as Json;
};
export const list = (x: unknown): unknown[] => {
  if (!Array.isArray(x)) throw Error('Invalid list');
  return x;
};
export const text = (x: unknown): string => {
  if (typeof x !== 'string') throw Error('Invalid text');
  return x;
};
export const id = (x: unknown): number => {
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < 1) throw Error('Invalid ID');
  return x;
};
export function equalPermissions(value: unknown): boolean {
  const p = object(value);
  return Object.keys(p).length === Object.keys(permissions).length
    && Object.entries(permissions).every(([k,v]) => p[k] === v);
}
export function repositoryName(value: unknown): string {
  const name = text(value);
  if (!/^[a-z0-9][a-z0-9-]{0,38}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) throw Error('Invalid repository');
  return name;
}
export function manifest(owner: string, callback: string): Json {
  if (!/^[a-z0-9][a-z0-9-]{0,38}$/.test(owner)) throw Error('Invalid owner');
  const url = new URL(callback);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port) throw Error('Loopback callback required');
  return {name:`${owner}-dependency-merge`,url:'https://github.com/zixcel/zixcel-repository-security',
    redirect_url:callback,setup_url:callback.replace('/registered/','/installed/'),public:false,
    hook_attributes:{active:false,url:'https://github.com/zixcel/zixcel-repository-security'},
    default_permissions:permissions,default_events:[],request_oauth_on_install:false};
}
export function validateApp(value: unknown, ownerId: number, slug: string): Json {
  const app = object(value);
  if (id(object(app.owner).id) !== ownerId || app.slug !== slug || !equalPermissions(app.permissions)
    || list(app.events).length || (app.public !== undefined && app.public !== false)) throw Error('App binding mismatch');
  id(app.id);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{9,79}$/.test(text(app.client_id))) throw Error('Invalid client ID');
  return app;
}
export function validateInstallation(value: unknown, ownerId: number, appId: number): number {
  const i = object(value);
  if (id(object(i.account).id) !== ownerId || i.app_id !== appId || i.repository_selection !== 'selected'
    || i.suspended_at !== null || !equalPermissions(i.permissions)) throw Error('Installation binding mismatch');
  return id(i.id);
}
export function validateScope(value: unknown, repo: string, repoId: number): void {
  const v = object(value), repos = list(v.repositories).map(object);
  if (v.total_count !== 1 || repos.length !== 1 || repos[0]!.full_name !== repo || repos[0]!.id !== repoId)
    throw Error('Installation must select only the pilot repository');
}
