import {id,list,object,repositoryName,text,type Json} from './model.mts';
export interface Target {repository:string;repoId:number;ownerId:number}
export function configuredRepositories(config: Json): string[] {
  if ((config.repository === undefined) === (config.repositories === undefined))
    throw Error('Specify repository or repositories, not both');
  const values = config.repository === undefined ? list(config.repositories) : [config.repository];
  const names = values.map(repositoryName);
  if (!names.length || names.length > 100 || new Set(names).size !== names.length
    || names.some(n=>n.split('/')[0] !== names[0]!.split('/')[0]))
    throw Error('Select one owner with 1 to 100 unique repositories');
  return names;
}
export function target(value: unknown,repository:string): Target {
  const r=object(value),owner=object(r.owner);
  if (r.full_name !== repository || owner.type !== 'Organization' || r.default_branch !== 'main'
    || r.private !== false || r.archived !== false || object(r.permissions).admin !== true)
    throw Error('Repository binding mismatch');
  return {repository,repoId:id(r.id),ownerId:id(owner.id)};
}
export function validateSelection(value: unknown,targets: readonly Target[]): void {
  const v=object(value), repos=list(v.repositories).map(object);
  if (!targets.length || v.total_count !== targets.length || repos.length !== targets.length
    || new Set(repos.map(r=>id(r.id))).size !== targets.length
    || targets.some(t=>!repos.some(r=>r.id===t.repoId && text(r.full_name)===t.repository)))
    throw Error('Installation repository selection mismatch');
}
