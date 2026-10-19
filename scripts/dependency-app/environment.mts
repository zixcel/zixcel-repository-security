import {object,list,type Json} from './model.mts';
import {Missing,absent,type Client} from './github.mts';
export const environment = 'dependency-maintenance';
export async function requireInactive(repository: string,client: Client): Promise<void> {
  try {
    const variable = object(await client(`repos/${repository}/actions/variables/DEPENDABOT_AUTOMERGE_ENABLED`));
    if (variable.value !== 'false') throw Error('App registration requires inactive merging');
  } catch (e) {if (!(e instanceof Missing)) throw e;}
}
export function validateEnvironment(value: unknown): void {
  const v = object(value), p = object(v.deployment_branch_policy);
  if (v.name !== environment || p.protected_branches !== false || p.custom_branch_policies !== true
    || list(v.protection_rules).some(r => object(r).type !== 'branch_policy')) throw Error('Environment protection mismatch');
}
export async function verifyEnvironment(repository: string,client: Client): Promise<string> {
  const path = `repos/${repository}/environments/${environment}`;
  validateEnvironment(await client(path));
  const policies = object(await client(`${path}/deployment-branch-policies?per_page=100`));
  const rules = list(policies.branch_policies).map(object);
  if (policies.total_count !== 1 || rules.length !== 1 || rules[0]!.name !== 'main' || rules[0]!.type !== 'branch')
    throw Error('Only the main branch may unlock this Environment');
  return path;
}
export async function prepareEnvironment(repository: string,client: Client): Promise<void> {
  await requireInactive(repository,client);
  const path = `repos/${repository}/environments/${environment}`;
  let exists = true;
  try {await client(path);} catch (e) {if (!(e instanceof Missing)) throw e; exists = false;}
  if (!exists) {
    await absent(path,client);
    await client(path,'PUT',{deployment_branch_policy:{protected_branches:false,custom_branch_policies:true}});
    await client(`${path}/deployment-branch-policies`,'POST',{name:'main',type:'branch'});
  }
  await verifyEnvironment(repository,client);
  await absent(`${path}/secrets/DEPENDENCY_MERGE_PRIVATE_KEY`,client);
  for (const name of ['APP_ID','CLIENT_ID','APP_SLUG','INSTALLATION_ID'])
    await absent(`${path}/variables/DEPENDENCY_MERGE_${name}`,client);
}
export async function bindVariables(repository: string,values: Record<string,string>,client: Client): Promise<void> {
  const path = await verifyEnvironment(repository,client);
  for (const [key,value] of Object.entries(values)) {
    const name = `DEPENDENCY_MERGE_${key}`;
    if (!['APP_ID','CLIENT_ID','APP_SLUG','INSTALLATION_ID'].includes(key)) throw Error('Unapproved variable');
    await absent(`${path}/variables/${name}`,client);
    await client(`${path}/variables`,'POST',{name,value});
    if (object(await client(`${path}/variables/${name}`)).value !== value) throw Error('Variable registration unverified');
  }
}
