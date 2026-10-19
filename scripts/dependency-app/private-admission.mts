import {id,list,object,text} from './model.mts';
import {admitChecks} from '../../.github/actions/dependabot-merge/policy.mts';
import type {Client} from './github.mts';
export async function verifyPrivateAdmission(repository:string,client:Client):Promise<void> {
  const prefix=`repos/${repository}`;
  if(object(await client(`${prefix}/actions/permissions`)).enabled !== true)
    throw Error('Private repository Actions must be enabled');
  const rules=list(await client(`${prefix}/rules/branches/main`)).map(object);
  for(const type of ['pull_request','deletion','non_fast_forward'])
    if(!rules.some(r=>r.type===type)) throw Error('Effective private branch protection required');
  const checkRules=rules.filter(r=>r.type==='required_status_checks').map(r=>object(r.parameters));
  if(!checkRules.length || checkRules.some(r=>r.strict_required_status_checks_policy !== true))
    throw Error('Strict private required checks must be effective');
  const required=checkRules.flatMap(r=>list(r.required_status_checks).map(object));
  if(!required.length || required.some(c=>!text(c.context).trim() || c.integration_id !== 15368))
    throw Error('Required checks must be bound to GitHub Actions');
  const ref=object(object(await client(`${prefix}/git/ref/heads/main`)).object);
  const sha=text(ref.sha);
  if(ref.type !== 'commit' || !/^[a-f0-9]{40}$/.test(sha)) throw Error('Invalid main identity');
  const response=object(await client(`${prefix}/commits/${sha}/check-runs?per_page=100`));
  const checks=list(response.check_runs).map(object);
  if(!admitChecks(response))
    throw Error('Complete private main CI evidence required');
  for(const expected of required) {
    const matches=checks.filter(c=>c.name===expected.context && object(c.app).id===15368);
    if(matches.length!==1 || matches[0]!.head_sha!==sha || matches[0]!.status!=='completed'
      || matches[0]!.conclusion!=='success') throw Error('Required private main CI must succeed');
    id(matches[0]!.id);
  }
}
