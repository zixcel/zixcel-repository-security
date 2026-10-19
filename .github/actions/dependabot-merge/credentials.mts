import {object, array} from './policy.mts';
import type {Client} from './orchestrate.mts';
export interface Identity {
  mode: string;
  installation: string;
  expectedInstallation: string;
  slug: string;
  expectedSlug: string;
}
export async function verifyCredentials(repository: string, identity: Identity, api: Client): Promise<void> {
  if (identity.mode === 'github-token') {
    if (identity.installation || identity.expectedInstallation || identity.slug || identity.expectedSlug)
      throw Error('App identity supplied in workflow-token mode');
    return;
  }
  if (identity.mode !== 'github-app' || !/^[1-9]\d{0,15}$/.test(identity.installation)
    || identity.installation !== identity.expectedInstallation || !/^[a-z0-9-]{1,100}$/.test(identity.slug)
    || identity.slug !== identity.expectedSlug) throw Error('App installation identity mismatch');
  const response = object(await api('installation/repositories?per_page=100'));
  const repos = array(response.repositories).map(object);
  if (response.total_count !== 1 || repos.length !== 1 || repos[0]!.full_name !== repository)
    throw Error('App token must be restricted to the current repository');
}
