import {object,text,permissions,equalPermissions,validateScope,type Json} from './model.mts';
import {HttpFailure,type Client} from './github.mts';
export type Wire = (path: string,method?: string,body?: Json,token?: string) => Promise<unknown>;
export type RecordStage = (stage: string,details?: Json) => void;
export async function verifyTokens(app: Client,wire: Wire,installation: number,repository: string,
  repoId: number,record: RecordStage): Promise<void> {
  for (const scoped of [false,true]) {
    record('creating_probe_token',{repositoryScoped:scoped});
    const granted = scoped ? {...permissions} : {metadata:'read'};
    const data = object(await app(`app/installations/${installation}/access_tokens`,'POST',
      {permissions:granted,...(scoped ? {repository_ids:[repoId]} : {})}));
    const token = text(data.token);
    if (!token) throw Error('Missing installation token');
    try {
      const p = object(data.permissions), expiry = Date.parse(text(data.expires_at));
      if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now()+3_660_000
        || (scoped ? !equalPermissions(p) : Object.keys(p).length !== 1 || p.metadata !== 'read'))
        throw Error('Unexpected token permissions or expiration');
      validateScope(await wire('installation/repositories?per_page=100','GET',undefined,token),repository,repoId);
      if (scoped) {
        if (object(await wire(`repos/${repository}`,'GET',undefined,token)).id !== repoId)
          throw Error('Repository identity mismatch');
        await wire(`repos/${repository}/rules/branches/main`,'GET',undefined,token);
      }
      record('probe_token_verified',{repositoryScoped:scoped});
    } finally {
      await wire('installation/token','DELETE',undefined,token);
      let revoked = false;
      try {await wire('installation/repositories?per_page=100','GET',undefined,token);}
      catch (e) {if (!(e instanceof HttpFailure) || e.status !== 401) throw e;revoked=true;}
      if (!revoked) throw Error('Token revocation not independently confirmed');
      record('probe_token_revoked',{repositoryScoped:scoped});
    }
  }
}
