import {createAppAuth} from '@octokit/auth-app';
import {object,text,id,validateApp,validateInstallation,type Json} from './model.mts';
import {gh,request,absent,installSecret,type Client} from './github.mts';
import {environment,prepareEnvironment,verifyEnvironment,bindVariables,requireInactive} from './environment.mts';
import {verifyPrivateAdmission} from './private-admission.mts';
import {target,type Target} from './selection.mts';
import {verifyTokens,type RecordStage} from './tokens.mts';
export class Registration {
  #key = '';
  #app: Json | undefined;
  #appApi: Client | undefined;
  readonly owner: string;
  readonly slug: string;
  readonly repository: string;
  readonly ownerId: number;
  readonly repoId: number;
  #record: RecordStage;
  readonly repositories: readonly string[];
  readonly ownerType: 'User'|'Organization';
  #privateRepositories: readonly string[];
  #targets: Target[] = [];
  constructor(repository: string,ownerId: number,repoId: number,record: RecordStage,
    repositories: readonly string[] = [repository],
    privateRepositories:readonly string[] = [],ownerType:'User'|'Organization'='Organization') {
    this.repository=repository;this.ownerId=ownerId;this.repoId=repoId;this.#record=record;
    this.repositories = repositories;this.#privateRepositories=privateRepositories;this.ownerType=ownerType;
    this.owner = repository.split('/')[0]!;
    this.slug = `${this.owner}-dependency-merge`;
  }
  dispose(): void {this.#key='';this.#appApi=undefined;this.#app=undefined;}
  async preflight(): Promise<void> {
    if (this.#privateRepositories.some(r=>!this.repositories.includes(r)) || !this.repositories.length || this.repositories[0] !== this.repository
      || new Set(this.repositories).size !== this.repositories.length
      || this.repositories.some(r=>r.split('/')[0] !== this.owner)) throw Error('Owner selection mismatch');
    for (const repository of this.repositories) {
      const isPrivate=this.#privateRepositories.includes(repository);
      const t=target(await gh(`repos/${repository}`),repository,isPrivate,this.ownerType);
      if(isPrivate) await verifyPrivateAdmission(repository,gh);
      if(t.ownerId !== this.ownerId || (repository===this.repository && t.repoId !== this.repoId))
        throw Error('Owner identity mismatch');
      this.#targets.push(t);
    }
    for (const t of this.#targets) await prepareEnvironment(t.repository,gh);
    this.#record('environment_main_only_verified');
  }
  async registered(code: string): Promise<void> {
    if (this.#appApi || !/^[A-Za-z0-9_-]{20,128}$/.test(code)) throw Error('Invalid registration phase');
    this.#record('converting_manifest');
    const converted = object(await request(`app-manifests/${code}/conversions`,'POST'));
    this.#key = text(converted.pem);
    const auth = createAppAuth({appId:id(converted.id),privateKey:this.#key});
    this.#appApi = async (path,method='GET',body) =>
      request(path,method,body,(await auth({type:'app'})).token);
    this.#app = validateApp(await this.#appApi('app'),this.ownerId,this.slug);
    this.#record('app_registered',{appId:this.#app.id,clientId:this.#app.client_id,slug:this.slug,
      manifestPrivate:true,apiVisibilityObserved:this.#app.public === false});
  }
  async installed(installation: number): Promise<void> {
    if (!this.#appApi || !this.#app || !this.#key) throw Error('App registration required');
    const appId = id(this.#app.id);
    validateInstallation(await this.#appApi(`app/installations/${installation}`),this.ownerId,appId);
    this.#record('selected_installation_verified',{installationId:installation});
    for (const [index,t] of this.#targets.entries())
      await verifyTokens(this.#appApi,request,installation,t.repository,t.repoId,this.#record,this.#targets,index===0);
    // Recheck every destination before the first secret write. Partial writes stay explicit in the receipt.
    for (const t of this.#targets) {
      if(this.#privateRepositories.includes(t.repository)) await verifyPrivateAdmission(t.repository,gh);
      await prepareEnvironment(t.repository,gh);
    }
    for (const t of this.#targets) {
      if(this.#privateRepositories.includes(t.repository)) await verifyPrivateAdmission(t.repository,gh);
      await requireInactive(t.repository,gh);
      const path = await verifyEnvironment(t.repository,gh);
      await absent(`${path}/secrets/DEPENDENCY_MERGE_PRIVATE_KEY`,gh);
      this.#record('registering_environment_key',{repository:t.repository});
      installSecret(t.repository,environment,this.#key);
      await gh(`${path}/secrets/DEPENDENCY_MERGE_PRIVATE_KEY`);
      this.#record('environment_key_registered',{repository:t.repository});
      await bindVariables(t.repository,{APP_ID:String(appId),CLIENT_ID:text(this.#app.client_id),
        APP_SLUG:this.slug,INSTALLATION_ID:String(installation)},gh);
      this.#record('repository_bound',{repository:t.repository,appId,installationId:installation});
    }
    this.#key = '';
    this.#record('complete',{appId,installationId:installation,repositories:[...this.repositories],
      activationChanged:false,protectionChanged:false,temporaryTokensRevoked:true});
    this.#appApi = undefined;
    this.#app = undefined;
  }
}
