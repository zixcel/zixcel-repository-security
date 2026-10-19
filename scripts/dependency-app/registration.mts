import {createAppAuth} from '@octokit/auth-app';
import {object,text,id,validateApp,validateInstallation,type Json} from './model.mts';
import {gh,request,absent,installSecret,type Client} from './github.mts';
import {environment,prepareEnvironment,verifyEnvironment,bindVariables} from './environment.mts';
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
  constructor(repository: string,ownerId: number,repoId: number,record: RecordStage) {
    this.repository=repository;this.ownerId=ownerId;this.repoId=repoId;this.#record=record;
    this.owner = repository.split('/')[0]!;
    this.slug = `${this.owner}-dependency-merge`;
  }
  dispose(): void {this.#key='';this.#appApi=undefined;this.#app=undefined;}
  async preflight(): Promise<void> {
    const repo = object(await gh(`repos/${this.repository}`));
    if (repo.id !== this.repoId || repo.full_name !== this.repository || object(repo.owner).id !== this.ownerId
      || object(repo.owner).type !== 'Organization' || repo.default_branch !== 'main'
      || repo.private !== false || repo.archived !== false || object(repo.permissions).admin !== true)
      throw Error('Pilot repository binding mismatch');
    await prepareEnvironment(this.repository,gh);
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
    await verifyTokens(this.#appApi,request,installation,this.repository,this.repoId,this.#record);
    const path = await verifyEnvironment(this.repository,gh);
    await absent(`${path}/secrets/DEPENDENCY_MERGE_PRIVATE_KEY`,gh);
    this.#record('registering_environment_key');
    installSecret(this.repository,environment,this.#key);
    await gh(`${path}/secrets/DEPENDENCY_MERGE_PRIVATE_KEY`);
    this.#record('environment_key_registered');
    this.#key = '';
    await bindVariables(this.repository,{APP_ID:String(appId),CLIENT_ID:text(this.#app.client_id),
      APP_SLUG:this.slug,INSTALLATION_ID:String(installation)},gh);
    this.#record('complete',{appId,installationId:installation,repository:this.repository,
      activationChanged:false,protectionChanged:false,temporaryTokensRevoked:true});
    this.#appApi = undefined;
    this.#app = undefined;
  }
}
