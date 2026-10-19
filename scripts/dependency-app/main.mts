import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {object,text,id} from './model.mts';
import {gh,HttpFailure} from './github.mts';
import {receipt} from './receipt.mts';
import {configuredRepositories,configuredPrivateRepositories} from './selection.mts';
import {Registration} from './registration.mts';
import {serve} from './server.mts';
import type {RecordStage} from './tokens.mts';
process.umask(0o077);
let record: RecordStage | undefined;
try {
  if (process.argv.length !== 3) throw Error('One local configuration file required');
  const config = object(JSON.parse(readFileSync(process.argv[2]!,'utf8')));
  const repositories = configuredRepositories(config);
  const repository = repositories[0]!;
  const privateRepositories=configuredPrivateRepositories(config,repositories);
  const path = join(text(config.receiptDirectory),`setup-${Date.now()}-${randomBytes(6).toString('hex')}.jsonl`);
  record = receipt(path);
  const log = record;
  console.log(`Private setup receipt: ${path}`);
  const repo = object(await gh(`repos/${repository}`));
  const ownerType=object(repo.owner).type;
  if(ownerType !== 'User' && ownerType !== 'Organization') throw Error('Unsupported owner type');
  const registration = new Registration(repository,id(object(repo.owner).id),id(repo.id),record,
    repositories,privateRepositories,ownerType);
  record('starting',{repositories});
  await registration.preflight();
  let server: Awaited<ReturnType<typeof serve>>;
  server = await serve(registration,(state,status) => {
    if (state === 'stopped') {log('stopped',{httpStatus:status ?? null});process.exitCode=1;}
    else console.log('Dependency App registered; Environment key and token cleanup verified; activation unchanged.');
    registration.dispose();server.close();
  });
  process.on('SIGINT',()=>{log('session_closed');registration.dispose();server.close();});
  console.log(`Open the local setup page: ${server.url}`);
  console.log('Keep this process open. No key is printed or saved to a local file.');
} catch (error) {
  record?.('stopped',{httpStatus:error instanceof HttpFailure ? error.status : null});
  console.error('App setup stopped. Inspect the private receipt; do not replay writes.');
  process.exitCode=1;
}
