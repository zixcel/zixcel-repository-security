import {readFileSync} from 'node:fs';
import {object,text,id,repositoryName} from './model.mts';
import {gh,HttpFailure} from './github.mts';
import {receipt} from './receipt.mts';
import {Registration} from './registration.mts';
import {serve} from './server.mts';
import type {RecordStage} from './tokens.mts';
process.umask(0o077);
let record: RecordStage | undefined;
try {
  if (process.argv.length !== 3) throw Error('One local configuration file required');
  const config = object(JSON.parse(readFileSync(process.argv[2]!,'utf8')));
  const repository = repositoryName(config.repository);
  record = receipt(text(config.receipt));
  const log = record;
  const repo = object(await gh(`repos/${repository}`));
  const registration = new Registration(repository,id(object(repo.owner).id),id(repo.id),record);
  record('starting',{repository});
  await registration.preflight();
  let server: Awaited<ReturnType<typeof serve>>;
  server = await serve(registration,(state,status) => {
    if (state === 'stopped') {log('stopped',{httpStatus:status ?? null});process.exitCode=1;}
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
