import {createServer,type IncomingMessage,type ServerResponse} from 'node:http';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {manifest} from './model.mts';
import {HttpFailure} from './github.mts';
export interface Session {
  owner: string;
  slug: string;
  repository: string;
  repositories?: readonly string[];
  registered(code: string): Promise<void>;
  installed(id: number): Promise<void>;
}
const escape = (x: string): string => x.replaceAll('&','&amp;').replaceAll('"','&quot;')
  .replaceAll('<','&lt;').replaceAll('>','&gt;');
export async function serve(session: Session,onFinish: (state:'complete'|'stopped',status?:number) => void): Promise<{url:string,close:()=>void}> {
  const nonce = randomBytes(24).toString('hex'), state = randomBytes(32).toString('hex');
  let phase: 'register'|'converting'|'install'|'binding'|'done'|'stopped' = 'register';
  let origin = '';
  const html = (res: ServerResponse,body: string,status=200): void => {
    res.writeHead(status,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store',
      'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',
      'Content-Security-Policy':"default-src 'none'; form-action https://github.com; frame-ancestors 'none'; base-uri 'none'"});
    res.end(`<!doctype html><html lang="en"><title>Dependency App setup</title><body>${body}</body></html>`);
  };
  const handler = async (req: IncomingMessage,res: ServerResponse): Promise<void> => {
    if (req.method !== 'GET' || `http://${req.headers.host}` !== origin)
      return html(res,'Request rejected',403);
    const url = new URL(req.url ?? '/',origin);
    const installationPage = (): void => html(res,
      `<h1>App verified</h1><p>Select exactly these repositories on GitHub: ${escape((session.repositories ?? [session.repository]).join(', '))}.</p>`+
      `<a href="https://github.com/apps/${session.slug}/installations/new">Install the private App</a>`);
    if (url.pathname === `/setup/${nonce}`) {
      if (phase === 'install') return installationPage();
      if (phase !== 'register') return html(res,`Setup phase: ${phase}`);
      const data = manifest(session.owner,`${origin}/registered/${nonce}`);
      return html(res,`<h1>Register a private dependency App</h1><p>Owner: ${escape(session.owner)}. `+
        `Keep the name ${escape(session.slug)} and select exactly ${escape((session.repositories ?? [session.repository]).join(', '))}. `+
        `No webhooks. Only the reviewed repository permissions. After registration, select only the reviewed repositories.</p>`+
        `<form method="post" action="https://github.com/organizations/${session.owner}/settings/apps/new?state=${state}">`+
        `<input type="hidden" name="manifest" value="${escape(JSON.stringify(data))}">`+
        '<button type="submit">Register on GitHub</button></form>');
    }
    if (url.pathname === `/registered/${nonce}`) {
      const received = url.searchParams.get('state') ?? '';
      const code = url.searchParams.get('code') ?? '';
      if (phase !== 'register' || !/^[a-f0-9]{64}$/.test(received) || !/^[A-Za-z0-9_-]{20,128}$/.test(code)
        || !timingSafeEqual(Buffer.from(received),Buffer.from(state))) return html(res,'State rejected',403);
      phase = 'converting';
      await session.registered(code);
      phase = 'install';
      return installationPage();
    }
    if (url.pathname === `/installed/${nonce}`) {
      const installation = url.searchParams.get('installation_id') ?? '';
      if (phase !== 'install' || !/^[1-9]\d{0,15}$/.test(installation)
        || !Number.isSafeInteger(Number(installation))) return html(res,'Installation rejected',403);
      phase = 'binding';
      await session.installed(Number(installation));
      phase = 'done';
      html(res,'<h1>Setup complete</h1><p>Environment credential registered. Activation and rules are unchanged.</p>');
      onFinish('complete');
      return;
    }
    html(res,'Not found',404);
  };
  const server = createServer((req,res) => {void handler(req,res).catch(error => {
    phase = 'stopped';html(res,'Setup stopped. Inspect the private receipt; do not replay writes.',500);
    onFinish('stopped',error instanceof HttpFailure ? error.status : undefined);
  });});
  await new Promise<void>((resolve,reject) => {server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const address = server.address();
  if (!address || typeof address === 'string') throw Error('No loopback port');
  origin = `http://127.0.0.1:${address.port}`;
  const timer = setTimeout(() => {server.close();onFinish('stopped');},55*60*1000);
  return {url:`${origin}/setup/${nonce}`,close:()=>{clearTimeout(timer);server.close();}};
}
