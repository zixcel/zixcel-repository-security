import test from 'node:test';
import assert from 'node:assert/strict';
import {serve} from './server.mts';
test('loopback manifest callback rejects CSRF, malformed codes and replay',async()=>{
  const calls:string[]=[];
  const s=await serve({owner:'example',slug:'example-dependency-merge',repository:'example/project',
    registered:async code=>{assert.equal(code,'a'.repeat(40));calls.push('registered');},
    installed:async id=>{assert.equal(id,42);calls.push('installed');}},state=>calls.push(state));
  try{
    const page=await fetch(s.url);assert.equal(page.headers.get('cache-control'),'no-store');
    const html=await page.text(),state=html.match(/new\?state=([a-f0-9]{64})/)?.[1];assert.ok(state);
    const callback=s.url.replace('/setup/','/registered/');
    for(const bad of ['', '0'.repeat(64),'ø'.repeat(64)])
      assert.equal((await fetch(callback+`?code=${'a'.repeat(40)}&state=${encodeURIComponent(bad)}`)).status,403);
    assert.equal((await fetch(callback+`?code=bad&state=${state}`)).status,403);assert.deepEqual(calls,[]);
    const valid=callback+`?code=${'a'.repeat(40)}&state=${state}`;
    assert.equal((await fetch(valid)).status,200);
    assert.equal((await fetch(valid)).status,403);
    assert.equal((await fetch(s.url.replace('/setup/','/installed/')+'?installation_id=42')).status,200);
    assert.deepEqual(calls,['registered','installed','complete']);
    assert.equal((await fetch(s.url.replace('/setup/','/installed/')+'?installation_id=42')).status,403);
  }finally{s.close();}
});
test('never expose conversion errors or credentials to the browser',async()=>{
  const states:string[]=[];const s=await serve({owner:'example',slug:'example-dependency-merge',repository:'example/project',
    registered:async()=>{throw Error('SYNTHETIC_PRIVATE_KEY');},installed:async()=>{}},x=>states.push(x));
  try{
    const page=await(await fetch(s.url)).text(),state=page.match(/new\?state=([a-f0-9]{64})/)?.[1];
    const res=await fetch(s.url.replace('/setup/','/registered/')+`?code=${'a'.repeat(40)}&state=${state}`);
    assert.equal(res.status,500);assert.doesNotMatch(await res.text(),/SYNTHETIC_PRIVATE_KEY/);
    assert.deepEqual(states,['stopped']);
  }finally{s.close();}
});
