import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,statSync,chmodSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {receipt} from './receipt.mts';
test('private receipts are exclusive, bounded metadata records',()=>{
  const d=mkdtempSync(join(tmpdir(),'app-receipt-'));
  try{const p=join(d,'receipt.jsonl'),record=receipt(p);record('starting',{repository:'example/project'});
    assert.equal(statSync(p).mode&0o777,0o600);assert.equal(JSON.parse(readFileSync(p,'utf8')).stage,'starting');
    assert.throws(()=>receipt(p));
    symlinkSync(p,join(d,'alias'));assert.throws(()=>receipt(join(d,'alias')));
    chmodSync(d,0o755);assert.throws(()=>receipt(join(d,'other')));
  }finally{rmSync(d,{recursive:true});}
});
