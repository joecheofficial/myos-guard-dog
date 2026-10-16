import { join } from 'node:path';
import { mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { guardogDataDir } from './paths.js';
import { cacheDigest } from './scan-cache.js';
import { acquireScanLease } from './scan-lease.js';

/** Hold one key's lease through the request so delayed processes cannot burst together. */
export function createRequestPacer(identity,{directory=join(guardogDataDir(),'request-pacing'),now=Date.now,wait=ms=>new Promise(r=>setTimeout(r,ms))}={}) {
  const path=join(directory,cacheDigest(identity)+'.json');
  let tail=Promise.resolve();
  return (interval,request)=>{
    const pending=tail.then(async()=>{
      mkdirSync(directory,{recursive:true,mode:0o700});
      let release;
      const deadline=now()+90000;
      while(!release) {
        try {release=acquireScanLease(path+'.lock');}
        catch {if(now()>=deadline)throw Error('Request pacing lease is busy; no request sent.');await wait(100);}
      }
      try {
        let next=0;
        try {
          const state=JSON.parse(readFileSync(path,'utf8')); next=state.next;
          if(!Number.isFinite(next)||next<0||next>now()+90000)throw Error('Invalid request pacing state');
        } catch(error) {if(error.code!=='ENOENT')throw error;}
        if(next>now())await wait(next-now());
        const temporary=path+'.'+randomUUID()+'.tmp';
        writeFileSync(temporary,JSON.stringify({next:now()+interval}),{mode:0o600,flag:'wx'});renameSync(temporary,path);
        return await request();
      } finally {release();}
    });
    tail=pending.catch(()=>{});return pending;
  };
}
