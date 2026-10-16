import { join } from 'node:path';
import { mkdirSync, readFileSync, writeFileSync, renameSync, openSync, closeSync, fsyncSync, fstatSync, lstatSync, unlinkSync, constants } from 'node:fs';
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
      if(lstatSync(directory).isSymbolicLink())throw Error('Unsafe request pacing directory');
      let release;
      const deadline=now()+90000;
      while(!release) {
        try {release=acquireScanLease(path+'.lock');}
        catch {if(now()>=deadline)throw Error('Request pacing lease is busy; no request sent.');await wait(100);}
      }
      try {
        let next=0;
        try {
          if(lstatSync(path).isSymbolicLink())throw Error('Unsafe request pacing file');
          const input=openSync(path,constants.O_RDONLY|(constants.O_NOFOLLOW||0)|(constants.O_NONBLOCK||0));
          try {
            const stat=fstatSync(input);
            if(!stat.isFile()||stat.size>4096||(process.platform!=='win32'&&(stat.mode&0o077)))throw Error('Unsafe request pacing file');
            const state=JSON.parse(readFileSync(input,'utf8'));next=state.next;
          } finally {closeSync(input);}
          if(!Number.isFinite(next)||next<0||next>now()+90000)throw Error('Invalid request pacing state');
        } catch(error) {if(error.code!=='ENOENT')throw error;}
        if(next>now())await wait(next-now());
        function persistReservation() {
          const temporary=path+'.'+randomUUID()+'.tmp';
          try {
            const output=openSync(temporary,'wx',0o600);
            try {writeFileSync(output,JSON.stringify({next:now()+interval}));fsyncSync(output);}finally{closeSync(output);}
            renameSync(temporary,path);
            if(process.platform!=='win32') {
              const parent=openSync(directory,constants.O_RDONLY);
              try {fsyncSync(parent);}catch(error){if(!['EINVAL','ENOTSUP'].includes(error.code))throw error;}finally{closeSync(parent);}
            }
          } finally {try{unlinkSync(temporary);}catch{/* renamed or never created */}}
        }
        persistReservation();
        // Completion-based spacing includes any delay writing the first reservation.
        try {return await request();}finally{persistReservation();}
      } finally {release();}
    });
    tail=pending.catch(()=>{});return pending;
  };
}
