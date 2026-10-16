import { openSync, closeSync, writeFileSync, readFileSync, unlinkSync, mkdirSync, rmdirSync, lstatSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

/** Exclusive PID lease. Recovery is itself serialized; age alone never proves abandonment. */
export function acquireScanLease(path) {
  mkdirSync(dirname(path),{recursive:true,mode:0o700});
  const token=JSON.stringify({pid:process.pid,nonce:randomUUID()});
  try {
    const gate=path+'.recover';
    mkdirSync(gate,{mode:0o700});
    try {
      try {
        if(lstatSync(path).isSymbolicLink())throw Error('Unsafe lease');
        const original=readFileSync(path,'utf8'),{pid}=JSON.parse(original);
        if(Number.isInteger(pid)&&pid>0) {
          try {process.kill(pid,0);} catch(error) {if(error.code==='ESRCH'&&readFileSync(path,'utf8')===original)unlinkSync(path);}
        }
      } catch(error) {if(error.code!=='ENOENT')throw error;}
      const fd=openSync(path,'wx',0o600);try{writeFileSync(fd,token);}finally{closeSync(fd);}
    } finally {rmdirSync(gate);}
  } catch {throw Error('Another scan owns this lease, or its owner cannot be verified.');}
  return ()=>{try{if(readFileSync(path,'utf8')===token)unlinkSync(path);}catch{/* preserve uncertain ownership */}};
}
