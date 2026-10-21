import { createHash, createHmac, randomBytes, timingSafeEqual, randomUUID } from 'node:crypto';
import { mkdirSync, lstatSync, openSync, fstatSync, readFileSync, closeSync, writeFileSync, renameSync, unlinkSync, readdirSync, constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { guardogDataDir, packageRoot } from './paths.js';

const VERSION = JSON.parse(readFileSync(join(packageRoot(), 'package.json'), 'utf8')).version;
const MAX_BYTES = 256 * 1024;
export const cacheDigest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

/** Evidence only, never a complete repository/package verdict. No project files are stored. */
export class EvidenceCache {
  constructor({ directory = join(guardogDataDir(), 'evidence-cache'), namespace, now = Date.now } = {}) {
    this.directory = resolve(directory); this.namespace = namespace; this.now = now;
    this.stats = { hits: 0, misses: 0, writes: 0, errors: 0 };
  }
  shard(key) {
    const hash = cacheDigest([VERSION, this.namespace, key]);
    const directory = join(this.directory, hash.slice(0, 2));
    // State root and shard must be real directories; OS aliases such as /var are allowed.
    try { if (lstatSync(this.directory).isSymbolicLink()) throw Error('Unsafe cache directory'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (process.platform !== 'win32' && (stat.mode & 0o022))) throw Error('Unsafe cache directory');
    return { directory, path: join(directory, hash + '.json'), identity: hash };
  }
  signingKey() {
    if(this.key)return this.key;
    const path=join(this.directory,'.integrity-key');
    try {writeFileSync(path,randomBytes(32),{mode:0o600,flag:'wx'});}catch(error){if(error.code!=='EEXIST')throw error;}
    const fd=openSync(path,constants.O_RDONLY|(constants.O_NOFOLLOW||0)|(constants.O_NONBLOCK||0));
    try {
      const stat=fstatSync(fd);
      if(!stat.isFile()||stat.size!==32||(process.platform!=='win32'&&(stat.mode&0o077)))throw Error('Unsafe cache integrity key');
      this.key=readFileSync(fd);return this.key;
    } finally {closeSync(fd);}
  }
  signature(entry) {return createHmac('sha256',this.signingKey()).update(JSON.stringify(entry)).digest('hex');}
  get(key, maxAgeMs) {
    let fd;
    try {
      const {path, identity} = this.shard(key);
      fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > MAX_BYTES || (process.platform !== 'win32' && (stat.mode & 0o077))) throw Error('Invalid cache file');
      const {mac,...entry} = JSON.parse(readFileSync(fd, 'utf8'));
      if(typeof mac!=='string'||!/^[a-f0-9]{64}$/.test(mac)||!timingSafeEqual(Buffer.from(mac,'hex'),Buffer.from(this.signature(entry),'hex')))throw Error('Cache integrity mismatch');
      const now = this.now();
      if (entry.schema !== 1 || entry.identity !== identity || !Number.isFinite(entry.createdAt) || !Number.isFinite(entry.expiresAt)
          || entry.createdAt > now || entry.expiresAt <= now || now - entry.createdAt >= maxAgeMs || entry.expiresAt - entry.createdAt > maxAgeMs) throw Error('Expired or invalid evidence');
      this.stats.hits++; return entry.value;
    } catch { this.stats.misses++; return null; }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  set(key, value, ttlMs) {
    let temporary;
    try {
      if (!Number.isFinite(ttlMs) || ttlMs <= 0) return false;
      const {directory, path, identity} = this.shard(key);
      const createdAt = this.now();
      const entry={schema: 1, identity, createdAt, expiresAt: createdAt + ttlMs, value};
      const data=JSON.stringify({...entry,mac:this.signature(entry)});
      if (Buffer.byteLength(data) > MAX_BYTES) return false;
      // 256 shards x 32 entries: bounded storage and bounded eviction work.
      const entries = readdirSync(directory).filter(name => /^[a-f0-9]{64}\.json$/.test(name));
      if (entries.length >= 32 && !entries.includes(identity + '.json')) {
        const oldest = entries.map(name => ({name, mtime: lstatSync(join(directory,name)).mtimeMs})).sort((a,b)=>a.mtime-b.mtime)[0];
        if (oldest) unlinkSync(join(directory,oldest.name));
      }
      temporary = path + '.' + randomUUID() + '.tmp';
      writeFileSync(temporary, data, {mode: 0o600, flag:'wx'}); renameSync(temporary,path);
      this.stats.writes++; return true;
    } catch { this.stats.errors++; return false; }
    finally { if (temporary) {try {unlinkSync(temporary);} catch { /* already renamed */ }} }
  }
}
