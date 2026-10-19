import {openSync,appendFileSync,fsyncSync,lstatSync,constants} from 'node:fs';
import {dirname} from 'node:path';
import type {Json} from './model.mts';
export function receipt(path: string): (stage: string,details?: Json) => void {
  const parent = lstatSync(dirname(path));
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid?.()
    || (parent.mode & 0o077)) throw Error('Existing private receipt directory required');
  const fd = openSync(path,constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW|constants.O_WRONLY,0o600);
  return (stage,details={}) => {
    appendFileSync(fd,JSON.stringify({time:new Date().toISOString(),stage,...details})+'\n');
    fsyncSync(fd);
  };
}
