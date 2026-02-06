/**
 * Verbosity-aware logger
 */

let verboseMode = false;

export function setVerbose(v: boolean): void {
  verboseMode = v;
}

export function info(msg: string): void {
  console.log(msg);
}

export function verbose(msg: string): void {
  if (verboseMode) console.log(msg);
}

export function warn(msg: string): void {
  console.error(`[!] ${msg}`);
}

export function error(msg: string): void {
  console.error(`[ERROR] ${msg}`);
}
