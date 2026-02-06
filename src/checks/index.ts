/**
 * Check registry - all available security check modules
 */

import type { BaseCheck, CheckInfo } from './base.js';
import { SecurityHeadersCheck } from './security-headers.js';
import { SqlInjectionCheck } from './sqli.js';
import { XssCheck } from './xss.js';
import { AuthBypassCheck } from './auth-bypass.js';
import { BrokenAccessControlCheck } from './bac.js';
import { SsrfCheck } from './ssrf.js';
import { SensitiveDataCheck } from './sensitive-data.js';
import { MassAssignmentCheck } from './mass-assignment.js';

const ALL_CHECKS: BaseCheck[] = [
  new SecurityHeadersCheck(),
  new SqlInjectionCheck(),
  new XssCheck(),
  new AuthBypassCheck(),
  new BrokenAccessControlCheck(),
  new SsrfCheck(),
  new SensitiveDataCheck(),
  new MassAssignmentCheck(),
];

export function getAllChecks(): BaseCheck[] {
  return ALL_CHECKS;
}

export function getChecksByIds(ids: string[]): BaseCheck[] {
  const idSet = new Set(ids);
  const found = ALL_CHECKS.filter(c => idSet.has(c.id));
  if (found.length !== ids.length) {
    const missing = ids.filter(id => !ALL_CHECKS.some(c => c.id === id));
    throw new Error(`Unknown check(s): ${missing.join(', ')}`);
  }
  return found;
}

export function listChecks(): CheckInfo[] {
  return ALL_CHECKS.map(c => c.info);
}
