/**
 * Base check abstract class
 */

import type { ScanTarget, ScanConfig, Finding } from '../types.js';

export interface CheckResult {
  findings: Finding[];
  requestCount: number;
}

export interface CheckInfo {
  id: string;
  name: string;
  description: string;
  owaspCategory: string;
}

export abstract class BaseCheck {
  abstract id: string;
  abstract name: string;
  abstract description: string;
  abstract owaspCategory: string;

  abstract run(target: ScanTarget, config: ScanConfig): Promise<CheckResult>;

  get info(): CheckInfo {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      owaspCategory: this.owaspCategory,
    };
  }
}
