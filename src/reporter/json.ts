/**
 * JSON reporter - structured output for CI/CD
 */

import { writeFileSync } from 'fs';
import type { ScanReport } from '../types.js';

export function reportJson(report: ScanReport, outputPath?: string): void {
  const json = JSON.stringify(report, null, 2);

  if (outputPath) {
    writeFileSync(outputPath, json);
    console.log(`\n Report written to ${outputPath}`);
  } else {
    console.log(json);
  }
}
