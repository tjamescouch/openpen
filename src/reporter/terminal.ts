/**
 * Terminal reporter - color-coded output
 */

import type { ScanReport, Finding, Severity } from '../types.js';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '\x1b[31m', // red
  high: '\x1b[91m',     // bright red
  medium: '\x1b[33m',   // yellow
  low: '\x1b[36m',      // cyan
  info: '\x1b[90m',     // gray
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

export function reportTerminal(report: ScanReport, noColor: boolean): void {
  const c = (color: string, text: string) => noColor ? text : `${color}${text}${RESET}`;

  console.log('\n' + c(BOLD, '═══════════════════════════════════════════════════════'));
  console.log(c(BOLD, ' OPENPEN SCAN REPORT'));
  console.log(c(BOLD, '═══════════════════════════════════════════════════════'));

  console.log(`\n Target:    ${report.target}`);
  console.log(` Duration:  ${(report.duration / 1000).toFixed(1)}s`);
  console.log(` Requests:  ${report.totalRequests}`);
  console.log(` Checks:    ${report.checksRun.join(', ')}`);

  // Summary
  console.log('\n' + c(BOLD, ' Summary'));
  console.log(' ───────');
  const { critical, high, medium, low, info } = report.summary;
  console.log(`  ${c(SEVERITY_COLORS.critical, `Critical: ${critical}`)}`);
  console.log(`  ${c(SEVERITY_COLORS.high, `High:     ${high}`)}`);
  console.log(`  ${c(SEVERITY_COLORS.medium, `Medium:   ${medium}`)}`);
  console.log(`  ${c(SEVERITY_COLORS.low, `Low:      ${low}`)}`);
  console.log(`  ${c(SEVERITY_COLORS.info, `Info:     ${info}`)}`);

  const total = critical + high + medium + low + info;
  console.log(`\n  Total: ${total} finding(s)\n`);

  if (total === 0) {
    console.log(c('\x1b[32m', '  No vulnerabilities found.\n'));
    return;
  }

  // Findings grouped by severity
  console.log(c(BOLD, ' Findings'));
  console.log(' ────────');

  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrder) {
    const sevFindings = report.findings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    console.log(`\n ${c(SEVERITY_COLORS[sev], `[${sev.toUpperCase()}]`)}`);

    for (const f of sevFindings) {
      console.log(`\n  ${c(BOLD, f.checkName)} (${f.checkId})`);
      console.log(`  ${f.method} ${f.endpoint}${f.parameter ? ` [${f.parameter}]` : ''}`);
      console.log(`  ${c(DIM, f.description)}`);
      if (f.payload) {
        console.log(`  Payload: ${f.payload.slice(0, 80)}`);
      }
      console.log(`  Evidence: ${f.evidence.slice(0, 120)}`);
      console.log(`  ${c('\x1b[32m', 'Fix: ' + f.remediation)}`);
    }
  }

  console.log('\n' + c(BOLD, '═══════════════════════════════════════════════════════\n'));
}
