/**
 * Security Headers Check (A05:2021 - Security Misconfiguration)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest } from '../utils/http.js';

const REQUIRED_HEADERS: { name: string; severity: 'medium' | 'low' | 'info'; desc: string; remediation: string }[] = [
  {
    name: 'strict-transport-security',
    severity: 'medium',
    desc: 'Missing HSTS header. Browser will allow HTTP connections.',
    remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
  },
  {
    name: 'x-content-type-options',
    severity: 'low',
    desc: 'Missing X-Content-Type-Options. Browser may MIME-sniff responses.',
    remediation: 'Add X-Content-Type-Options: nosniff',
  },
  {
    name: 'x-frame-options',
    severity: 'medium',
    desc: 'Missing X-Frame-Options. Page may be framed (clickjacking).',
    remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN',
  },
  {
    name: 'content-security-policy',
    severity: 'medium',
    desc: 'Missing Content-Security-Policy. No CSP protection against XSS.',
    remediation: "Add Content-Security-Policy with restrictive directives",
  },
  {
    name: 'x-xss-protection',
    severity: 'info',
    desc: 'Missing X-XSS-Protection header.',
    remediation: 'Add X-XSS-Protection: 0 (or rely on CSP)',
  },
  {
    name: 'referrer-policy',
    severity: 'low',
    desc: 'Missing Referrer-Policy. Full URL may leak in Referer header.',
    remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin',
  },
];

const DANGEROUS_HEADERS = [
  { name: 'server', pattern: /./i, desc: 'Server header reveals technology stack' },
  { name: 'x-powered-by', pattern: /./i, desc: 'X-Powered-By reveals framework/language' },
  { name: 'x-aspnet-version', pattern: /./i, desc: 'ASP.NET version exposed' },
  { name: 'x-aspnetmvc-version', pattern: /./i, desc: 'ASP.NET MVC version exposed' },
];

export class SecurityHeadersCheck extends BaseCheck {
  id = 'security-headers';
  name = 'Security Headers';
  description = 'Check for missing or misconfigured security headers';
  owaspCategory = 'A05:2021 Misconfiguration';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;

    // Test the base URL and first few endpoints
    const urlsToTest = [
      target.baseUrl,
      ...target.endpoints.slice(0, 3).map(ep => target.baseUrl + ep.path),
    ];
    const tested = new Set<string>();

    for (const url of urlsToTest) {
      if (tested.has(url)) continue;
      tested.add(url);

      try {
        const res = await sendRequest({
          url,
          method: 'GET',
          headers: target.globalHeaders,
          timeout: config.timeout,
        });
        requestCount++;

        // Check missing headers
        for (const header of REQUIRED_HEADERS) {
          if (!res.response.headers[header.name]) {
            findings.push({
              id: `${this.id}-missing-${header.name}`,
              checkId: this.id,
              checkName: this.name,
              severity: header.severity,
              endpoint: url,
              method: 'GET',
              evidence: `Header "${header.name}" not present in response`,
              description: header.desc,
              remediation: header.remediation,
              owaspCategory: this.owaspCategory,
              request: res.request,
              response: res.response,
            });
          }
        }

        // Check information leakage headers
        for (const dh of DANGEROUS_HEADERS) {
          const val = res.response.headers[dh.name];
          if (val && dh.pattern.test(val)) {
            findings.push({
              id: `${this.id}-info-leak-${dh.name}`,
              checkId: this.id,
              checkName: this.name,
              severity: 'info',
              endpoint: url,
              method: 'GET',
              evidence: `${dh.name}: ${val}`,
              description: dh.desc,
              remediation: `Remove or obfuscate the ${dh.name} header`,
              owaspCategory: this.owaspCategory,
              request: res.request,
              response: res.response,
            });
          }
        }

        // Only need to check headers once (they should be consistent)
        break;
      } catch {
        continue;
      }
    }

    return { findings: dedup(findings), requestCount };
  }
}

function dedup(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}
