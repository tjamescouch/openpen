/**
 * Sensitive Data Exposure Check (A02:2021 - Cryptographic Failures)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest } from '../utils/http.js';

const SENSITIVE_PATTERNS: { name: string; pattern: RegExp; severity: 'high' | 'medium' | 'low' }[] = [
  { name: 'email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'low' },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: 'high' },
  { name: 'api_key', pattern: /(?:api[_-]?key|apikey|api_secret)['":\s]*['"]?([a-zA-Z0-9]{20,})/gi, severity: 'high' },
  { name: 'aws_key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'high' },
  { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, severity: 'high' },
  { name: 'password_field', pattern: /"password"\s*:\s*"[^"]+"/gi, severity: 'high' },
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'high' },
  { name: 'credit_card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, severity: 'high' },
  { name: 'internal_ip', pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, severity: 'medium' },
  { name: 'stack_trace', pattern: /(?:at\s+[\w.$]+\s*\(.*:\d+:\d+\)|Traceback \(most recent|Exception in thread)/g, severity: 'medium' },
  { name: 'debug_info', pattern: /(?:DEBUG|TRACE|stack_trace|backtrace).*[:=]/gi, severity: 'low' },
];

const COMMON_LEAK_PATHS = [
  '/.env',
  '/config.json',
  '/config.yaml',
  '/.git/config',
  '/debug',
  '/actuator/env',
  '/api/debug',
  '/graphql',
  '/__debug__',
  '/server-status',
  '/phpinfo.php',
  '/swagger.json',
  '/api-docs',
  '/.well-known/security.txt',
];

export class SensitiveDataCheck extends BaseCheck {
  id = 'sensitive-data';
  name = 'Sensitive Data Exposure';
  description = 'Check for leaked secrets, PII, and debug information in responses';
  owaspCategory = 'A02:2021 Crypto Failures';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;

    // Check endpoint responses for sensitive data
    for (const ep of target.endpoints) {
      const url = target.baseUrl + ep.path;

      try {
        const res = await sendRequest({
          url,
          method: ep.method,
          headers: target.globalHeaders,
          timeout: config.timeout,
        });
        requestCount++;

        for (const sp of SENSITIVE_PATTERNS) {
          const matches = res.response.bodySnippet.match(sp.pattern);
          if (matches && matches.length > 0) {
            // Don't flag emails in obvious contexts (like user profile endpoints)
            if (sp.name === 'email' && matches.length < 3) continue;

            findings.push({
              id: `sensitive-${sp.name}-${ep.method}-${ep.path}`,
              checkId: this.id,
              checkName: this.name,
              severity: sp.severity,
              endpoint: url,
              method: ep.method,
              evidence: `Found ${matches.length} ${sp.name} pattern(s): ${matches[0].slice(0, 50)}...`,
              description: `Response from ${ep.method} ${ep.path} contains ${sp.name} data that may be sensitive.`,
              remediation: 'Review response content. Mask or remove sensitive data. Use proper access controls.',
              owaspCategory: this.owaspCategory,
              request: res.request,
              response: res.response,
            });
          }
        }
      } catch {
        // skip
      }
    }

    // Probe common leak paths
    const leakPaths = config.depth === 'shallow'
      ? COMMON_LEAK_PATHS.slice(0, 5)
      : COMMON_LEAK_PATHS;

    for (const path of leakPaths) {
      const url = target.baseUrl + path;
      try {
        const res = await sendRequest({
          url,
          method: 'GET',
          headers: target.globalHeaders,
          timeout: config.timeout,
        });
        requestCount++;

        if (res.response.statusCode === 200 && res.response.bodySnippet.length > 10) {
          let severity: 'high' | 'medium' | 'low' = 'medium';
          if (path.includes('.env') || path.includes('.git') || path.includes('config')) {
            severity = 'high';
          }

          findings.push({
            id: `sensitive-leak-path-${path}`,
            checkId: this.id,
            checkName: this.name,
            severity,
            endpoint: url,
            method: 'GET',
            evidence: `Path ${path} returned 200 with ${res.response.bodySnippet.length} bytes`,
            description: `Sensitive path ${path} is accessible and returns content. This may expose configuration, debug info, or secrets.`,
            remediation: `Block access to ${path}. Ensure sensitive files are not served by the web server.`,
            owaspCategory: this.owaspCategory,
            request: res.request,
            response: res.response,
          });
        }
      } catch {
        // skip
      }
    }

    return { findings, requestCount };
  }
}
