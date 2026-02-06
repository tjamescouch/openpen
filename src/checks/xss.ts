/**
 * Cross-Site Scripting Check (A03:2021 - Injection)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest, Semaphore, RateLimiter } from '../utils/http.js';
import { XSS_PAYLOADS } from '../fuzzer/payloads.js';

export class XssCheck extends BaseCheck {
  id = 'xss';
  name = 'Cross-Site Scripting';
  description = 'Test for reflected XSS vulnerabilities';
  owaspCategory = 'A03:2021 Injection';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;
    const sem = new Semaphore(config.concurrency);
    const rl = new RateLimiter(config.rateLimit);

    const payloads = config.depth === 'shallow'
      ? XSS_PAYLOADS.slice(0, 4)
      : config.depth === 'deep'
        ? XSS_PAYLOADS
        : XSS_PAYLOADS.slice(0, 8);

    const tasks: Promise<void>[] = [];

    for (const ep of target.endpoints) {
      if (ep.method !== 'GET') continue; // reflected XSS mainly via GET
      const url = target.baseUrl + ep.path;

      const params = ep.parameters.filter(p => p.in === 'query');
      // Also test a generic param if none defined
      const testParams = params.length > 0 ? params.map(p => p.name) : ['q', 'search', 'input'];

      for (const paramName of testParams) {
        for (const payload of payloads) {
          tasks.push((async () => {
            await sem.acquire();
            try {
              await rl.wait();
              const testUrl = `${url}?${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}`;
              const res = await sendRequest({
                url: testUrl,
                method: 'GET',
                headers: target.globalHeaders,
                timeout: config.timeout,
              });
              requestCount++;

              // Check if payload is reflected unescaped
              if (res.response.bodySnippet.includes(payload)) {
                const contentType = res.response.headers['content-type'] || '';
                const isHtml = contentType.includes('html');

                findings.push({
                  id: `xss-${paramName}-${findings.length}`,
                  checkId: this.id,
                  checkName: this.name,
                  severity: isHtml ? 'high' : 'medium',
                  endpoint: url,
                  method: 'GET',
                  parameter: paramName,
                  payload,
                  evidence: `Payload reflected in response${isHtml ? ' (HTML context)' : ''}`,
                  description: `Parameter "${paramName}" reflects input without escaping. ${isHtml ? 'Response is HTML, making XSS likely exploitable.' : 'Response is not HTML but input is reflected.'}`,
                  remediation: 'Escape all user input before rendering. Use Content-Type headers correctly. Implement CSP.',
                  owaspCategory: this.owaspCategory,
                  request: res.request,
                  response: res.response,
                });
              }
            } catch {
              // skip
            } finally {
              sem.release();
            }
          })());
        }
      }
    }

    await Promise.all(tasks);
    return { findings, requestCount };
  }
}
