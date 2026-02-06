/**
 * Server-Side Request Forgery Check (A10:2021)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest, Semaphore, RateLimiter } from '../utils/http.js';
import { SSRF_PAYLOADS } from '../fuzzer/payloads.js';

const SSRF_INDICATORS = [
  /root:.*:0:0/i,        // /etc/passwd content
  /ami-id/i,             // AWS metadata
  /instance-id/i,        // Cloud metadata
  /compute\.internal/i,  // GCP metadata
  /\b10\.\d+\.\d+\.\d+/,// Internal IP leaked
  /\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/, // Internal IP
  /\b192\.168\.\d+\.\d+/,// Internal IP
];

export class SsrfCheck extends BaseCheck {
  id = 'ssrf';
  name = 'Server-Side Request Forgery';
  description = 'Test for SSRF vulnerabilities in URL parameters';
  owaspCategory = 'A10:2021 SSRF';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;
    const sem = new Semaphore(config.concurrency);
    const rl = new RateLimiter(config.rateLimit);

    const payloads = config.depth === 'shallow'
      ? SSRF_PAYLOADS.slice(0, 4)
      : config.depth === 'deep'
        ? SSRF_PAYLOADS
        : SSRF_PAYLOADS.slice(0, 8);

    // Find parameters that look like URLs
    const urlParamNames = ['url', 'uri', 'href', 'link', 'redirect', 'callback', 'next', 'return', 'dest', 'target', 'path', 'file', 'page', 'fetch', 'load'];

    const tasks: Promise<void>[] = [];

    for (const ep of target.endpoints) {
      const url = target.baseUrl + ep.path;

      const queryParams = ep.parameters.filter(p => p.in === 'query');
      // Test named URL-like params, or common param names if none defined
      const testParams = queryParams.length > 0
        ? queryParams.filter(p => urlParamNames.some(n => p.name.toLowerCase().includes(n)))
        : urlParamNames.slice(0, 3).map(n => ({ name: n }));

      for (const param of testParams) {
        for (const payload of payloads) {
          tasks.push((async () => {
            await sem.acquire();
            try {
              await rl.wait();
              const testUrl = `${url}?${encodeURIComponent(param.name)}=${encodeURIComponent(payload)}`;
              const res = await sendRequest({
                url: testUrl,
                method: ep.method,
                headers: target.globalHeaders,
                timeout: config.timeout,
              });
              requestCount++;

              // Check for SSRF indicators in response
              for (const indicator of SSRF_INDICATORS) {
                if (indicator.test(res.response.bodySnippet)) {
                  findings.push({
                    id: `ssrf-${param.name}-${findings.length}`,
                    checkId: this.id,
                    checkName: this.name,
                    severity: 'critical',
                    endpoint: url,
                    method: ep.method,
                    parameter: param.name,
                    payload,
                    evidence: `SSRF indicator in response: ${res.response.bodySnippet.slice(0, 200)}`,
                    description: `Parameter "${param.name}" may be vulnerable to SSRF. The server appears to fetch attacker-controlled URLs.`,
                    remediation: 'Validate and sanitize all URL inputs. Use allowlists for permitted domains. Block requests to internal/metadata IPs.',
                    owaspCategory: this.owaspCategory,
                    request: res.request,
                    response: res.response,
                  });
                  break;
                }
              }

              // Check for different behavior with internal URLs
              if (res.response.statusCode === 200 && payload.includes('127.0.0.1')) {
                // Compare with a non-internal URL
                const extUrl = `${url}?${encodeURIComponent(param.name)}=${encodeURIComponent('http://example.com')}`;
                try {
                  const extRes = await sendRequest({
                    url: extUrl,
                    method: ep.method,
                    headers: target.globalHeaders,
                    timeout: config.timeout,
                  });
                  requestCount++;

                  if (res.response.bodySnippet !== extRes.response.bodySnippet) {
                    findings.push({
                      id: `ssrf-diff-${param.name}-${findings.length}`,
                      checkId: this.id,
                      checkName: this.name,
                      severity: 'high',
                      endpoint: url,
                      method: ep.method,
                      parameter: param.name,
                      payload,
                      evidence: `Different responses for internal (${payload}) vs external URL`,
                      description: `Parameter "${param.name}" produces different responses for internal vs external URLs, suggesting server-side URL fetching.`,
                      remediation: 'Block requests to internal IPs and cloud metadata endpoints. Use URL allowlists.',
                      owaspCategory: this.owaspCategory,
                      request: res.request,
                      response: res.response,
                    });
                  }
                } catch {
                  // skip comparison
                }
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
