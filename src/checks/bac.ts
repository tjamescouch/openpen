/**
 * Broken Access Control / IDOR Check (A01:2021)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest } from '../utils/http.js';

const IDOR_TEST_IDS = ['1', '2', '0', '999999', '-1', 'admin', 'test'];

export class BrokenAccessControlCheck extends BaseCheck {
  id = 'bac';
  name = 'Broken Access Control';
  description = 'Test for IDOR and horizontal privilege escalation';
  owaspCategory = 'A01:2021 Access Control';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;

    // Find endpoints with path parameters that look like IDs
    const idEndpoints = target.endpoints.filter(ep =>
      ep.path.includes('{') ||
      ep.parameters.some(p => p.in === 'path' && /id|user|account|profile/i.test(p.name))
    );

    const testIds = config.depth === 'shallow' ? IDOR_TEST_IDS.slice(0, 3) : IDOR_TEST_IDS;

    for (const ep of idEndpoints) {
      // Replace path params with test IDs
      const pathParams = ep.parameters.filter(p => p.in === 'path');
      if (pathParams.length === 0 && ep.path.includes('{')) {
        // Extract param names from path template
        const matches = ep.path.match(/\{(\w+)\}/g) || [];
        for (const m of matches) {
          pathParams.push({
            name: m.slice(1, -1),
            in: 'path',
            type: 'string',
            required: true,
          });
        }
      }

      for (const param of pathParams) {
        const successfulIds: string[] = [];

        for (const testId of testIds) {
          const path = ep.path.replace(`{${param.name}}`, testId);
          const url = target.baseUrl + path;

          try {
            const res = await sendRequest({
              url,
              method: ep.method,
              headers: target.globalHeaders,
              timeout: config.timeout,
            });
            requestCount++;

            if (res.response.statusCode >= 200 && res.response.statusCode < 300) {
              successfulIds.push(testId);
            }
          } catch {
            // skip
          }
        }

        // If multiple different IDs succeed, possible IDOR
        if (successfulIds.length > 1) {
          findings.push({
            id: `bac-idor-${ep.method}-${ep.path}-${param.name}`,
            checkId: this.id,
            checkName: this.name,
            severity: 'high',
            endpoint: target.baseUrl + ep.path,
            method: ep.method,
            parameter: param.name,
            evidence: `Multiple IDs returned 2xx: ${successfulIds.join(', ')}`,
            description: `Endpoint ${ep.method} ${ep.path} returns successful responses for multiple ID values in "${param.name}". This may indicate missing authorization checks (IDOR).`,
            remediation: 'Implement proper authorization checks. Verify the authenticated user has access to the requested resource.',
            owaspCategory: this.owaspCategory,
          });
        }
      }
    }

    // Test HTTP method override
    for (const ep of target.endpoints.filter(e => e.method === 'GET').slice(0, 5)) {
      const url = target.baseUrl + ep.path;
      try {
        const res = await sendRequest({
          url,
          method: 'DELETE',
          headers: target.globalHeaders,
          timeout: config.timeout,
        });
        requestCount++;

        if (res.response.statusCode < 400 && res.response.statusCode !== 405) {
          findings.push({
            id: `bac-method-${ep.path}`,
            checkId: this.id,
            checkName: this.name,
            severity: 'medium',
            endpoint: url,
            method: 'DELETE',
            evidence: `DELETE method returned ${res.response.statusCode} on GET-only endpoint`,
            description: `Endpoint ${ep.path} accepts DELETE requests that should only allow GET.`,
            remediation: 'Restrict HTTP methods to only those that are intended. Return 405 Method Not Allowed for others.',
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
