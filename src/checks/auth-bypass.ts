/**
 * Authentication Bypass Check (A07:2021 - Identification and Auth Failures)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest } from '../utils/http.js';

export class AuthBypassCheck extends BaseCheck {
  id = 'auth-bypass';
  name = 'Authentication Bypass';
  description = 'Test for endpoints accessible without authentication';
  owaspCategory = 'A07:2021 Auth Failures';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;

    // Only meaningful if auth is configured
    if (!target.auth || Object.keys(target.auth.headers).length === 0) {
      return { findings, requestCount };
    }

    const endpoints = config.depth === 'shallow'
      ? target.endpoints.slice(0, 5)
      : target.endpoints;

    for (const ep of endpoints) {
      const url = target.baseUrl + ep.path;

      try {
        // Request WITHOUT auth
        const noAuth = await sendRequest({
          url,
          method: ep.method,
          headers: {},
          timeout: config.timeout,
        });
        requestCount++;

        // Request WITH auth
        const withAuth = await sendRequest({
          url,
          method: ep.method,
          headers: target.globalHeaders,
          timeout: config.timeout,
        });
        requestCount++;

        // If both succeed with same status, auth might not be enforced
        if (noAuth.response.statusCode === withAuth.response.statusCode &&
            noAuth.response.statusCode < 400) {
          findings.push({
            id: `auth-bypass-${ep.method}-${ep.path}`,
            checkId: this.id,
            checkName: this.name,
            severity: 'high',
            endpoint: url,
            method: ep.method,
            evidence: `Endpoint returns ${noAuth.response.statusCode} both with and without auth credentials`,
            description: `Endpoint ${ep.method} ${ep.path} appears to be accessible without authentication. Both authenticated and unauthenticated requests returned ${noAuth.response.statusCode}.`,
            remediation: 'Ensure all sensitive endpoints require valid authentication. Return 401/403 for unauthenticated requests.',
            owaspCategory: this.owaspCategory,
            request: noAuth.request,
            response: noAuth.response,
          });
        }

        // Test with invalid/expired token
        const authHeaders = { ...target.globalHeaders };
        if (authHeaders['Authorization']) {
          authHeaders['Authorization'] = 'Bearer invalid_token_12345';
        }

        const invalidAuth = await sendRequest({
          url,
          method: ep.method,
          headers: authHeaders,
          timeout: config.timeout,
        });
        requestCount++;

        if (invalidAuth.response.statusCode < 400) {
          findings.push({
            id: `auth-bypass-invalid-${ep.method}-${ep.path}`,
            checkId: this.id,
            checkName: this.name,
            severity: 'critical',
            endpoint: url,
            method: ep.method,
            evidence: `Endpoint returns ${invalidAuth.response.statusCode} with invalid auth token`,
            description: `Endpoint ${ep.method} ${ep.path} accepts invalid/expired authentication tokens.`,
            remediation: 'Validate authentication tokens on every request. Reject invalid or expired tokens with 401.',
            owaspCategory: this.owaspCategory,
            request: invalidAuth.request,
            response: invalidAuth.response,
          });
        }
      } catch {
        // skip unreachable endpoints
      }
    }

    return { findings, requestCount };
  }
}
