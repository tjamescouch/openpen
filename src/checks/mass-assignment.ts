/**
 * Mass Assignment Check (A04:2021 - Insecure Design)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest } from '../utils/http.js';

const DANGEROUS_FIELDS = [
  'role', 'admin', 'is_admin', 'isAdmin',
  'privilege', 'permissions', 'access_level', 'accessLevel',
  'verified', 'is_verified', 'isVerified',
  'active', 'is_active', 'isActive',
  'balance', 'credits',
  'user_id', 'userId', 'owner_id', 'ownerId',
  '__proto__', 'constructor',
  'password', 'password_hash', 'passwordHash',
  'email_verified', 'emailVerified',
  'created_at', 'updated_at',
];

export class MassAssignmentCheck extends BaseCheck {
  id = 'mass-assignment';
  name = 'Mass Assignment';
  description = 'Test if extra fields in request bodies are accepted and processed';
  owaspCategory = 'A04:2021 Insecure Design';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;

    // Focus on POST/PUT/PATCH endpoints
    const writeEndpoints = target.endpoints.filter(ep =>
      ['POST', 'PUT', 'PATCH'].includes(ep.method)
    );

    const fields = config.depth === 'shallow'
      ? DANGEROUS_FIELDS.slice(0, 6)
      : config.depth === 'deep'
        ? DANGEROUS_FIELDS
        : DANGEROUS_FIELDS.slice(0, 12);

    for (const ep of writeEndpoints) {
      const url = target.baseUrl + ep.path;

      // Build a base body from the schema
      const baseBody: Record<string, any> = {};
      if (ep.requestBody?.fields) {
        for (const [k, v] of Object.entries(ep.requestBody.fields)) {
          baseBody[k] = v.example || getDefaultValue(v.type);
        }
      }

      // First, send clean request to get baseline
      let baselineStatus: number;
      try {
        const baseline = await sendRequest({
          url,
          method: ep.method,
          headers: { ...target.globalHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify(baseBody),
          timeout: config.timeout,
        });
        requestCount++;
        baselineStatus = baseline.response.statusCode;
      } catch {
        continue;
      }

      // Now inject extra fields
      for (const field of fields) {
        if (baseBody[field] !== undefined) continue; // skip fields already in schema

        const testBody = {
          ...baseBody,
          [field]: getFieldValue(field),
        };

        try {
          const res = await sendRequest({
            url,
            method: ep.method,
            headers: { ...target.globalHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify(testBody),
            timeout: config.timeout,
          });
          requestCount++;

          // If the server accepts the extra field without error
          if (res.response.statusCode < 400) {
            // Check if the field is reflected in the response
            const responseBody = res.response.bodySnippet;
            const fieldReflected = responseBody.includes(`"${field}"`) ||
                                   responseBody.includes(`"${field.replace(/_/g, '')}"`);

            if (fieldReflected) {
              findings.push({
                id: `mass-assign-${ep.method}-${ep.path}-${field}`,
                checkId: this.id,
                checkName: this.name,
                severity: isPrivilegeField(field) ? 'high' : 'medium',
                endpoint: url,
                method: ep.method,
                parameter: field,
                payload: JSON.stringify(testBody),
                evidence: `Extra field "${field}" accepted and reflected in response`,
                description: `Endpoint ${ep.method} ${ep.path} accepts and processes the undocumented field "${field}". ${isPrivilegeField(field) ? 'This is a privilege escalation field.' : 'This may allow unintended data modification.'}`,
                remediation: 'Use allowlists for accepted fields. Reject or ignore unexpected properties. Use DTOs/schemas for input validation.',
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

      // Test prototype pollution
      try {
        const pollutionBody = {
          ...baseBody,
          '__proto__': { 'isAdmin': true },
          'constructor': { 'prototype': { 'isAdmin': true } },
        };

        const res = await sendRequest({
          url,
          method: ep.method,
          headers: { ...target.globalHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify(pollutionBody),
          timeout: config.timeout,
        });
        requestCount++;

        if (res.response.statusCode < 400) {
          findings.push({
            id: `mass-assign-proto-${ep.method}-${ep.path}`,
            checkId: this.id,
            checkName: this.name,
            severity: 'high',
            endpoint: url,
            method: ep.method,
            payload: JSON.stringify(pollutionBody),
            evidence: `Server accepted __proto__ / constructor fields without error (${res.response.statusCode})`,
            description: `Endpoint ${ep.method} ${ep.path} does not reject __proto__ or constructor fields, which may enable prototype pollution.`,
            remediation: 'Strip __proto__ and constructor from input. Use Object.create(null) for dictionaries.',
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

function getDefaultValue(type: string): any {
  switch (type) {
    case 'string': return 'test';
    case 'number':
    case 'integer': return 1;
    case 'boolean': return true;
    case 'array': return [];
    case 'object': return {};
    default: return 'test';
  }
}

function getFieldValue(field: string): any {
  if (/admin|privilege|verified|active/i.test(field)) return true;
  if (/balance|credits/i.test(field)) return 99999;
  if (/role|access/i.test(field)) return 'admin';
  if (/id/i.test(field)) return '1';
  return 'injected';
}

function isPrivilegeField(field: string): boolean {
  return /admin|role|privilege|permission|access|verified|password/i.test(field);
}
