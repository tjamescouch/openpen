/**
 * SQL Injection Check (A03:2021 - Injection)
 */

import { BaseCheck, type CheckResult } from './base.js';
import type { ScanTarget, ScanConfig, Finding } from '../types.js';
import { sendRequest, Semaphore, RateLimiter } from '../utils/http.js';
import { SQLI_PAYLOADS } from '../fuzzer/payloads.js';

const SQL_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning:.*mysql/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /pg_query\(\)/i,
  /postgresql/i,
  /sqlite3?\.OperationalError/i,
  /SQLite\/JDBCDriver/i,
  /ORA-\d{5}/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /ODBC SQL Server Driver/i,
  /SQL Server.*Driver/i,
  /Warning.*mssql_/i,
  /com\.mysql\.jdbc/i,
  /org\.postgresql\.util\.PSQLException/i,
  /Syntax error.*in query expression/i,
];

export class SqlInjectionCheck extends BaseCheck {
  id = 'sqli';
  name = 'SQL Injection';
  description = 'Test for SQL injection vulnerabilities in parameters and request bodies';
  owaspCategory = 'A03:2021 Injection';

  async run(target: ScanTarget, config: ScanConfig): Promise<CheckResult> {
    const findings: Finding[] = [];
    let requestCount = 0;
    const sem = new Semaphore(config.concurrency);
    const rl = new RateLimiter(config.rateLimit);

    const payloads = config.depth === 'shallow'
      ? SQLI_PAYLOADS.slice(0, 5)
      : config.depth === 'deep'
        ? SQLI_PAYLOADS
        : SQLI_PAYLOADS.slice(0, 12);

    const tasks: Promise<void>[] = [];

    for (const ep of target.endpoints) {
      const url = target.baseUrl + ep.path;

      // Test query parameters
      for (const param of ep.parameters.filter(p => p.in === 'query')) {
        for (const payload of payloads) {
          tasks.push(testPayload(url, ep.method, param.name, payload));
        }
      }

      // Test body fields
      if (ep.requestBody?.fields) {
        for (const [fieldName] of Object.entries(ep.requestBody.fields)) {
          for (const payload of payloads) {
            tasks.push(testBodyField(url, ep.method, fieldName, payload, ep.requestBody.fields));
          }
        }
      }

      // Always test with a query param even if none defined
      if (ep.parameters.filter(p => p.in === 'query').length === 0) {
        for (const payload of payloads.slice(0, 3)) {
          tasks.push(testPayload(url, ep.method, 'id', payload));
        }
      }
    }

    async function testPayload(baseUrl: string, method: string, param: string, payload: string): Promise<void> {
      await sem.acquire();
      try {
        await rl.wait();
        const testUrl = `${baseUrl}?${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;
        const res = await sendRequest({
          url: testUrl,
          method: 'GET',
          headers: target.globalHeaders,
          timeout: config.timeout,
        });
        requestCount++;

        const match = checkForSqlError(res.response.bodySnippet);
        if (match) {
          findings.push({
            id: `sqli-${param}-${findings.length}`,
            checkId: 'sqli',
            checkName: 'SQL Injection',
            severity: 'critical',
            endpoint: baseUrl,
            method: method as any,
            parameter: param,
            payload,
            evidence: `SQL error detected: "${match}"`,
            description: `Parameter "${param}" may be vulnerable to SQL injection. The server returned a database error in response to a SQL payload.`,
            remediation: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL.',
            owaspCategory: 'A03:2021 Injection',
            request: res.request,
            response: res.response,
          });
        }

        // Time-based detection
        if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
          if (res.response.responseTime > 4500) {
            findings.push({
              id: `sqli-time-${param}-${findings.length}`,
              checkId: 'sqli',
              checkName: 'SQL Injection (Time-based)',
              severity: 'critical',
              endpoint: baseUrl,
              method: method as any,
              parameter: param,
              payload,
              evidence: `Response took ${res.response.responseTime}ms (expected delay from payload)`,
              description: `Parameter "${param}" appears vulnerable to time-based blind SQL injection.`,
              remediation: 'Use parameterized queries or prepared statements.',
              owaspCategory: 'A03:2021 Injection',
              request: res.request,
              response: res.response,
            });
          }
        }
      } catch {
        // Request failed, skip
      } finally {
        sem.release();
      }
    }

    async function testBodyField(
      baseUrl: string,
      method: string,
      field: string,
      payload: string,
      fields: Record<string, any>,
    ): Promise<void> {
      await sem.acquire();
      try {
        await rl.wait();
        const body: Record<string, any> = {};
        for (const [k, v] of Object.entries(fields)) {
          body[k] = k === field ? payload : (v.example || 'test');
        }

        const res = await sendRequest({
          url: baseUrl,
          method,
          headers: { ...target.globalHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          timeout: config.timeout,
        });
        requestCount++;

        const match = checkForSqlError(res.response.bodySnippet);
        if (match) {
          findings.push({
            id: `sqli-body-${field}-${findings.length}`,
            checkId: 'sqli',
            checkName: 'SQL Injection',
            severity: 'critical',
            endpoint: baseUrl,
            method: method as any,
            parameter: field,
            payload,
            evidence: `SQL error in response body: "${match}"`,
            description: `Body field "${field}" may be vulnerable to SQL injection.`,
            remediation: 'Use parameterized queries or prepared statements.',
            owaspCategory: 'A03:2021 Injection',
            request: res.request,
            response: res.response,
          });
        }
      } catch {
        // skip
      } finally {
        sem.release();
      }
    }

    await Promise.all(tasks);
    return { findings, requestCount };
  }
}

function checkForSqlError(body: string): string | null {
  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = body.match(pattern);
    if (match) return match[0];
  }
  return null;
}
