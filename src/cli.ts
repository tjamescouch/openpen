#!/usr/bin/env node
/**
 * openpen - Open source API fuzzing and penetration testing CLI
 */

import { Command } from 'commander';
import { setVerbose, info, error } from './utils/logger.js';
import { loadTarget } from './spec/parser.js';
import { FuzzEngine } from './fuzzer/engine.js';
import { getAllChecks, getChecksByIds, listChecks } from './checks/index.js';
import { getAllWsChecks, getWsChecksByIds, listWsChecks } from './ws/checks.js';
import { reportTerminal, reportJson } from './reporter/index.js';
import type { ScanConfig, ScanReport, Severity, Finding, AuthConfig, WsTestReport } from './types.js';

const program = new Command();

program
  .name('openpen')
  .description('Open source CLI for API fuzzing and penetration testing')
  .version('0.1.0');

// scan command
program
  .command('scan')
  .description('Run OWASP security checks against an API')
  .argument('<target>', 'Base URL of the API')
  .option('--spec <path>', 'Path or URL to OpenAPI/Swagger spec')
  .option('--checks <list>', 'Comma-separated check IDs to run')
  .option('--exclude-checks <list>', 'Checks to skip')
  .option('--auth-header <header>', 'Auth header (e.g. "Authorization: Bearer tok")', collect, [])
  .option('--auth-token <token>', 'Bearer token shorthand')
  .option('--method <methods>', 'HTTP methods to test (comma-separated)')
  .option('--paths <paths>', 'Comma-separated paths to test (manual mode)')
  .option('--depth <level>', 'Payload volume: shallow, normal, deep', 'normal')
  .option('--output <file>', 'Write report to file')
  .option('--format <fmt>', 'Output format: terminal, json', 'terminal')
  .option('--timeout <ms>', 'Per-request timeout in ms', '10000')
  .option('--concurrency <n>', 'Max concurrent requests', '10')
  .option('--rate-limit <n>', 'Max requests per second', '50')
  .option('--verbose', 'Show individual request details')
  .option('--no-color', 'Disable colored output')
  .action(async (targetUrl, opts) => {
    setVerbose(opts.verbose || false);

    const auth = parseAuth(opts.authHeader, opts.authToken);
    const target = await loadTarget(targetUrl, {
      specPath: opts.spec,
      methods: opts.method?.split(','),
      paths: opts.paths?.split(','),
      auth,
    });

    if (target.endpoints.length === 0) {
      error('No endpoints found. Provide --spec or --paths.');
      process.exit(1);
    }

    info(`\n OPENPEN v0.1.0 -- API Security Scanner\n`);
    info(` Target:     ${targetUrl}`);
    info(` Endpoints:  ${target.endpoints.length}`);
    info(` Depth:      ${opts.depth}`);

    const config: ScanConfig = {
      depth: opts.depth,
      checks: opts.checks ? opts.checks.split(',') : [],
      excludeChecks: opts.excludeChecks ? opts.excludeChecks.split(',') : [],
      timeout: parseInt(opts.timeout),
      concurrency: parseInt(opts.concurrency),
      rateLimit: parseInt(opts.rateLimit),
      verbose: opts.verbose || false,
      noColor: !opts.color,
    };

    const checks = config.checks.length > 0
      ? getChecksByIds(config.checks)
      : getAllChecks().filter(c => !config.excludeChecks.includes(c.id));

    info(` Checks:     ${checks.length} modules\n`);

    const startedAt = new Date();
    let totalRequests = 0;
    const findings: Finding[] = [];

    for (const check of checks) {
      info(` Running: ${check.name}...`);
      const result = await check.run(target, config);
      findings.push(...result.findings);
      totalRequests += result.requestCount;
    }

    const completedAt = new Date();
    const report: ScanReport = {
      target: targetUrl,
      startedAt: startedAt.toISOString(),
      completedAt: completedAt.toISOString(),
      duration: completedAt.getTime() - startedAt.getTime(),
      totalRequests,
      findings,
      summary: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length,
      },
      checksRun: checks.map(c => c.id),
    };

    if (opts.format === 'json') {
      reportJson(report, opts.output);
    } else {
      reportTerminal(report, !opts.color);
    }
  });

// fuzz command
program
  .command('fuzz')
  .description('Fuzz API endpoints with mutated payloads')
  .argument('<target>', 'URL to fuzz')
  .option('--method <method>', 'HTTP method', 'GET')
  .option('--body <json>', 'Request body (use FUZZ as placeholder)')
  .option('--headers <json>', 'Additional headers as JSON')
  .option('--fuzz-params <list>', 'Parameters to fuzz (comma-separated)')
  .option('--wordlist <name>', 'Wordlist: sqli, xss, path-traversal, ssrf, all', 'all')
  .option('--detect <methods>', 'Anomaly detection: status,length,time,content', 'status,length,time,content')
  .option('--baseline', 'Send clean request first for comparison')
  .option('--auth-header <header>', 'Auth header', collect, [])
  .option('--auth-token <token>', 'Bearer token shorthand')
  .option('--timeout <ms>', 'Per-request timeout', '10000')
  .option('--concurrency <n>', 'Max concurrent requests', '10')
  .option('--rate-limit <n>', 'Max requests per second', '50')
  .option('--output <file>', 'Write results to file')
  .option('--verbose', 'Show each request/response')
  .action(async (targetUrl, opts) => {
    setVerbose(opts.verbose || false);
    const auth = parseAuth(opts.authHeader, opts.authToken);

    const engine = new FuzzEngine({
      timeout: parseInt(opts.timeout),
      concurrency: parseInt(opts.concurrency),
      rateLimit: parseInt(opts.rateLimit),
      verbose: opts.verbose || false,
    });

    info(`\n OPENPEN v0.1.0 -- Fuzzer\n`);
    info(` Target: ${targetUrl}`);
    info(` Method: ${opts.method}`);
    info(` Wordlist: ${opts.wordlist}\n`);

    const results = await engine.fuzz({
      url: targetUrl,
      method: opts.method,
      body: opts.body,
      headers: {
        ...(opts.headers ? JSON.parse(opts.headers) : {}),
        ...(auth?.headers || {}),
      },
      fuzzParams: opts.fuzzParams?.split(',') || [],
      wordlist: opts.wordlist,
      detect: opts.detect.split(','),
      baseline: opts.baseline || false,
    });

    const anomalies = results.filter(r => r.anomalies.length > 0);
    info(`\n Results: ${anomalies.length} anomalies from ${results.length} requests\n`);

    for (const r of anomalies) {
      info(`  [${r.anomalies.join(',')}] ${r.payload} -> ${r.response.statusCode} (${r.response.responseTime}ms)`);
    }

    if (opts.output) {
      const { writeFileSync } = await import('fs');
      writeFileSync(opts.output, JSON.stringify(results, null, 2));
      info(`\n Report written to ${opts.output}`);
    }
  });

// info command
program
  .command('info')
  .description('Reconnaissance - fingerprint an API')
  .argument('<target>', 'Base URL of the API')
  .option('--spec <path>', 'Path or URL to OpenAPI/Swagger spec')
  .option('--auth-header <header>', 'Auth header', collect, [])
  .option('--auth-token <token>', 'Bearer token shorthand')
  .action(async (targetUrl, opts) => {
    const auth = parseAuth(opts.authHeader, opts.authToken);
    const target = await loadTarget(targetUrl, {
      specPath: opts.spec,
      auth,
    });

    info(`\n OPENPEN v0.1.0 -- API Recon\n`);
    info(` Target: ${targetUrl}`);
    info(` Endpoints: ${target.endpoints.length}\n`);

    for (const ep of target.endpoints) {
      const params = ep.parameters.map(p => `${p.name}(${p.in})`).join(', ');
      info(`  ${ep.method.padEnd(7)} ${ep.path}${params ? '  [' + params + ']' : ''}`);
    }

    // Fingerprint
    try {
      const res = await fetch(targetUrl, { signal: AbortSignal.timeout(5000) });
      info(`\n Server Headers:`);
      for (const [k, v] of res.headers) {
        if (['server', 'x-powered-by', 'x-frame-options', 'x-content-type-options',
             'strict-transport-security', 'content-security-policy',
             'access-control-allow-origin'].includes(k.toLowerCase())) {
          info(`  ${k}: ${v}`);
        }
      }
    } catch {
      info(`\n Could not reach ${targetUrl} for fingerprinting`);
    }
  });

// ws-test command
program
  .command('ws-test')
  .description('Run security checks against a WebSocket endpoint')
  .argument('<target>', 'WebSocket URL (ws:// or wss://)')
  .option('--checks <list>', 'Comma-separated check IDs to run')
  .option('--exclude-checks <list>', 'Checks to skip')
  .option('--timeout <ms>', 'Connection timeout in ms', '5000')
  .option('--output <file>', 'Write report to file')
  .option('--format <fmt>', 'Output format: terminal, json', 'terminal')
  .option('--verbose', 'Show detailed test output')
  .action(async (targetUrl, opts) => {
    setVerbose(opts.verbose || false);

    // Validate URL scheme
    if (!targetUrl.startsWith('ws://') && !targetUrl.startsWith('wss://')) {
      // Auto-upgrade http(s) to ws(s)
      targetUrl = targetUrl.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:');
      if (!targetUrl.startsWith('ws://') && !targetUrl.startsWith('wss://')) {
        targetUrl = `wss://${targetUrl}`;
      }
    }

    const timeout = parseInt(opts.timeout);

    const allChecks = opts.checks
      ? getWsChecksByIds(opts.checks.split(','))
      : getAllWsChecks().filter(c =>
          !(opts.excludeChecks || '').split(',').includes(c.info.id)
        );

    info(`\n OPENPEN v0.1.0 -- WebSocket Security Tester\n`);
    info(` Target:  ${targetUrl}`);
    info(` Checks:  ${allChecks.length} modules\n`);

    const startedAt = new Date();
    const results = [];

    for (const check of allChecks) {
      info(` Running: ${check.info.name}...`);
      const result = await check.run(targetUrl, timeout);
      results.push(result);

      const icon = result.status === 'pass' ? 'OK' :
                   result.status === 'fail' ? 'FAIL' :
                   result.status === 'warn' ? 'WARN' : 'ERR';
      const sev = result.status === 'pass' ? '' : ` [${result.severity.toUpperCase()}]`;
      info(`   ${icon}${sev} ${result.description}`);
    }

    const completedAt = new Date();
    const report: WsTestReport = {
      target: targetUrl,
      startedAt: startedAt.toISOString(),
      completedAt: completedAt.toISOString(),
      duration: completedAt.getTime() - startedAt.getTime(),
      results,
      summary: {
        pass: results.filter(r => r.status === 'pass').length,
        fail: results.filter(r => r.status === 'fail').length,
        warn: results.filter(r => r.status === 'warn').length,
        error: results.filter(r => r.status === 'error').length,
      },
    };

    info(`\n Summary: ${report.summary.pass} pass, ${report.summary.fail} fail, ${report.summary.warn} warn, ${report.summary.error} error`);
    info(` Duration: ${report.duration}ms\n`);

    if (opts.format === 'json' || opts.output) {
      const json = JSON.stringify(report, null, 2);
      if (opts.output) {
        const { writeFileSync } = await import('fs');
        writeFileSync(opts.output, json);
        info(` Report written to ${opts.output}\n`);
      } else {
        console.log(json);
      }
    }
  });

// list-checks command
program
  .command('list-checks')
  .description('List available security check modules')
  .action(() => {
    info(`\n OPENPEN v0.1.0 -- Available Checks\n`);
    info(` HTTP API Checks:`);
    const checks = listChecks();
    for (const c of checks) {
      info(`  ${c.id.padEnd(20)} ${c.owaspCategory.padEnd(25)} ${c.name}`);
    }
    info(`\n WebSocket Checks:`);
    const wsChecks = listWsChecks();
    for (const c of wsChecks) {
      info(`  ${c.id.padEnd(20)} ${''.padEnd(25)} ${c.name}`);
    }
    info('');
  });

// Helpers

function collect(val: string, prev: string[]): string[] {
  prev.push(val);
  return prev;
}

function parseAuth(headers: string[], token?: string): AuthConfig | undefined {
  const result: Record<string, string> = {};
  for (const h of headers) {
    const idx = h.indexOf(':');
    if (idx > 0) {
      result[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
    }
  }
  if (token) {
    result['Authorization'] = `Bearer ${token}`;
  }
  if (Object.keys(result).length === 0) return undefined;
  return { headers: result };
}

program.parse();
