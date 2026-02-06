/**
 * Core fuzzing orchestrator
 */

import type { FuzzResult, ResponseSummary, AnomalyType } from '../types.js';
import { sendRequest, Semaphore, RateLimiter } from '../utils/http.js';
import { getPayloads, type WordlistName } from './payloads.js';
import { info, verbose } from '../utils/logger.js';

export interface FuzzEngineConfig {
  timeout: number;
  concurrency: number;
  rateLimit: number;
  verbose: boolean;
}

export interface FuzzRequest {
  url: string;
  method: string;
  body?: string;
  headers: Record<string, string>;
  fuzzParams: string[];
  wordlist: string;
  detect: string[];
  baseline: boolean;
}

export class FuzzEngine {
  private semaphore: Semaphore;
  private rateLimiter: RateLimiter;
  private config: FuzzEngineConfig;

  constructor(config: FuzzEngineConfig) {
    this.config = config;
    this.semaphore = new Semaphore(config.concurrency);
    this.rateLimiter = new RateLimiter(config.rateLimit);
  }

  async fuzz(req: FuzzRequest): Promise<FuzzResult[]> {
    const payloads = getPayloads(req.wordlist as WordlistName);
    info(` Payloads:  ${payloads.length}`);

    // Get baseline if requested
    let baselineResponse: ResponseSummary | undefined;
    if (req.baseline) {
      verbose('  Getting baseline response...');
      const cleanUrl = req.url.replace(/FUZZ/g, 'test');
      const cleanBody = req.body?.replace(/FUZZ/g, 'test');
      try {
        const res = await sendRequest({
          url: cleanUrl,
          method: req.method,
          headers: req.headers,
          body: cleanBody,
          timeout: this.config.timeout,
        });
        baselineResponse = res.response;
        verbose(`  Baseline: ${baselineResponse.statusCode} (${baselineResponse.responseTime}ms, ${baselineResponse.bodySnippet.length} bytes)`);
      } catch {
        verbose('  Baseline request failed, continuing without');
      }
    }

    const results: FuzzResult[] = [];
    const detectors = new Set(req.detect);

    const tasks = payloads.map(payload => async () => {
      await this.semaphore.acquire();
      try {
        await this.rateLimiter.wait();

        const fuzzedUrl = req.url.replace(/FUZZ/g, encodeURIComponent(payload));
        const fuzzedBody = req.body?.replace(/FUZZ/g, payload);

        const res = await sendRequest({
          url: fuzzedUrl,
          method: req.method,
          headers: req.headers,
          body: fuzzedBody,
          timeout: this.config.timeout,
        });

        const anomalies = detectAnomalies(res.response, baselineResponse, payload, detectors);

        results.push({
          payload,
          request: res.request,
          response: res.response,
          anomalies,
          baseline: baselineResponse,
        });
      } catch (err) {
        verbose(`  Error fuzzing with payload "${payload.slice(0, 30)}": ${err}`);
      } finally {
        this.semaphore.release();
      }
    });

    // Execute all fuzz tasks
    await Promise.all(tasks.map(t => t()));

    return results;
  }
}

function detectAnomalies(
  response: ResponseSummary,
  baseline: ResponseSummary | undefined,
  payload: string,
  detectors: Set<string>,
): AnomalyType[] {
  const anomalies: AnomalyType[] = [];

  // Status code change
  if (detectors.has('status') && baseline) {
    if (response.statusCode !== baseline.statusCode) {
      // 500 errors are especially interesting
      if (response.statusCode >= 500) {
        anomalies.push('status_change');
      } else if (Math.floor(response.statusCode / 100) !== Math.floor(baseline.statusCode / 100)) {
        anomalies.push('status_change');
      }
    }
  }

  // Response length anomaly
  if (detectors.has('length') && baseline) {
    const baseLen = baseline.bodySnippet.length;
    const resLen = response.bodySnippet.length;
    if (baseLen > 0) {
      const ratio = Math.abs(resLen - baseLen) / baseLen;
      if (ratio > 0.5) {
        anomalies.push('length_anomaly');
      }
    }
  }

  // Timing anomaly (possible time-based injection)
  if (detectors.has('time') && baseline) {
    if (response.responseTime > baseline.responseTime * 3 && response.responseTime > 3000) {
      anomalies.push('time_anomaly');
    }
  }

  // Error string detection
  if (detectors.has('content')) {
    const body = response.bodySnippet.toLowerCase();
    const errorPatterns = [
      'sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-',
      'syntax error', 'uncaught exception', 'stack trace',
      'internal server error', 'fatal error',
      'root:', '/etc/passwd', '/bin/sh',
      'access denied', 'permission denied',
    ];
    if (errorPatterns.some(p => body.includes(p))) {
      anomalies.push('error_string');
    }

    // Check for payload reflection (potential XSS)
    if (response.bodySnippet.includes(payload)) {
      anomalies.push('reflection');
    }
  }

  return anomalies;
}
