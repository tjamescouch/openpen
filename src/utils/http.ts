/**
 * Low-level HTTP helpers wrapping native fetch
 */

import type { RequestSummary, ResponseSummary } from '../types.js';
import { verbose } from './logger.js';

export interface HttpRequestOptions {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  timeout?: number;
}

export interface HttpResponse {
  request: RequestSummary;
  response: ResponseSummary;
  rawHeaders: Headers;
}

export async function sendRequest(opts: HttpRequestOptions): Promise<HttpResponse> {
  const { url, method, headers = {}, body, timeout = 10000 } = opts;

  const reqHeaders: Record<string, string> = {
    'User-Agent': 'openpen/0.1.0',
    ...headers,
  };

  if (body && !reqHeaders['Content-Type']) {
    reqHeaders['Content-Type'] = 'application/json';
  }

  verbose(`  -> ${method} ${url}`);

  const start = Date.now();
  const res = await fetch(url, {
    method,
    headers: reqHeaders,
    body: body || undefined,
    signal: AbortSignal.timeout(timeout),
    redirect: 'follow',
  });

  const responseTime = Date.now() - start;
  const responseBody = await res.text();

  const responseHeaders: Record<string, string> = {};
  for (const [k, v] of res.headers) {
    responseHeaders[k] = v;
  }

  verbose(`  <- ${res.status} (${responseTime}ms, ${responseBody.length} bytes)`);

  return {
    request: {
      url,
      method,
      headers: reqHeaders,
      body,
    },
    response: {
      statusCode: res.status,
      headers: responseHeaders,
      bodySnippet: responseBody.slice(0, 500),
      responseTime,
    },
    rawHeaders: res.headers,
  };
}

/**
 * Simple concurrency limiter
 */
export class Semaphore {
  private queue: (() => void)[] = [];
  private active = 0;

  constructor(private max: number) {}

  async acquire(): Promise<void> {
    if (this.active < this.max) {
      this.active++;
      return;
    }
    return new Promise(resolve => {
      this.queue.push(() => {
        this.active++;
        resolve();
      });
    });
  }

  release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next) next();
  }
}

/**
 * Simple rate limiter (token bucket)
 */
export class RateLimiter {
  private lastTime = 0;
  private minInterval: number;

  constructor(maxPerSecond: number) {
    this.minInterval = 1000 / maxPerSecond;
  }

  async wait(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastTime;
    if (elapsed < this.minInterval) {
      await new Promise(r => setTimeout(r, this.minInterval - elapsed));
    }
    this.lastTime = Date.now();
  }
}
