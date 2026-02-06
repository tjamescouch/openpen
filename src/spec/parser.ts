/**
 * Unified target loader - from OpenAPI spec or manual paths
 */

import type { ScanTarget, Endpoint, HttpMethod, AuthConfig } from '../types.js';
import { parseOpenApiSpec } from './openapi.js';
import { info } from '../utils/logger.js';

export interface LoadTargetOptions {
  specPath?: string;
  methods?: string[];
  paths?: string[];
  auth?: AuthConfig;
}

export async function loadTarget(baseUrl: string, opts: LoadTargetOptions = {}): Promise<ScanTarget> {
  const globalHeaders: Record<string, string> = {
    ...(opts.auth?.headers || {}),
  };

  let endpoints: Endpoint[] = [];

  // Load from spec if provided
  if (opts.specPath) {
    info(` Loading spec: ${opts.specPath}`);
    endpoints = await parseOpenApiSpec(opts.specPath);
  }

  // Add manual paths
  if (opts.paths && opts.paths.length > 0) {
    const methods: HttpMethod[] = opts.methods
      ? opts.methods.map(m => m.toUpperCase() as HttpMethod)
      : ['GET'];

    for (const path of opts.paths) {
      for (const method of methods) {
        // Skip if already defined by spec
        if (!endpoints.some(e => e.path === path && e.method === method)) {
          endpoints.push({
            path,
            method,
            parameters: [],
          });
        }
      }
    }
  }

  // Filter methods if specified (for spec-loaded endpoints)
  if (opts.methods && opts.specPath) {
    const allowed = new Set(opts.methods.map(m => m.toUpperCase()));
    endpoints = endpoints.filter(e => allowed.has(e.method));
  }

  return {
    baseUrl: baseUrl.replace(/\/$/, ''),
    endpoints,
    auth: opts.auth,
    globalHeaders,
  };
}
