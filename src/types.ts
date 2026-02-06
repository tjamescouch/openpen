/**
 * Core types for openpen
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Depth = 'shallow' | 'normal' | 'deep';
export type AnomalyType = 'status_change' | 'length_anomaly' | 'time_anomaly' | 'error_string' | 'reflection';

// Target specification

export interface ScanTarget {
  baseUrl: string;
  endpoints: Endpoint[];
  auth?: AuthConfig;
  globalHeaders: Record<string, string>;
}

export interface Endpoint {
  path: string;
  method: HttpMethod;
  parameters: Parameter[];
  requestBody?: RequestBodySchema;
  description?: string;
}

export interface Parameter {
  name: string;
  in: 'query' | 'path' | 'header' | 'cookie';
  type: string;
  required: boolean;
  example?: string;
}

export interface RequestBodySchema {
  contentType: string;
  fields: Record<string, FieldSchema>;
}

export interface FieldSchema {
  type: string;
  required: boolean;
  example?: unknown;
}

export interface AuthConfig {
  headers: Record<string, string>;
}

// Scan configuration

export interface ScanConfig {
  depth: Depth;
  checks: string[];
  excludeChecks: string[];
  timeout: number;
  concurrency: number;
  rateLimit: number;
  verbose: boolean;
  noColor: boolean;
}

// Results

export interface Finding {
  id: string;
  checkId: string;
  checkName: string;
  severity: Severity;
  endpoint: string;
  method: HttpMethod;
  parameter?: string;
  payload?: string;
  evidence: string;
  description: string;
  remediation: string;
  owaspCategory: string;
  request?: RequestSummary;
  response?: ResponseSummary;
}

export interface RequestSummary {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

export interface ResponseSummary {
  statusCode: number;
  headers: Record<string, string>;
  bodySnippet: string;
  responseTime: number;
}

export interface ScanReport {
  target: string;
  startedAt: string;
  completedAt: string;
  duration: number;
  totalRequests: number;
  findings: Finding[];
  summary: Record<Severity, number>;
  checksRun: string[];
}

// Fuzzer

export interface FuzzConfig {
  body?: string;
  headers: Record<string, string>;
  fuzzParams: string[];
  wordlist: string;
  detect: string[];
  baseline: boolean;
  timeout: number;
  concurrency: number;
  rateLimit: number;
  verbose: boolean;
}

export interface FuzzResult {
  payload: string;
  request: RequestSummary;
  response: ResponseSummary;
  anomalies: AnomalyType[];
  baseline?: ResponseSummary;
}

// WebSocket testing

export interface WsTestConfig {
  timeout: number;
  verbose: boolean;
  auth?: AuthConfig;
  checks: string[];
  excludeChecks: string[];
  output?: string;
  format: 'terminal' | 'json';
}

export interface WsMessage {
  direction: 'sent' | 'received';
  data: string;
  timestamp: number;
  parseError?: boolean;
}

export interface WsTestResult {
  checkId: string;
  checkName: string;
  status: 'pass' | 'fail' | 'warn' | 'error';
  severity: Severity;
  description: string;
  evidence: string;
  remediation?: string;
  messages?: WsMessage[];
  duration: number;
}

export interface WsTestReport {
  target: string;
  startedAt: string;
  completedAt: string;
  duration: number;
  results: WsTestResult[];
  summary: { pass: number; fail: number; warn: number; error: number };
}
