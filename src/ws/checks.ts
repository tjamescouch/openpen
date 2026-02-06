/**
 * WebSocket security checks
 * Built-in protocol tests for common WS vulnerabilities
 */

import { connect, sendAndWait, sendRaw, close, parseJson } from './engine.js';
import { verbose } from '../utils/logger.js';
import type { WsTestResult, Severity } from '../types.js';

export interface WsCheckInfo {
  id: string;
  name: string;
  description: string;
}

type WsCheck = {
  info: WsCheckInfo;
  run: (url: string, timeout: number) => Promise<WsTestResult>;
};

/**
 * Check: Unauthenticated access
 * Tests if the server accepts connections and responds to commands without auth
 */
const unauthAccess: WsCheck = {
  info: {
    id: 'ws-unauth',
    name: 'Unauthenticated Access',
    description: 'Tests if server responds to commands without authentication',
  },
  async run(url, timeout) {
    const start = Date.now();
    try {
      const conn = await connect(url, { timeout });
      // Try common discovery commands without auth
      const probes = [
        '{"type":"LIST_CHANNELS"}',
        '{"type":"LIST_AGENTS","channel":"#general"}',
        '{"type":"SEARCH_SKILLS"}',
        '{"action":"list"}',
        '{"cmd":"help"}',
      ];

      const responses: string[] = [];
      for (const probe of probes) {
        const resp = await sendAndWait(conn, probe, { timeout: 1500 });
        if (resp) {
          responses.push(resp);
          verbose(`  [ws-unauth] ${probe} -> ${resp.slice(0, 120)}`);
        }
      }

      await close(conn);

      const successResponses = responses.filter(r => {
        const p = parseJson(r);
        if (!p.parsed) return false;
        const v = p.value as Record<string, unknown>;
        return v.type !== 'ERROR' && !v.error;
      });

      if (successResponses.length > 0) {
        return {
          checkId: 'ws-unauth',
          checkName: 'Unauthenticated Access',
          status: 'fail',
          severity: 'high' as Severity,
          description: `Server responded to ${successResponses.length} commands without authentication`,
          evidence: successResponses.map(r => r.slice(0, 200)).join('\n'),
          remediation: 'Require authentication before processing any commands',
          duration: Date.now() - start,
        };
      }

      return {
        checkId: 'ws-unauth',
        checkName: 'Unauthenticated Access',
        status: 'pass',
        severity: 'info' as Severity,
        description: 'Server requires authentication for commands',
        evidence: `${probes.length} probes sent, all rejected or ignored`,
        duration: Date.now() - start,
      };
    } catch (e) {
      return {
        checkId: 'ws-unauth',
        checkName: 'Unauthenticated Access',
        status: 'error',
        severity: 'info' as Severity,
        description: `Connection failed: ${(e as Error).message}`,
        evidence: '',
        duration: Date.now() - start,
      };
    }
  },
};

/**
 * Check: Message type enumeration
 * Discovers valid message types by probing common names
 */
const typeEnumeration: WsCheck = {
  info: {
    id: 'ws-enum',
    name: 'Message Type Enumeration',
    description: 'Discovers valid protocol message types',
  },
  async run(url, timeout) {
    const start = Date.now();
    try {
      const conn = await connect(url, { timeout });

      const types = [
        'IDENTIFY', 'LOGIN', 'AUTH', 'HELLO', 'REGISTER',
        'JOIN', 'LEAVE', 'MSG', 'MESSAGE', 'SEND',
        'PING', 'PONG', 'HEARTBEAT',
        'LIST', 'LIST_CHANNELS', 'LIST_AGENTS', 'LIST_USERS', 'LIST_ROOMS',
        'CREATE', 'CREATE_CHANNEL', 'CREATE_ROOM',
        'DELETE', 'REMOVE', 'BAN', 'KICK',
        'SUBSCRIBE', 'UNSUBSCRIBE', 'PUBLISH',
        'PROPOSAL', 'ACCEPT', 'REJECT', 'COMPLETE', 'DISPUTE',
        'REGISTER_SKILLS', 'SEARCH_SKILLS',
        'SET_PRESENCE', 'STATUS',
        'VERIFY_REQUEST', 'VERIFY_RESPONSE',
        'INVITE', 'TRANSFER', 'ADMIN',
      ];

      const recognized: string[] = [];
      const errors: string[] = [];

      for (const type of types) {
        const resp = await sendAndWait(conn, JSON.stringify({ type }), { timeout: 500 });
        if (resp) {
          const p = parseJson(resp);
          if (p.parsed) {
            const v = p.value as Record<string, unknown>;
            if (v.type === 'ERROR') {
              const msg = (v.message || v.error || '') as string;
              // "Unknown message type" means it's NOT recognized
              if (!/unknown.*type/i.test(msg)) {
                recognized.push(type);
                verbose(`  [ws-enum] ${type} -> recognized (error: ${msg})`);
              }
            } else {
              recognized.push(type);
              verbose(`  [ws-enum] ${type} -> recognized (response: ${v.type})`);
            }
          }
        }
      }

      await close(conn);

      return {
        checkId: 'ws-enum',
        checkName: 'Message Type Enumeration',
        status: recognized.length > 0 ? 'warn' : 'pass',
        severity: 'info' as Severity,
        description: `Discovered ${recognized.length} valid message types out of ${types.length} probed`,
        evidence: recognized.length > 0
          ? `Valid types: ${recognized.join(', ')}`
          : 'No types discovered (server may require auth first)',
        remediation: 'Ensure sensitive operations are gated behind authentication',
        duration: Date.now() - start,
      };
    } catch (e) {
      return {
        checkId: 'ws-enum',
        checkName: 'Message Type Enumeration',
        status: 'error',
        severity: 'info' as Severity,
        description: `Connection failed: ${(e as Error).message}`,
        evidence: '',
        duration: Date.now() - start,
      };
    }
  },
};

/**
 * Check: Message size limit
 * Tests if the server enforces payload size limits
 */
const messageSizeLimit: WsCheck = {
  info: {
    id: 'ws-size',
    name: 'Message Size Limit',
    description: 'Tests if the server enforces WebSocket frame size limits',
  },
  async run(url, timeout) {
    const start = Date.now();
    const sizes = [
      { label: '1KB', size: 1024 },
      { label: '64KB', size: 64 * 1024 },
      { label: '256KB', size: 256 * 1024 },
      { label: '1MB', size: 1024 * 1024 },
      { label: '5MB', size: 5 * 1024 * 1024 },
    ];

    let maxAccepted = 0;
    let maxAcceptedLabel = 'none';

    try {
      for (const { label, size } of sizes) {
        try {
          const conn = await connect(url, { timeout });
          const payload = JSON.stringify({ type: 'PING', data: 'x'.repeat(size) });
          sendRaw(conn, payload);

          // Wait briefly to see if connection stays alive
          await new Promise(r => setTimeout(r, 500));

          if (conn.connected) {
            maxAccepted = size;
            maxAcceptedLabel = label;
            verbose(`  [ws-size] ${label} -> accepted`);
          } else {
            verbose(`  [ws-size] ${label} -> connection closed (code: ${conn.closedCode})`);
          }
          await close(conn);
        } catch {
          verbose(`  [ws-size] ${label} -> rejected/failed`);
          break;
        }
      }

      if (maxAccepted >= 1024 * 1024) {
        return {
          checkId: 'ws-size',
          checkName: 'Message Size Limit',
          status: 'fail',
          severity: 'medium' as Severity,
          description: `Server accepts messages up to ${maxAcceptedLabel} without limit`,
          evidence: `Max accepted payload: ${maxAcceptedLabel} (${maxAccepted} bytes)`,
          remediation: 'Set maxPayload on WebSocket server (recommended: 256KB or less)',
          duration: Date.now() - start,
        };
      }

      if (maxAccepted >= 256 * 1024) {
        return {
          checkId: 'ws-size',
          checkName: 'Message Size Limit',
          status: 'warn',
          severity: 'low' as Severity,
          description: `Server accepts messages up to ${maxAcceptedLabel}`,
          evidence: `Max accepted payload: ${maxAcceptedLabel} (${maxAccepted} bytes)`,
          remediation: 'Consider lowering maxPayload if protocol messages are small',
          duration: Date.now() - start,
        };
      }

      return {
        checkId: 'ws-size',
        checkName: 'Message Size Limit',
        status: 'pass',
        severity: 'info' as Severity,
        description: `Server enforces message size limit (max accepted: ${maxAcceptedLabel})`,
        evidence: `Largest accepted: ${maxAcceptedLabel} (${maxAccepted} bytes)`,
        duration: Date.now() - start,
      };
    } catch (e) {
      return {
        checkId: 'ws-size',
        checkName: 'Message Size Limit',
        status: 'error',
        severity: 'info' as Severity,
        description: `Test failed: ${(e as Error).message}`,
        evidence: '',
        duration: Date.now() - start,
      };
    }
  },
};

/**
 * Check: Rate limiting
 * Tests if the server limits message frequency
 */
const rateLimiting: WsCheck = {
  info: {
    id: 'ws-rate',
    name: 'Rate Limiting',
    description: 'Tests if the server enforces message rate limits',
  },
  async run(url, timeout) {
    const start = Date.now();
    try {
      const conn = await connect(url, { timeout });

      // Send 20 messages as fast as possible
      const burstCount = 20;
      const startBurst = Date.now();
      for (let i = 0; i < burstCount; i++) {
        sendRaw(conn, JSON.stringify({ type: 'PING', seq: i }));
      }

      // Wait for responses
      await new Promise(r => setTimeout(r, 2000));
      const burstDuration = Date.now() - startBurst;

      // Check for rate limit errors
      const rateLimitErrors = conn.messages.filter(m => {
        if (m.direction !== 'received') return false;
        const p = parseJson(m.data);
        if (!p.parsed) return false;
        const v = p.value as Record<string, unknown>;
        const msg = ((v.message || v.error || '') as string).toLowerCase();
        return msg.includes('rate') || msg.includes('limit') || msg.includes('throttl') || msg.includes('too many');
      });

      await close(conn);

      if (rateLimitErrors.length > 0) {
        return {
          checkId: 'ws-rate',
          checkName: 'Rate Limiting',
          status: 'pass',
          severity: 'info' as Severity,
          description: `Server enforces rate limiting (${rateLimitErrors.length} rate limit responses for ${burstCount} burst messages)`,
          evidence: rateLimitErrors[0]?.data.slice(0, 200) || '',
          duration: Date.now() - start,
        };
      }

      return {
        checkId: 'ws-rate',
        checkName: 'Rate Limiting',
        status: 'warn',
        severity: 'medium' as Severity,
        description: `No rate limiting detected for ${burstCount} rapid messages in ${burstDuration}ms`,
        evidence: `Sent ${burstCount} messages, received ${conn.messages.filter(m => m.direction === 'received').length} responses, no rate limit errors`,
        remediation: 'Implement per-connection rate limiting to prevent message flooding',
        duration: Date.now() - start,
      };
    } catch (e) {
      return {
        checkId: 'ws-rate',
        checkName: 'Rate Limiting',
        status: 'error',
        severity: 'info' as Severity,
        description: `Test failed: ${(e as Error).message}`,
        evidence: '',
        duration: Date.now() - start,
      };
    }
  },
};

/**
 * Check: Connection flood
 * Tests if the server limits concurrent connections from one source
 */
const connectionFlood: WsCheck = {
  info: {
    id: 'ws-flood',
    name: 'Connection Flood',
    description: 'Tests if the server limits concurrent connections per IP',
  },
  async run(url, timeout) {
    const start = Date.now();
    const maxConns = 15;
    const conns: (Awaited<ReturnType<typeof connect>> | null)[] = [];
    let rejected = false;
    let rejectedAt = 0;

    try {
      for (let i = 0; i < maxConns; i++) {
        try {
          const conn = await connect(url, { timeout: 2000 });
          conns.push(conn);
          verbose(`  [ws-flood] Connection ${i + 1} opened`);
        } catch {
          rejected = true;
          rejectedAt = i + 1;
          verbose(`  [ws-flood] Connection ${i + 1} rejected`);
          break;
        }
      }

      // Also check if any connections were forcibly closed
      const closedConns = conns.filter(c => c && !c.connected);

      // Clean up
      for (const conn of conns) {
        if (conn) await close(conn);
      }

      if (rejected || closedConns.length > 0) {
        const limit = rejected ? rejectedAt : conns.length;
        return {
          checkId: 'ws-flood',
          checkName: 'Connection Flood',
          status: 'pass',
          severity: 'info' as Severity,
          description: `Server limits connections per IP (limit ~${limit})`,
          evidence: rejected
            ? `Connection ${rejectedAt} was rejected`
            : `${closedConns.length} connections were forcibly closed`,
          duration: Date.now() - start,
        };
      }

      return {
        checkId: 'ws-flood',
        checkName: 'Connection Flood',
        status: 'warn',
        severity: 'medium' as Severity,
        description: `Server accepted all ${maxConns} concurrent connections without limiting`,
        evidence: `${conns.length} simultaneous connections from same IP were accepted`,
        remediation: 'Implement per-IP connection limiting (recommended: 10-20 max)',
        duration: Date.now() - start,
      };
    } catch (e) {
      // Clean up on error
      for (const conn of conns) {
        if (conn) await close(conn).catch(() => {});
      }
      return {
        checkId: 'ws-flood',
        checkName: 'Connection Flood',
        status: 'error',
        severity: 'info' as Severity,
        description: `Test failed: ${(e as Error).message}`,
        evidence: '',
        duration: Date.now() - start,
      };
    }
  },
};

/**
 * Check: Invalid message handling
 * Tests how server handles malformed/malicious input
 */
const invalidMessages: WsCheck = {
  info: {
    id: 'ws-invalid',
    name: 'Invalid Message Handling',
    description: 'Tests server response to malformed and malicious payloads',
  },
  async run(url, timeout) {
    const start = Date.now();
    try {
      const conn = await connect(url, { timeout });

      const payloads = [
        // Malformed JSON
        '{not valid json',
        '{"type":',
        '',
        // Injection attempts
        '{"type":"<script>alert(1)</script>"}',
        '{"type":"IDENTIFY","name":"test\'; DROP TABLE users; --"}',
        // Type confusion
        '{"type":123}',
        '{"type":null}',
        '{"type":true}',
        '[]',
        '"just a string"',
        // Oversized field
        JSON.stringify({ type: 'PING', data: 'A'.repeat(10000) }),
        // Prototype pollution
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
      ];

      let crashed = false;
      let errorResponses = 0;
      let silentDrops = 0;

      for (const payload of payloads) {
        try {
          sendRaw(conn, payload);
          await new Promise(r => setTimeout(r, 200));

          if (!conn.connected) {
            crashed = true;
            verbose(`  [ws-invalid] Server closed connection after: ${payload.slice(0, 60)}`);
            break;
          }
        } catch {
          crashed = true;
          break;
        }
      }

      // Count error responses
      errorResponses = conn.messages.filter(m => {
        if (m.direction !== 'received') return false;
        const p = parseJson(m.data);
        if (!p.parsed) return false;
        const v = p.value as Record<string, unknown>;
        return v.type === 'ERROR' || v.error;
      }).length;

      const totalReceived = conn.messages.filter(m => m.direction === 'received').length;
      silentDrops = payloads.length - errorResponses - (crashed ? 1 : 0);

      await close(conn);

      if (crashed) {
        return {
          checkId: 'ws-invalid',
          checkName: 'Invalid Message Handling',
          status: 'fail',
          severity: 'medium' as Severity,
          description: 'Server crashed or disconnected on malformed input',
          evidence: `Connection dropped after ${conn.messages.length} messages`,
          remediation: 'Gracefully handle all malformed input without closing the connection',
          duration: Date.now() - start,
        };
      }

      return {
        checkId: 'ws-invalid',
        checkName: 'Invalid Message Handling',
        status: 'pass',
        severity: 'info' as Severity,
        description: `Server handled ${payloads.length} malformed payloads gracefully`,
        evidence: `${errorResponses} error responses, ${silentDrops} silently dropped, connection stable`,
        duration: Date.now() - start,
      };
    } catch (e) {
      return {
        checkId: 'ws-invalid',
        checkName: 'Invalid Message Handling',
        status: 'error',
        severity: 'info' as Severity,
        description: `Test failed: ${(e as Error).message}`,
        evidence: '',
        duration: Date.now() - start,
      };
    }
  },
};

// Registry

const ALL_WS_CHECKS: WsCheck[] = [
  unauthAccess,
  typeEnumeration,
  messageSizeLimit,
  rateLimiting,
  connectionFlood,
  invalidMessages,
];

export function getAllWsChecks(): WsCheck[] {
  return ALL_WS_CHECKS;
}

export function getWsChecksByIds(ids: string[]): WsCheck[] {
  const checks: WsCheck[] = [];
  for (const id of ids) {
    const check = ALL_WS_CHECKS.find(c => c.info.id === id);
    if (!check) throw new Error(`Unknown WebSocket check: ${id}`);
    checks.push(check);
  }
  return checks;
}

export function listWsChecks(): WsCheckInfo[] {
  return ALL_WS_CHECKS.map(c => c.info);
}
