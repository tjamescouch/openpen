/**
 * WebSocket test engine
 * Handles connections, message exchange, and response collection
 */

import WebSocket from 'ws';
import type { WsMessage } from '../types.js';

export interface WsConnection {
  ws: WebSocket;
  messages: WsMessage[];
  connected: boolean;
  closedCode?: number;
  closedReason?: string;
}

/**
 * Open a WebSocket connection to the target
 */
export function connect(url: string, options: {
  timeout?: number;
  headers?: Record<string, string>;
} = {}): Promise<WsConnection> {
  const timeout = options.timeout || 5000;

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, {
      headers: options.headers || {},
      handshakeTimeout: timeout,
    });

    const conn: WsConnection = {
      ws,
      messages: [],
      connected: false,
    };

    const timer = setTimeout(() => {
      if (!conn.connected) {
        ws.terminate();
        reject(new Error(`Connection timeout after ${timeout}ms`));
      }
    }, timeout);

    ws.on('open', () => {
      clearTimeout(timer);
      conn.connected = true;
      resolve(conn);
    });

    ws.on('message', (data) => {
      conn.messages.push({
        direction: 'received',
        data: data.toString(),
        timestamp: Date.now(),
      });
    });

    ws.on('close', (code, reason) => {
      conn.connected = false;
      conn.closedCode = code;
      conn.closedReason = reason.toString();
    });

    ws.on('error', (err) => {
      clearTimeout(timer);
      if (!conn.connected) {
        reject(err);
      }
    });
  });
}

/**
 * Send a message and wait for a response
 */
export function sendAndWait(conn: WsConnection, data: string, options: {
  timeout?: number;
  matchFn?: (msg: string) => boolean;
} = {}): Promise<string | null> {
  const timeout = options.timeout || 3000;
  const startIdx = conn.messages.length;

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      conn.ws.removeListener('message', onMessage);
      resolve(null);
    }, timeout);

    const check = () => {
      for (let i = startIdx; i < conn.messages.length; i++) {
        const msg = conn.messages[i];
        if (msg.direction === 'received') {
          if (!options.matchFn || options.matchFn(msg.data)) {
            clearTimeout(timer);
            conn.ws.removeListener('message', onMessage);
            resolve(msg.data);
            return true;
          }
        }
      }
      return false;
    };

    const onMessage = () => { check(); };
    conn.ws.on('message', onMessage);

    conn.messages.push({
      direction: 'sent',
      data,
      timestamp: Date.now(),
    });
    conn.ws.send(data);

    // Check messages already received
    check();
  });
}

/**
 * Send raw data (string or buffer) without recording
 */
export function sendRaw(conn: WsConnection, data: string | Buffer): void {
  conn.ws.send(data);
}

/**
 * Close a connection gracefully
 */
export function close(conn: WsConnection): Promise<void> {
  return new Promise((resolve) => {
    if (!conn.connected) {
      resolve();
      return;
    }
    conn.ws.on('close', () => resolve());
    conn.ws.close();
    setTimeout(() => resolve(), 1000);
  });
}

/**
 * Wait for a specific number of messages or timeout
 */
export function waitForMessages(conn: WsConnection, count: number, timeout = 3000): Promise<WsMessage[]> {
  const startIdx = conn.messages.length;

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve(conn.messages.slice(startIdx));
    }, timeout);

    const check = () => {
      const received = conn.messages.slice(startIdx).filter(m => m.direction === 'received');
      if (received.length >= count) {
        clearTimeout(timer);
        resolve(conn.messages.slice(startIdx));
      }
    };

    conn.ws.on('message', () => check());
    check();
  });
}

/**
 * Try to parse a message as JSON
 */
export function parseJson(data: string): { parsed: boolean; value?: unknown; error?: string } {
  try {
    return { parsed: true, value: JSON.parse(data) };
  } catch (e) {
    return { parsed: false, error: (e as Error).message };
  }
}
