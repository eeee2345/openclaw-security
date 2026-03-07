/**
 * DashboardRelayClient unit tests
 * DashboardRelayClient 單元測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer, type IncomingMessage } from 'node:http';
import { createHash } from 'node:crypto';
import type { Socket } from 'node:net';
import type { Server } from 'node:http';
import { DashboardRelayClient, type RelayClientConfig } from '../src/dashboard/relay-client.js';

/** WebSocket magic GUID / WebSocket 魔術 GUID */
const WS_MAGIC_GUID = '258EAFA5-E914-47DA-95CA-5AB5DC11E65B';

/** Helper to get a free port / 輔助取得可用埠 */
function getPort(): Promise<number> {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

/** Create a mock Manager WebSocket server that accepts relay upgrades / 建立接受 relay 升級的模擬 Manager WebSocket 伺服器 */
function createMockManager(port: number): {
  server: Server;
  connections: Socket[];
  receivedFrames: Buffer[];
  start: () => Promise<void>;
  stop: () => Promise<void>;
} {
  const connections: Socket[] = [];
  const receivedFrames: Buffer[] = [];

  const server = createServer();

  server.on('upgrade', (req: IncomingMessage, socket: Socket) => {
    const url = req.url ?? '';

    // Only accept relay paths / 只接受 relay 路徑
    if (!url.startsWith('/api/dashboard/relay/')) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    // Validate auth / 驗證認證
    const authHeader = req.headers.authorization ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // Complete WebSocket handshake / 完成 WebSocket 交握
    const key = req.headers['sec-websocket-key'];
    if (!key) {
      socket.destroy();
      return;
    }

    const acceptKey = createHash('sha1')
      .update(key + WS_MAGIC_GUID)
      .digest('base64');

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${acceptKey}\r\n` +
        '\r\n'
    );

    connections.push(socket);

    socket.on('data', (data: Buffer) => {
      receivedFrames.push(data);
    });

    socket.on('close', () => {
      const idx = connections.indexOf(socket);
      if (idx >= 0) connections.splice(idx, 1);
    });
  });

  return {
    server,
    connections,
    receivedFrames,
    start: () => new Promise<void>((resolve) => {
      server.listen(port, '127.0.0.1', () => resolve());
    }),
    stop: () => new Promise<void>((resolve) => {
      for (const conn of connections) {
        try { conn.destroy(); } catch { /* ignore */ }
      }
      connections.length = 0;
      server.close(() => resolve());
    }),
  };
}

/** Create an unmasked WebSocket text frame (server->client) / 建立未遮罩的 WebSocket 文字框架 */
function createServerFrame(text: string): Buffer {
  const payload = Buffer.from(text, 'utf-8');
  const length = payload.length;
  let header: Buffer;

  if (length < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81;
    header[1] = length;
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  }

  return Buffer.concat([header, payload]);
}

/** Extract text from a masked client WebSocket frame / 從帶遮罩的客戶端 WebSocket 框架提取文字 */
function extractMaskedText(data: Buffer): string | null {
  if (data.length < 6) return null;
  const opcode = (data[0] ?? 0) & 0x0f;
  if (opcode !== 0x01) return null;

  const masked = ((data[1] ?? 0) & 0x80) !== 0;
  if (!masked) return null; // Client frames should be masked

  let payloadLen = (data[1] ?? 0) & 0x7f;
  let offset = 2;
  if (payloadLen === 126) {
    payloadLen = data.readUInt16BE(2);
    offset = 4;
  }

  const maskKey = data.subarray(offset, offset + 4);
  offset += 4;

  const payload = Buffer.alloc(payloadLen);
  for (let i = 0; i < payloadLen; i++) {
    payload[i] = (data[offset + i] ?? 0) ^ (maskKey[i % 4] ?? 0);
  }

  return payload.toString('utf-8');
}

describe('DashboardRelayClient', () => {
  let mockManager: ReturnType<typeof createMockManager>;
  let port: number;

  beforeEach(async () => {
    port = await getPort();
    mockManager = createMockManager(port);
    await mockManager.start();
  });

  afterEach(async () => {
    await mockManager.stop();
  });

  function makeConfig(overrides?: Partial<RelayClientConfig>): RelayClientConfig {
    return {
      managerUrl: `http://127.0.0.1:${port}`,
      agentId: 'test-agent-001',
      token: 'test-token-abc',
      ...overrides,
    };
  }

  describe('constructor', () => {
    it('should accept valid config', () => {
      const client = new DashboardRelayClient(makeConfig());
      expect(client).toBeDefined();
      expect(client.isConnected).toBe(false);
    });

    it('should throw on missing managerUrl', () => {
      expect(() => new DashboardRelayClient(makeConfig({ managerUrl: '' }))).toThrow(
        'managerUrl is required'
      );
    });

    it('should throw on missing agentId', () => {
      expect(() => new DashboardRelayClient(makeConfig({ agentId: '' }))).toThrow(
        'agentId is required'
      );
    });

    it('should throw on missing token', () => {
      expect(() => new DashboardRelayClient(makeConfig({ token: '' }))).toThrow(
        'token is required'
      );
    });
  });

  describe('connect / disconnect lifecycle', () => {
    it('should connect to mock manager and emit connected event', async () => {
      const client = new DashboardRelayClient(makeConfig());

      const connected = new Promise<void>((resolve) => {
        client.on('connected', () => resolve());
      });

      client.connect();
      await connected;

      expect(client.isConnected).toBe(true);
      expect(mockManager.connections).toHaveLength(1);

      client.disconnect();
      expect(client.isConnected).toBe(false);
    });

    it('should emit disconnected event on disconnect', async () => {
      const client = new DashboardRelayClient(makeConfig());

      const connected = new Promise<void>((resolve) => {
        client.on('connected', () => resolve());
      });

      client.connect();
      await connected;

      const disconnected = new Promise<void>((resolve) => {
        client.on('disconnected', () => resolve());
      });

      client.disconnect();
      await disconnected;

      expect(client.isConnected).toBe(false);
    });

    it('should handle connect when already connected gracefully', async () => {
      const client = new DashboardRelayClient(makeConfig());

      const connected = new Promise<void>((resolve) => {
        client.on('connected', () => resolve());
      });

      client.connect();
      await connected;

      // Second connect should not throw or create duplicate connections
      client.connect();

      expect(mockManager.connections).toHaveLength(1);
      client.disconnect();
    });
  });

  describe('sendEvent', () => {
    it('should send event data as a masked WebSocket frame', async () => {
      const client = new DashboardRelayClient(makeConfig());

      const connected = new Promise<void>((resolve) => {
        client.on('connected', () => resolve());
      });

      client.connect();
      await connected;

      // Clear any initial frames / 清除初始框架
      mockManager.receivedFrames.length = 0;

      const event = { type: 'status_update', data: { mode: 'learning' }, timestamp: '2026-01-01T00:00:00Z' };
      client.sendEvent(event);

      // Wait for data to arrive
      await new Promise((r) => setTimeout(r, 100));

      expect(mockManager.receivedFrames.length).toBeGreaterThan(0);
      const text = extractMaskedText(mockManager.receivedFrames[0]!);
      expect(text).toBeTruthy();
      const parsed = JSON.parse(text!);
      expect(parsed.type).toBe('status_update');
      expect(parsed.data.mode).toBe('learning');

      client.disconnect();
    });

    it('should silently skip sending when not connected', () => {
      const client = new DashboardRelayClient(makeConfig());
      // Should not throw
      client.sendEvent({ type: 'test', data: {} });
    });
  });

  describe('auto-reconnect', () => {
    it('should attempt to reconnect after server-initiated disconnect', async () => {
      const client = new DashboardRelayClient(
        makeConfig({ reconnectInterval: 100 })
      );

      let connectCount = 0;
      client.on('connected', () => {
        connectCount++;
      });

      const firstConnect = new Promise<void>((resolve) => {
        client.once('connected', () => resolve());
      });

      client.connect();
      await firstConnect;
      expect(connectCount).toBe(1);

      // Server forcibly closes the connection / 伺服器強制關閉連接
      const firstSocket = mockManager.connections[0];
      if (firstSocket) {
        firstSocket.destroy();
      }

      // Wait for reconnect (100ms base + some jitter) / 等待重連
      const secondConnect = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Reconnect timed out')), 3000);
        client.once('connected', () => {
          clearTimeout(timer);
          resolve();
        });
      });

      await secondConnect;
      expect(connectCount).toBe(2);

      client.disconnect();
    });
  });

  describe('isConnected property', () => {
    it('should return false initially', () => {
      const client = new DashboardRelayClient(makeConfig());
      expect(client.isConnected).toBe(false);
    });

    it('should return true after connecting', async () => {
      const client = new DashboardRelayClient(makeConfig());

      const connected = new Promise<void>((resolve) => {
        client.on('connected', () => resolve());
      });

      client.connect();
      await connected;
      expect(client.isConnected).toBe(true);

      client.disconnect();
    });

    it('should return false after disconnecting', async () => {
      const client = new DashboardRelayClient(makeConfig());

      const connected = new Promise<void>((resolve) => {
        client.on('connected', () => resolve());
      });

      client.connect();
      await connected;

      client.disconnect();
      expect(client.isConnected).toBe(false);
    });
  });

  describe('receiving messages from Manager', () => {
    it('should emit message events for data from Manager', async () => {
      const client = new DashboardRelayClient(makeConfig());

      const connected = new Promise<void>((resolve) => {
        client.on('connected', () => resolve());
      });

      client.connect();
      await connected;

      const messageReceived = new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Message timed out')), 2000);
        client.on('message', (msg: Record<string, unknown>) => {
          clearTimeout(timer);
          resolve(msg);
        });
      });

      // Manager sends a command to the agent
      const agentSocket = mockManager.connections[0]!;
      const command = { type: 'subscribe', channels: ['events', 'verdicts'] };
      const frame = createServerFrame(JSON.stringify(command));
      agentSocket.write(frame);

      const received = await messageReceived;
      expect(received.type).toBe('subscribe');
      expect(received.channels).toEqual(['events', 'verdicts']);

      client.disconnect();
    });
  });
});
