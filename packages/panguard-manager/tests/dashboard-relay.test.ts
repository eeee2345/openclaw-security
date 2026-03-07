/**
 * DashboardRelay unit tests
 * DashboardRelay 單元測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer, request as httpRequest, type IncomingMessage } from 'node:http';
import { randomBytes } from 'node:crypto';
import type { Socket } from 'node:net';
import { DashboardRelay } from '../src/dashboard-relay.js';


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

/** Helper to perform a WebSocket handshake as a client / 輔助以客戶端身分執行 WebSocket 交握 */
function wsConnect(
  port: number,
  path: string,
  headers?: Record<string, string>
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const wsKey = randomBytes(16).toString('base64');

    const req = httpRequest({
      hostname: '127.0.0.1',
      port,
      path,
      method: 'GET',
      headers: {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Key': wsKey,
        'Sec-WebSocket-Version': '13',
        ...headers,
      },
    });

    req.on('upgrade', (_res: IncomingMessage, socket: Socket) => {
      resolve(socket);
    });

    req.on('response', (res) => {
      reject(new Error(`Upgrade rejected: HTTP ${res.statusCode}`));
    });

    req.on('error', reject);
    req.end();
  });
}

/** Create a masked WebSocket text frame (client->server) / 建立帶遮罩的 WebSocket 文字框架 */
function createMaskedFrame(text: string): Buffer {
  const payload = Buffer.from(text, 'utf-8');
  const maskKey = randomBytes(4);
  const length = payload.length;

  let header: Buffer;
  if (length < 126) {
    header = Buffer.alloc(6);
    header[0] = 0x81;
    header[1] = 0x80 | length;
    maskKey.copy(header, 2);
  } else {
    header = Buffer.alloc(8);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(length, 2);
    maskKey.copy(header, 4);
  }

  const masked = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    masked[i] = (payload[i] ?? 0) ^ (maskKey[i % 4] ?? 0);
  }

  return Buffer.concat([header, masked]);
}

/** Extract text from an unmasked server WebSocket frame / 從未遮罩的伺服器 WebSocket 框架提取文字 */
function extractTextFromFrame(data: Buffer): string | null {
  if (data.length < 2) return null;
  const opcode = (data[0] ?? 0) & 0x0f;
  if (opcode !== 0x01) return null; // Not a text frame

  let payloadLen = (data[1] ?? 0) & 0x7f;
  let offset = 2;
  if (payloadLen === 126) {
    payloadLen = data.readUInt16BE(2);
    offset = 4;
  }

  return data.subarray(offset, offset + payloadLen).toString('utf-8');
}

/** Wait for data on a socket / 等待 socket 上的資料 */
function waitForData(socket: Socket, timeoutMs = 2000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout waiting for data')), timeoutMs);
    socket.once('data', (data: Buffer) => {
      clearTimeout(timer);
      resolve(data);
    });
  });
}

describe('DashboardRelay', () => {
  let relay: DashboardRelay;
  let server: ReturnType<typeof createServer>;
  let port: number;
  const sockets: Socket[] = [];

  beforeEach(async () => {
    relay = new DashboardRelay();
    port = await getPort();
    server = createServer();

    server.on('upgrade', (req: IncomingMessage, socket: Socket, head: Buffer) => {
      relay.handleUpgrade(req, socket, head);
    });

    await new Promise<void>((resolve) => {
      server.listen(port, '127.0.0.1', () => resolve());
    });
  });

  afterEach(async () => {
    // Cleanup sockets
    for (const s of sockets) {
      try { s.destroy(); } catch { /* ignore */ }
    }
    sockets.length = 0;

    relay.disconnectAll();

    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  // Helper to track sockets for cleanup
  function track(socket: Socket): Socket {
    sockets.push(socket);
    return socket;
  }

  describe('constructor', () => {
    it('should create instance with default config', () => {
      const r = new DashboardRelay();
      expect(r).toBeDefined();
      expect(r.getConnectedAgents()).toEqual([]);
    });

    it('should create instance with requireAuth config', () => {
      const r = new DashboardRelay({ requireAuth: true });
      expect(r).toBeDefined();
    });
  });

  describe('handleUpgrade - agent connection', () => {
    it('should register an agent connection on relay path', async () => {
      track(await wsConnect(port, '/api/dashboard/relay/agent-001'));
      // Allow event loop to process
      await new Promise((r) => setTimeout(r, 50));

      expect(relay.getConnectedAgents()).toContain('agent-001');
    });

    it('should replace existing agent connection on reconnect', async () => {
      track(await wsConnect(port, '/api/dashboard/relay/agent-002'));
      await new Promise((r) => setTimeout(r, 50));
      expect(relay.getConnectedAgents()).toContain('agent-002');

      track(await wsConnect(port, '/api/dashboard/relay/agent-002'));
      await new Promise((r) => setTimeout(r, 50));
      expect(relay.getConnectedAgents()).toContain('agent-002');
      // Still only one agent
      expect(relay.getConnectedAgents().filter(id => id === 'agent-002')).toHaveLength(1);
    });
  });

  describe('handleUpgrade - client connection', () => {
    it('should register a client connection for an existing agent', async () => {
      // First connect agent
      track(await wsConnect(port, '/api/dashboard/relay/agent-010'));
      await new Promise((r) => setTimeout(r, 50));

      // Then connect client
      track(await wsConnect(port, '/api/dashboard/view/agent-010'));
      await new Promise((r) => setTimeout(r, 50));

      expect(relay.getClientCount('agent-010')).toBe(1);
    });

    it('should reject client connection for non-connected agent', async () => {
      await expect(
        wsConnect(port, '/api/dashboard/view/non-existent-agent')
      ).rejects.toThrow('Upgrade rejected');
    });
  });

  describe('event forwarding', () => {
    it('should forward agent events to subscribed clients', async () => {
      // Connect agent
      const agentSocket = track(await wsConnect(port, '/api/dashboard/relay/agent-020'));
      await new Promise((r) => setTimeout(r, 50));

      // Connect client
      const clientSocket = track(await wsConnect(port, '/api/dashboard/view/agent-020'));
      await new Promise((r) => setTimeout(r, 50));

      // Agent sends event
      const event = { type: 'status_update', data: { mode: 'protection' }, timestamp: new Date().toISOString() };
      const frame = createMaskedFrame(JSON.stringify(event));
      agentSocket.write(frame);

      // Client should receive
      const received = await waitForData(clientSocket);
      const text = extractTextFromFrame(received);
      expect(text).toBeTruthy();

      const parsed = JSON.parse(text!);
      expect(parsed.type).toBe('status_update');
      expect(parsed.data.mode).toBe('protection');
    });
  });

  describe('multiple clients broadcast', () => {
    it('should broadcast to all subscribed clients', async () => {
      // Connect agent
      const agentSocket = track(await wsConnect(port, '/api/dashboard/relay/agent-030'));
      await new Promise((r) => setTimeout(r, 50));

      // Connect two clients
      const client1 = track(await wsConnect(port, '/api/dashboard/view/agent-030'));
      const client2 = track(await wsConnect(port, '/api/dashboard/view/agent-030'));
      await new Promise((r) => setTimeout(r, 50));

      expect(relay.getClientCount('agent-030')).toBe(2);

      // Agent sends event
      const event = { type: 'new_event', data: { threat: true }, timestamp: new Date().toISOString() };
      agentSocket.write(createMaskedFrame(JSON.stringify(event)));

      // Both clients should receive
      const [data1, data2] = await Promise.all([
        waitForData(client1),
        waitForData(client2),
      ]);

      const text1 = extractTextFromFrame(data1);
      const text2 = extractTextFromFrame(data2);
      expect(text1).toBeTruthy();
      expect(text2).toBeTruthy();
      expect(JSON.parse(text1!).type).toBe('new_event');
      expect(JSON.parse(text2!).type).toBe('new_event');
    });
  });

  describe('agent disconnect', () => {
    it('should notify clients when agent disconnects', async () => {
      // Connect agent
      const agentSocket = track(await wsConnect(port, '/api/dashboard/relay/agent-040'));
      await new Promise((r) => setTimeout(r, 50));

      // Connect client
      const clientSocket = track(await wsConnect(port, '/api/dashboard/view/agent-040'));
      await new Promise((r) => setTimeout(r, 50));

      // Start listening for data before destroying the agent
      const dataPromise = waitForData(clientSocket, 3000);

      // Disconnect agent by ending the socket cleanly
      agentSocket.end();
      sockets.splice(sockets.indexOf(agentSocket), 1);

      // Client should receive agent_disconnected notification
      const received = await dataPromise;
      const text = extractTextFromFrame(received);
      expect(text).toBeTruthy();

      const parsed = JSON.parse(text!);
      expect(parsed.type).toBe('agent_disconnected');
      expect(parsed.agentId).toBe('agent-040');
    });

    it('should remove agent from connected list on disconnect', async () => {
      const agentSocket = track(await wsConnect(port, '/api/dashboard/relay/agent-041'));
      await new Promise((r) => setTimeout(r, 50));
      expect(relay.getConnectedAgents()).toContain('agent-041');

      agentSocket.destroy();
      sockets.splice(sockets.indexOf(agentSocket), 1);
      // Wait for close event propagation / 等待關閉事件傳播
      await new Promise((r) => setTimeout(r, 200));

      expect(relay.getConnectedAgents()).not.toContain('agent-041');
    });
  });

  describe('client disconnect', () => {
    it('should cleanup client on disconnect', async () => {
      // Connect agent and client
      track(await wsConnect(port, '/api/dashboard/relay/agent-050'));
      await new Promise((r) => setTimeout(r, 50));

      const clientSocket = track(await wsConnect(port, '/api/dashboard/view/agent-050'));
      await new Promise((r) => setTimeout(r, 50));
      expect(relay.getClientCount('agent-050')).toBe(1);

      // Disconnect client
      clientSocket.destroy();
      sockets.splice(sockets.indexOf(clientSocket), 1);
      // Wait for close event propagation / 等待關閉事件傳播
      await new Promise((r) => setTimeout(r, 200));

      expect(relay.getClientCount('agent-050')).toBe(0);
    });
  });

  describe('getConnectedAgents', () => {
    it('should return correct list of connected agents', async () => {
      track(await wsConnect(port, '/api/dashboard/relay/agent-a'));
      track(await wsConnect(port, '/api/dashboard/relay/agent-b'));
      track(await wsConnect(port, '/api/dashboard/relay/agent-c'));
      await new Promise((r) => setTimeout(r, 50));

      const agents = relay.getConnectedAgents();
      expect(agents).toHaveLength(3);
      expect(agents).toContain('agent-a');
      expect(agents).toContain('agent-b');
      expect(agents).toContain('agent-c');
    });
  });

  describe('unknown path', () => {
    it('should reject upgrade for unknown paths', async () => {
      await expect(
        wsConnect(port, '/api/dashboard/unknown/agent-x')
      ).rejects.toThrow();
    });
  });

  describe('disconnectAll', () => {
    it('should close all connections', async () => {
      track(await wsConnect(port, '/api/dashboard/relay/agent-da'));
      await new Promise((r) => setTimeout(r, 50));
      track(await wsConnect(port, '/api/dashboard/view/agent-da'));
      await new Promise((r) => setTimeout(r, 50));

      expect(relay.getConnectedAgents()).toHaveLength(1);
      expect(relay.getClientCount('agent-da')).toBe(1);

      relay.disconnectAll();

      expect(relay.getConnectedAgents()).toHaveLength(0);
      expect(relay.getClientCount('agent-da')).toBe(0);
    });
  });
});
