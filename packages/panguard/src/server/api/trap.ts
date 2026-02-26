/**
 * /api/trap/* - Honeypot system endpoints
 * Checks real port binding to determine trap status.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { createConnection } from 'node:net';

/** Default trap service definitions */
const TRAP_SERVICES = [
  { type: 'ssh', port: 2222, enabled: true },
  { type: 'http', port: 8080, enabled: true },
  { type: 'ftp', port: 2121, enabled: false },
  { type: 'telnet', port: 2323, enabled: false },
  { type: 'mysql', port: 3307, enabled: false },
  { type: 'redis', port: 6380, enabled: false },
  { type: 'smb', port: 4450, enabled: false },
  { type: 'rdp', port: 3390, enabled: false },
];

/** Check if a port is listening on localhost */
function checkPort(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host: '127.0.0.1', port }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.setTimeout(500, () => {
      socket.destroy();
      resolve(false);
    });
  });
}

/**
 * GET /api/trap/status - Get honeypot system status (real check)
 */
export async function handleTrapStatus(_req: IncomingMessage, res: ServerResponse): Promise<void> {
  // Check each trap service port in parallel
  const checks = await Promise.all(
    TRAP_SERVICES.map(async (svc) => {
      const listening = svc.enabled ? await checkPort(svc.port) : false;
      return { ...svc, listening };
    }),
  );

  const activeCount = checks.filter(s => s.listening).length;
  const running = activeCount > 0;

  const status = {
    running,
    services: checks.map(s => ({
      type: s.type,
      port: s.port,
      enabled: s.enabled,
      listening: s.listening,
    })),
    activeServices: activeCount,
    message: running
      ? `${activeCount} honeypot service(s) active`
      : 'No honeypots running. Start with: panguard trap start',
  };

  res.writeHead(200);
  res.end(JSON.stringify({ ok: true, data: status }));
}
