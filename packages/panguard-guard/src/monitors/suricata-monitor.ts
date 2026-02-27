/**
 * SuricataMonitor - Network intrusion detection via Suricata EVE JSON
 * SuricataMonitor - 透過 Suricata EVE JSON 實作的網路入侵偵測
 *
 * Integrates with Suricata's EVE JSON output to provide deep packet
 * inspection (DPI) capabilities. Gracefully degrades when Suricata
 * is not installed (same pattern as FalcoMonitor).
 *
 * @module @panguard-ai/panguard-guard/monitors/suricata-monitor
 */

import { EventEmitter } from 'node:events';
import { createReadStream, existsSync, watchFile, unwatchFile, statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { execFile } from 'node:child_process';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:suricata-monitor');

/** Default Suricata EVE log paths (ordered by preference) */
const SURICATA_EVE_PATHS = [
  '/var/log/suricata/eve.json',
  '/var/log/suricata/fast.json',
  '/usr/local/var/log/suricata/eve.json',
] as const;

/**
 * Raw Suricata EVE JSON alert structure
 */
export interface SuricataEveAlert {
  timestamp: string;
  event_type: string;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  alert?: {
    action?: string;
    gid?: number;
    signature_id?: number;
    rev?: number;
    signature?: string;
    category?: string;
    severity?: number;
    metadata?: Record<string, string[]>;
  };
  flow?: {
    pkts_toserver?: number;
    pkts_toclient?: number;
    bytes_toserver?: number;
    bytes_toclient?: number;
    start?: string;
  };
  app_proto?: string;
  in_iface?: string;
  host?: string;
}

/**
 * Map Suricata severity (1-4) to Panguard severity
 */
function mapSuricataSeverity(severity?: number): Severity {
  if (severity === 1) return 'critical';
  if (severity === 2) return 'high';
  if (severity === 3) return 'medium';
  return 'low';
}

/**
 * Map Suricata alert category to Panguard category
 */
function mapSuricataCategory(category?: string, signature?: string): string {
  if (!category && !signature) return 'unknown';

  const text = `${category ?? ''} ${signature ?? ''}`.toLowerCase();

  // More specific categories first, then general ones
  if (text.includes('c2') || text.includes('command and control') || text.includes('cnc'))
    return 'command_and_control';
  if (text.includes('mining') || text.includes('crypto') || text.includes('stratum'))
    return 'cryptomining';
  if (text.includes('exfil') || text.includes('data leak')) return 'data_exfiltration';
  if (text.includes('shellcode') || text.includes('exploit')) return 'exploit';
  if (text.includes('trojan') || text.includes('malware') || text.includes('backdoor'))
    return 'malware';
  if (text.includes('scan') || text.includes('recon') || text.includes('discovery'))
    return 'reconnaissance';
  if (text.includes('dos') || text.includes('denial')) return 'denial_of_service';
  if (text.includes('credential') || text.includes('brute') || text.includes('login'))
    return 'credential_access';
  if (text.includes('web') || text.includes('sql') || text.includes('xss') || text.includes('rfi'))
    return 'web_attack';
  if (text.includes('policy') || text.includes('not-suspicious')) return 'policy_violation';

  return category ?? 'network_activity';
}

let eventCounter = 0;

/**
 * Parse a raw Suricata EVE JSON alert into a Panguard SecurityEvent
 */
export function parseSuricataEvent(raw: SuricataEveAlert): SecurityEvent | null {
  // Only process alert events
  if (raw.event_type !== 'alert' || !raw.alert) return null;

  eventCounter++;
  const alert = raw.alert;

  return {
    id: `suricata-${Date.now()}-${eventCounter}`,
    timestamp: raw.timestamp ? new Date(raw.timestamp) : new Date(),
    source: 'suricata',
    severity: mapSuricataSeverity(alert.severity),
    category: mapSuricataCategory(alert.category, alert.signature),
    description:
      alert.signature ??
      `Suricata alert: SID ${alert.signature_id ?? 'unknown'}`,
    raw,
    host: raw.host ?? 'unknown',
    metadata: {
      signatureId: alert.signature_id,
      signature: alert.signature,
      alertCategory: alert.category,
      alertAction: alert.action,
      sourceIP: raw.src_ip,
      sourcePort: raw.src_port,
      destIP: raw.dest_ip,
      destPort: raw.dest_port,
      protocol: raw.proto,
      appProto: raw.app_proto,
      interface: raw.in_iface,
    },
  };
}

/**
 * SuricataMonitor watches Suricata EVE JSON output and emits SecurityEvents
 *
 * Usage:
 *   const monitor = new SuricataMonitor();
 *   if (await monitor.checkAvailability()) {
 *     monitor.on('event', (event) => processEvent(event));
 *     await monitor.start();
 *   }
 */
export class SuricataMonitor extends EventEmitter {
  private evePath: string | null = null;
  private running = false;
  private fileOffset = 0;

  /**
   * Check if Suricata is installed and EVE log files are accessible
   */
  async checkAvailability(): Promise<boolean> {
    // Check if suricata binary exists
    const hasBinary = await new Promise<boolean>((resolve) => {
      execFile('which', ['suricata'], (error) => {
        resolve(!error);
      });
    });

    if (hasBinary) {
      logger.info('Suricata binary detected');
    }

    // Check for EVE log file
    for (const path of SURICATA_EVE_PATHS) {
      if (existsSync(path)) {
        this.evePath = path;
        logger.info(`Suricata EVE log found: ${path}`);
        return true;
      }
    }

    // Allow custom path via env
    const customPath = process.env['SURICATA_EVE_PATH'];
    if (customPath && existsSync(customPath)) {
      this.evePath = customPath;
      logger.info(`Suricata EVE log (custom): ${customPath}`);
      return true;
    }

    if (hasBinary) {
      logger.warn(
        'Suricata binary found but no EVE log file. Ensure Suricata is running with eve-log enabled',
      );
      return false;
    }

    logger.info('Suricata not detected, network IDS monitoring disabled (optional)');
    return false;
  }

  /**
   * Start tailing the Suricata EVE log file
   */
  async start(): Promise<void> {
    if (!this.evePath) {
      throw new Error('Suricata EVE log not found. Call checkAvailability() first.');
    }

    if (this.running) return;
    this.running = true;

    // Start from end of file (only read new alerts)
    try {
      const stats = statSync(this.evePath);
      this.fileOffset = stats.size;
    } catch {
      this.fileOffset = 0;
    }

    logger.info(`SuricataMonitor started, tailing ${this.evePath}`);

    // Use polling-based file watch for compatibility
    const evePath = this.evePath;
    watchFile(evePath, { interval: 1000 }, () => {
      this.readNewLines(evePath);
    });
  }

  /**
   * Read new lines from the EVE log since last offset
   */
  private readNewLines(filePath: string): void {
    try {
      const stats = statSync(filePath);
      if (stats.size <= this.fileOffset) {
        // File was truncated or unchanged
        if (stats.size < this.fileOffset) {
          this.fileOffset = 0;
        }
        return;
      }

      const stream = createReadStream(filePath, {
        start: this.fileOffset,
        encoding: 'utf-8',
      });
      const rl = createInterface({ input: stream, crlfDelay: Infinity });

      rl.on('line', (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;

        try {
          const eve = JSON.parse(trimmed) as SuricataEveAlert;
          const event = parseSuricataEvent(eve);
          if (event) {
            this.emit('event', event);
          }
        } catch {
          // Skip non-JSON lines
        }
      });

      rl.on('close', () => {
        this.fileOffset = stats.size;
      });
    } catch (err: unknown) {
      logger.error(`Error reading Suricata EVE log: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Stop monitoring
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    if (this.evePath) {
      unwatchFile(this.evePath);
    }

    logger.info('SuricataMonitor stopped');
  }
}
