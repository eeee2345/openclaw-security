/**
 * Panguard MCP - Guard Tools
 * Panguard MCP - 守護工具
 *
 * Implements panguard_guard_start, panguard_guard_stop, panguard_status,
 * and panguard_alerts MCP tools.
 * 實作 panguard_guard_start、panguard_guard_stop、panguard_status 和 panguard_alerts MCP 工具。
 *
 * @module @panguard-ai/panguard-mcp/tools/guard-tools
 */

import { promises as fs, existsSync, readFileSync, openSync, closeSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';

/**
 * Resolve the guard data directory from args or default.
 * 從參數或預設值解析守護資料目錄。
 */
function resolveDataDir(args: Record<string, unknown>): string {
  return (args['dataDir'] as string) ?? path.join(os.homedir(), '.panguard-guard');
}

/**
 * Execute panguard_guard_start — start the real-time threat monitoring daemon.
 * 執行 panguard_guard_start — 啟動即時威脅監控常駐程式。
 *
 * Spawns the guard daemon as a detached background process with stdio
 * redirected to a log file, so it does not interfere with MCP stdio transport.
 * 將守護常駐程式作為分離的背景進程啟動，stdio 重導向到日誌檔案。
 */
export async function executeGuardStart(args: Record<string, unknown>) {
  const dataDir = resolveDataDir(args);
  const mode = (args['mode'] as string) ?? 'learning';

  try {
    await fs.mkdir(dataDir, { recursive: true });
  } catch {
    // Directory may already exist
  }

  // Check if guard is already running
  const pidFile = path.join(dataDir, 'panguard-guard.pid');
  try {
    const pidContent = await fs.readFile(pidFile, 'utf-8');
    const existingPid = parseInt(pidContent.trim(), 10);
    if (!isNaN(existingPid)) {
      try {
        process.kill(existingPid, 0);
        // Process exists — guard is already running
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  status: 'already_running',
                  pid: existingPid,
                  dataDir,
                  mode,
                  message: `Guard engine is already running (PID: ${existingPid}).`,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch {
        // Process not found — stale PID file, continue to start
        await fs.unlink(pidFile).catch(() => undefined);
      }
    }
  } catch {
    // No PID file — proceed to start
  }

  // Resolve the panguard-guard CLI script path
  let guardCliScript: string;
  try {
    const _require = createRequire(import.meta.url);
    const guardMainPath = _require.resolve('@panguard-ai/panguard-guard');
    guardCliScript = path.join(path.dirname(guardMainPath), 'cli', 'index.js');
  } catch {
    // Fallback: try resolving via import.meta.resolve
    try {
      const guardMainUrl = import.meta.resolve('@panguard-ai/panguard-guard');
      guardCliScript = path.join(fileURLToPath(guardMainUrl), '..', 'cli', 'index.js');
    } catch {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                status: 'error',
                message: 'Could not resolve @panguard-ai/panguard-guard package. Is it installed?',
              },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }
  }

  // Spawn guard as a detached background process
  const logPath = path.join(dataDir, 'guard.log');
  let logFd: number;
  try {
    logFd = openSync(logPath, 'a');
  } catch (err) {
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              status: 'error',
              message: `Failed to open log file: ${err instanceof Error ? err.message : String(err)}`,
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }

  try {
    const child = spawn(process.execPath, [guardCliScript, 'start'], {
      detached: true,
      stdio: ['ignore', logFd, logFd],
      env: { ...process.env },
    });
    child.unref();
    closeSync(logFd);

    // Wait for PID file to confirm startup (up to 5 seconds)
    let started = false;
    let newPid: number | null = null;
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      if (existsSync(pidFile)) {
        try {
          const content = readFileSync(pidFile, 'utf-8').trim();
          const parsed = parseInt(content, 10);
          if (!isNaN(parsed)) {
            process.kill(parsed, 0);
            started = true;
            newPid = parsed;
            break;
          }
        } catch {
          // Not ready yet
        }
      }
      await new Promise((r) => setTimeout(r, 300));
    }

    if (started) {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                status: 'started',
                pid: newPid,
                dataDir,
                mode,
                logFile: logPath,
                message: `Guard engine started successfully (PID: ${newPid}).`,
              },
              null,
              2,
            ),
          },
        ],
      };
    } else {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                status: 'timeout',
                dataDir,
                mode,
                logFile: logPath,
                message: 'Guard engine was spawned but did not confirm startup within 5 seconds. Check the log file for details.',
              },
              null,
              2,
            ),
          },
        ],
      };
    }
  } catch (err) {
    closeSync(logFd);
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              status: 'error',
              message: `Failed to spawn guard process: ${err instanceof Error ? err.message : String(err)}`,
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }
}

/**
 * Execute panguard_guard_stop — stop the real-time threat monitoring daemon.
 * 執行 panguard_guard_stop — 停止即時威脅監控常駐程式。
 */
export async function executeGuardStop(args: Record<string, unknown>) {
  const dataDir = resolveDataDir(args);
  const pidFile = path.join(dataDir, 'guard.pid');

  let pid: number | null = null;
  let stopped = false;

  try {
    const pidContent = await fs.readFile(pidFile, 'utf-8');
    pid = parseInt(pidContent.trim(), 10);

    if (!isNaN(pid)) {
      try {
        process.kill(pid, 'SIGTERM');
        stopped = true;
        // Remove stale PID file
        await fs.unlink(pidFile).catch(() => undefined);
      } catch {
        // Process not running — clean up stale PID file
        await fs.unlink(pidFile).catch(() => undefined);
        stopped = false;
      }
    }
  } catch {
    // No PID file found
  }

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(
          {
            status: stopped ? 'stopped' : 'not_running',
            pid,
            message: stopped
              ? `Guard engine (PID: ${pid}) has been sent SIGTERM.`
              : 'Guard engine was not running (no PID file found).',
          },
          null,
          2,
        ),
      },
    ],
  };
}

/**
 * Execute panguard_status — get current status of all Panguard services.
 * 執行 panguard_status — 取得所有 Panguard 服務的當前狀態。
 */
export async function executeStatus(args: Record<string, unknown>) {
  const dataDir = resolveDataDir(args);
  const pidFile = path.join(dataDir, 'guard.pid');

  let isRunning = false;
  let pid: number | null = null;

  try {
    const pidContent = await fs.readFile(pidFile, 'utf-8');
    pid = parseInt(pidContent.trim(), 10);
    if (!isNaN(pid)) {
      // Sending signal 0 checks if process exists without killing it
      process.kill(pid, 0);
      isRunning = true;
    }
  } catch {
    isRunning = false;
  }

  // Try to read guard config
  let config: Record<string, unknown> = {};
  try {
    const configPath = path.join(dataDir, 'config.json');
    const configContent = await fs.readFile(configPath, 'utf-8');
    config = JSON.parse(configContent) as Record<string, unknown>;
  } catch {
    // No config file yet
  }

  // Count recent events as a proxy for threat activity
  let eventCount = 0;
  try {
    const eventsFile = path.join(dataDir, 'events.jsonl');
    const content = await fs.readFile(eventsFile, 'utf-8');
    eventCount = content.trim().split('\n').filter(Boolean).length;
  } catch {
    // No events file
  }

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(
          {
            guard: {
              running: isRunning,
              pid,
              dataDir,
              mode: config['mode'] ?? 'unknown',
              lang: config['lang'] ?? 'en',
            },
            events: {
              total_logged: eventCount,
            },
            summary: isRunning
              ? `Panguard Guard is RUNNING (PID: ${pid}, mode: ${config['mode'] ?? 'unknown'}).`
              : 'Panguard Guard is NOT running. Use panguard_guard_start to start it.',
          },
          null,
          2,
        ),
      },
    ],
  };
}

/**
 * Execute panguard_alerts — get recent security alerts from guard event log.
 * 執行 panguard_alerts — 從守護事件日誌取得近期安全告警。
 */
export async function executeAlerts(args: Record<string, unknown>) {
  const limit = (args['limit'] as number) ?? 20;
  const severity = (args['severity'] as string) ?? 'all';
  const dataDir = resolveDataDir(args);

  const eventsFile = path.join(dataDir, 'events.jsonl');
  const alerts: unknown[] = [];

  try {
    const content = await fs.readFile(eventsFile, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);

    for (const line of lines) {
      try {
        const event = JSON.parse(line) as Record<string, unknown>;
        if (severity === 'all' || event['severity'] === severity) {
          alerts.push(event);
        }
      } catch {
        // Skip malformed JSONL lines
      }
    }
  } catch {
    // No events file yet — guard may not have started
  }

  // Return the most recent `limit` alerts
  const recentAlerts = alerts.slice(-Math.max(1, limit));

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(
          {
            total_alerts: recentAlerts.length,
            filter: { severity, limit },
            alerts: recentAlerts,
            summary:
              recentAlerts.length === 0
                ? 'No recent alerts. System appears clean.'
                : `${recentAlerts.length} recent alert(s) detected.`,
          },
          null,
          2,
        ),
      },
    ],
  };
}
