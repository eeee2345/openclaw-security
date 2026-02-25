/**
 * osquery Integration Provider - SQL-based system state queries
 * osquery 整合提供者 - 基於 SQL 的系統狀態查詢
 *
 * Provides system discovery via osquery when available, with graceful
 * fallback to the existing shell-based discovery methods.
 * 當 osquery 可用時提供系統偵察，否則優雅降級到現有的 shell 指令方式。
 *
 * @module @openclaw/core/discovery/osquery-provider
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createLogger } from '../utils/logger.js';
import type { PortInfo, UserInfo } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('osquery');

/** osquery process entry */
export interface OsqueryProcess {
  pid: number;
  name: string;
  path: string;
  cmdline: string;
  uid: number;
  state: string;
}

/** osquery listening port entry */
export interface OsqueryListeningPort {
  pid: number;
  port: number;
  protocol: string;
  address: string;
  processName: string;
}

/** osquery logged-in user entry */
export interface OsqueryLoggedInUser {
  user: string;
  host: string;
  time: number;
  tty: string;
  type: string;
}

/**
 * osquery Provider - queries system state via SQL
 * osquery 提供者 - 透過 SQL 查詢系統狀態
 */
export class OsqueryProvider {
  private osqueryPath: string;
  private available: boolean | null = null;

  constructor(osqueryPath: string = 'osqueryi') {
    this.osqueryPath = osqueryPath;
  }

  /**
   * Check if osquery is installed and accessible
   * 檢查 osquery 是否已安裝且可存取
   */
  async isAvailable(): Promise<boolean> {
    if (this.available !== null) return this.available;

    try {
      const { stdout } = await execFileAsync(this.osqueryPath, ['--version'], {
        timeout: 5000,
      });
      this.available = stdout.includes('osquery');
      if (this.available) {
        logger.info(`osquery available: ${stdout.trim()}`);
      }
    } catch {
      this.available = false;
      logger.info('osquery not available, using fallback discovery');
    }

    return this.available;
  }

  /**
   * Execute a SQL query via osqueryi
   * 透過 osqueryi 執行 SQL 查詢
   */
  async query<T>(sql: string): Promise<T[]> {
    if (!(await this.isAvailable())) {
      throw new Error('osquery is not available');
    }

    try {
      const { stdout } = await execFileAsync(
        this.osqueryPath,
        ['--json', sql],
        { timeout: 30000 },
      );

      return JSON.parse(stdout) as T[];
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`osquery query failed: ${msg}`, { sql });
      throw new Error(`osquery query failed: ${msg}`);
    }
  }

  /**
   * Get running processes via osquery
   * 透過 osquery 取得執行中的程序
   */
  async getProcesses(): Promise<OsqueryProcess[]> {
    const rows = await this.query<{
      pid: string;
      name: string;
      path: string;
      cmdline: string;
      uid: string;
      state: string;
    }>('SELECT pid, name, path, cmdline, uid, state FROM processes');

    return rows.map(row => ({
      pid: parseInt(row.pid, 10),
      name: row.name,
      path: row.path,
      cmdline: row.cmdline,
      uid: parseInt(row.uid, 10),
      state: row.state,
    }));
  }

  /**
   * Get listening ports via osquery
   * 透過 osquery 取得監聽 port
   */
  async getListeningPorts(): Promise<OsqueryListeningPort[]> {
    const rows = await this.query<{
      pid: string;
      port: string;
      protocol: string;
      address: string;
      name: string;
    }>(
      'SELECT lp.pid, lp.port, lp.protocol, lp.address, p.name ' +
      'FROM listening_ports lp LEFT JOIN processes p ON lp.pid = p.pid ' +
      'WHERE lp.port > 0'
    );

    return rows.map(row => ({
      pid: parseInt(row.pid, 10),
      port: parseInt(row.port, 10),
      protocol: row.protocol === '6' ? 'tcp' : row.protocol === '17' ? 'udp' : row.protocol,
      address: row.address,
      processName: row.name ?? 'unknown',
    }));
  }

  /**
   * Convert osquery ports to PortInfo format (matching existing discovery types)
   * 將 osquery port 轉換為 PortInfo 格式
   */
  async getPortsAsPortInfo(): Promise<PortInfo[]> {
    const ports = await this.getListeningPorts();
    return ports.map(p => ({
      port: p.port,
      protocol: p.protocol as 'tcp' | 'udp',
      state: 'LISTEN',
      service: p.processName,
      pid: p.pid,
    }));
  }

  /**
   * Get user list via osquery
   * 透過 osquery 取得用戶列表
   */
  async getUsers(): Promise<UserInfo[]> {
    const rows = await this.query<{
      uid: string;
      gid: string;
      username: string;
      description: string;
      shell: string;
      directory: string;
    }>('SELECT uid, gid, username, description, shell, directory FROM users');

    return rows.map(row => ({
      username: row.username,
      uid: parseInt(row.uid, 10),
      gid: parseInt(row.gid, 10),
      home: row.directory,
      shell: row.shell,
      groups: [],
      isAdmin: parseInt(row.uid, 10) === 0,
      lastLogin: undefined,
    }));
  }

  /**
   * Get currently logged-in users via osquery
   * 透過 osquery 取得目前登入的用戶
   */
  async getLoggedInUsers(): Promise<OsqueryLoggedInUser[]> {
    const rows = await this.query<{
      user: string;
      host: string;
      time: string;
      tty: string;
      type: string;
    }>('SELECT user, host, time, tty, type FROM logged_in_users');

    return rows.map(row => ({
      user: row.user,
      host: row.host,
      time: parseInt(row.time, 10),
      tty: row.tty,
      type: row.type,
    }));
  }

  /**
   * Get system info via osquery
   * 透過 osquery 取得系統資訊
   */
  async getSystemInfo(): Promise<Record<string, string>> {
    const rows = await this.query<Record<string, string>>(
      'SELECT hostname, computer_name, cpu_brand, cpu_type, ' +
      'physical_memory, hardware_vendor, hardware_model FROM system_info'
    );
    return rows[0] ?? {};
  }

  /**
   * Get OS version via osquery
   * 透過 osquery 取得作業系統版本
   */
  async getOSVersion(): Promise<Record<string, string>> {
    const rows = await this.query<Record<string, string>>(
      'SELECT name, version, major, minor, patch, build, platform FROM os_version'
    );
    return rows[0] ?? {};
  }

  /**
   * Check for kernel modules (Linux) or kexts (macOS)
   * 檢查核心模組
   */
  async getKernelModules(): Promise<Array<{ name: string; size: string; status: string }>> {
    try {
      const rows = await this.query<{
        name: string;
        size: string;
        status: string;
      }>('SELECT name, size, status FROM kernel_modules');
      return rows;
    } catch {
      // Not all platforms support this table
      return [];
    }
  }

  /**
   * Get network interfaces via osquery
   * 透過 osquery 取得網路介面
   */
  async getInterfaces(): Promise<Array<{
    interface: string;
    address: string;
    mask: string;
    type: string;
  }>> {
    const rows = await this.query<{
      interface: string;
      address: string;
      mask: string;
      type: string;
    }>(
      'SELECT ia.interface, ia.address, ia.mask, id.type ' +
      'FROM interface_addresses ia ' +
      'JOIN interface_details id ON ia.interface = id.interface ' +
      'WHERE ia.address != "" AND ia.address != "::1" AND ia.address != "127.0.0.1"'
    );
    return rows;
  }

  /**
   * Run a custom security audit query
   * 執行自訂安全稽核查詢
   */
  async securityAudit(): Promise<{
    suidBinaries: number;
    listeningPorts: number;
    loggedInUsers: number;
    totalProcesses: number;
  }> {
    const [ports, users, processes] = await Promise.all([
      this.getListeningPorts().catch(() => []),
      this.getLoggedInUsers().catch(() => []),
      this.getProcesses().catch(() => []),
    ]);

    return {
      suidBinaries: 0, // Would need platform-specific query
      listeningPorts: ports.length,
      loggedInUsers: users.length,
      totalProcesses: processes.length,
    };
  }
}

/**
 * Create an OsqueryProvider with availability check
 * 建立帶可用性檢查的 OsqueryProvider
 *
 * Returns the provider if osquery is available, null otherwise.
 */
export async function createOsqueryProvider(
  osqueryPath?: string,
): Promise<OsqueryProvider | null> {
  const provider = new OsqueryProvider(osqueryPath);
  const available = await provider.isAvailable();
  return available ? provider : null;
}
