/**
 * User account auditor
 * 使用者帳號稽核
 *
 * Audits local user accounts to identify administrators, inactive accounts,
 * and other user-related security concerns across macOS, Linux, and Windows.
 * 稽核本地使用者帳號以識別管理員、非活躍帳號和其他跨 macOS、Linux 和 Windows 的使用者相關安全問題。
 *
 * @module @panguard-ai/core/discovery/user-auditor
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { platform as osPlatform } from 'os';
import { readFile } from 'fs/promises';
import { createLogger } from '../utils/logger.js';
import type { UserInfo } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('discovery:users');

/**
 * Safely execute a command and return stdout, or empty string on failure
 * 安全地執行命令並回傳 stdout，失敗時回傳空字串
 *
 * @param cmd - Command to execute / 要執行的命令
 * @param args - Command arguments / 命令參數
 * @returns stdout output trimmed / 修剪後的 stdout 輸出
 */
async function safeExec(cmd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, { timeout: 10_000 });
    return stdout.trim();
  } catch (err) {
    logger.debug(`Command failed: ${cmd} ${args.join(' ')}`, {
      error: err instanceof Error ? err.message : String(err),
    });
    return '';
  }
}

/**
 * Audit user accounts on macOS via dscl (Directory Service command line)
 * 透過 dscl（目錄服務命令列）稽核 macOS 上的使用者帳號
 *
 * @returns Array of user info / 使用者資訊陣列
 */
async function auditMacOSUsers(): Promise<UserInfo[]> {
  const users: UserInfo[] = [];

  // Get list of all users
  // 取得所有使用者列表
  const userListOutput = await safeExec('dscl', ['.', '-list', '/Users']);
  if (!userListOutput) {
    logger.warn('dscl list returned no output');
    return users;
  }

  // Get admin group members
  // 取得管理員群組成員
  const adminGroupOutput = await safeExec('dscl', [
    '.',
    '-read',
    '/Groups/admin',
    'GroupMembership',
  ]);
  const adminUsers = new Set<string>();
  if (adminGroupOutput) {
    const match = adminGroupOutput.match(/GroupMembership:\s*(.+)/);
    if (match?.[1]) {
      match[1]
        .trim()
        .split(/\s+/)
        .forEach((u) => adminUsers.add(u));
    }
  }

  const usernames = userListOutput
    .split('\n')
    .map((u) => u.trim())
    .filter(Boolean);

  for (const username of usernames) {
    // Skip system accounts (those starting with _)
    // 跳過系統帳號（以 _ 開頭的）
    if (username.startsWith('_')) continue;
    // Skip daemon, nobody, root-like system users on macOS
    // 跳過 macOS 上的 daemon、nobody、root 類似系統使用者
    if (username === 'daemon' || username === 'nobody') continue;

    const userDetail = await safeExec('dscl', ['.', '-read', `/Users/${username}`]);
    if (!userDetail) continue;

    // Extract UID
    // 擷取 UID
    let uid: string | undefined;
    const uidMatch = userDetail.match(/UniqueID:\s*(\d+)/);
    if (uidMatch?.[1]) {
      uid = uidMatch[1];
      // Skip system accounts with UID < 500 (except root=0)
      // 跳過 UID < 500 的系統帳號（root=0 除外）
      const uidNum = parseInt(uid, 10);
      if (uidNum > 0 && uidNum < 500) continue;
    }

    // Extract shell
    // 擷取 shell
    let shell: string | undefined;
    const shellMatch = userDetail.match(/UserShell:\s*(\S+)/);
    if (shellMatch?.[1]) {
      shell = shellMatch[1];
      // Skip users with /usr/bin/false or /sbin/nologin shells (non-interactive)
      // 跳過使用 /usr/bin/false 或 /sbin/nologin 的使用者（非互動式）
      if (shell === '/usr/bin/false' || shell === '/sbin/nologin') continue;
    }

    // Get last login info
    // 取得上次登入資訊
    let lastLogin: string | undefined;
    const lastOutput = await safeExec('last', ['-1', username]);
    if (lastOutput && !lastOutput.includes('wtmp begins')) {
      const firstLine = lastOutput.split('\n')[0];
      if (firstLine && firstLine.includes(username)) {
        // Extract the date portion from last output
        // 從 last 輸出擷取日期部分
        const dateParts = firstLine.trim().split(/\s+/).slice(2, 6);
        lastLogin = dateParts.join(' ') || undefined;
      }
    }

    users.push({
      username,
      uid,
      isAdmin: adminUsers.has(username),
      lastLogin,
      passwordAge: undefined,
      shell,
    });
  }

  return users;
}

/**
 * Audit user accounts on Linux via /etc/passwd and /etc/group
 * 透過 /etc/passwd 和 /etc/group 稽核 Linux 上的使用者帳號
 *
 * @returns Array of user info / 使用者資訊陣列
 */
async function auditLinuxUsers(): Promise<UserInfo[]> {
  const users: UserInfo[] = [];

  // Read /etc/passwd
  // 讀取 /etc/passwd
  let passwdContent: string;
  try {
    passwdContent = await readFile('/etc/passwd', 'utf-8');
  } catch {
    logger.warn('Could not read /etc/passwd');
    return users;
  }

  // Determine admin groups (sudo, wheel, admin)
  // 判斷管理員群組（sudo、wheel、admin）
  const adminUsers = new Set<string>();

  // Check root is always admin
  // root 始終是管理員
  adminUsers.add('root');

  try {
    const groupContent = await readFile('/etc/group', 'utf-8');
    const groupLines = groupContent.split('\n');

    for (const line of groupLines) {
      const parts = line.split(':');
      if (parts.length < 4) continue;

      const groupName = parts[0] ?? '';
      const membersStr = parts[3] ?? '';
      const members = membersStr
        .split(',')
        .map((m) => m.trim())
        .filter(Boolean);

      // sudo, wheel, and admin groups grant admin privileges
      // sudo、wheel 和 admin 群組授予管理員權限
      if (groupName === 'sudo' || groupName === 'wheel' || groupName === 'admin') {
        members.forEach((m) => adminUsers.add(m));
      }
    }
  } catch {
    logger.warn('Could not read /etc/group');
  }

  const passwdLines = passwdContent.split('\n');

  for (const line of passwdLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Format: username:password:uid:gid:gecos:home:shell
    // 格式：username:password:uid:gid:gecos:home:shell
    const parts = trimmed.split(':');
    if (parts.length < 7) continue;

    const username = parts[0] ?? '';
    const uid = parts[2] ?? '';
    const shell = parts[6] ?? '';
    if (!username) continue;

    const uidNum = parseInt(uid, 10);

    // Filter: include root (0) and regular users (typically UID >= 1000)
    // 過濾：包含 root (0) 和一般使用者（通常 UID >= 1000）
    if (uidNum !== 0 && uidNum < 1000) continue;

    // Skip users with nologin/false shells (non-interactive)
    // 跳過使用 nologin/false shell 的使用者（非互動式）
    if (
      shell === '/usr/sbin/nologin' ||
      shell === '/sbin/nologin' ||
      shell === '/bin/false' ||
      shell === '/usr/bin/false'
    ) {
      continue;
    }

    // Get last login info
    // 取得上次登入資訊
    let lastLogin: string | undefined;
    const lastOutput = await safeExec('last', ['-1', username]);
    if (lastOutput && !lastOutput.includes('wtmp begins') && lastOutput.trim()) {
      const firstLine = lastOutput.split('\n')[0];
      if (firstLine && firstLine.includes(username)) {
        const dateParts = firstLine.trim().split(/\s+/).slice(2, 6);
        const joined = dateParts.join(' ');
        lastLogin = joined || undefined;
      }
    }

    // Try to get password age from /etc/shadow (requires root)
    // 嘗試從 /etc/shadow 取得密碼使用天數（需要 root 權限）
    let passwordAge: number | undefined;
    const chageOutput = await safeExec('chage', ['-l', username]);
    if (chageOutput) {
      const lastChangeMatch = chageOutput.match(/Last password change\s*:\s*(.+)/);
      if (lastChangeMatch?.[1]) {
        const changeDate = new Date(lastChangeMatch[1].trim());
        if (!isNaN(changeDate.getTime())) {
          passwordAge = Math.floor((Date.now() - changeDate.getTime()) / (1000 * 60 * 60 * 24));
        }
      }
    }

    users.push({
      username,
      uid: uid || undefined,
      isAdmin: adminUsers.has(username),
      lastLogin,
      passwordAge,
      shell: shell || undefined,
    });
  }

  return users;
}

/**
 * Audit user accounts on Windows via net user
 * 透過 net user 稽核 Windows 上的使用者帳號
 *
 * @returns Array of user info / 使用者資訊陣列
 */
async function auditWindowsUsers(): Promise<UserInfo[]> {
  const users: UserInfo[] = [];

  // Get list of administrators
  // 取得管理員列表
  const adminOutput = await safeExec('net', ['localgroup', 'administrators']);
  const adminUsers = new Set<string>();

  if (adminOutput) {
    const lines = adminOutput.split('\n');
    let inMemberSection = false;

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed.startsWith('---')) {
        inMemberSection = true;
        continue;
      }

      if (trimmed.startsWith('The command completed')) {
        break;
      }

      if (inMemberSection && trimmed) {
        adminUsers.add(trimmed.toLowerCase());
      }
    }
  }

  // Get all users
  // 取得所有使用者
  const userListOutput = await safeExec('net', ['user']);

  if (!userListOutput) {
    logger.warn('net user returned no output');
    return users;
  }

  // Parse user list - net user shows users in columns
  // 解析使用者列表 - net user 以欄位顯示使用者
  const lines = userListOutput.split('\n');
  const usernames: string[] = [];

  let inUserSection = false;
  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith('---')) {
      inUserSection = true;
      continue;
    }

    if (trimmed.startsWith('The command completed')) {
      break;
    }

    if (inUserSection && trimmed) {
      // Users are listed separated by spaces, multiple per line
      // 使用者以空格分隔列出，每行可能多個
      const names = trimmed.split(/\s{2,}/);
      for (const name of names) {
        const n = name.trim();
        if (n) usernames.push(n);
      }
    }
  }

  // Get detailed info for each user
  // 取得每個使用者的詳細資訊
  for (const username of usernames) {
    const detailOutput = await safeExec('net', ['user', username]);

    let lastLogin: string | undefined;
    let passwordAge: number | undefined;

    if (detailOutput) {
      const lastLogonMatch = detailOutput.match(/Last logon\s*(.+)/i);
      if (lastLogonMatch?.[1]) {
        const dateStr = lastLogonMatch[1].trim();
        if (dateStr !== 'Never') {
          lastLogin = dateStr;
        }
      }

      const passwordLastSetMatch = detailOutput.match(/Password last set\s*(.+)/i);
      if (passwordLastSetMatch?.[1]) {
        const dateStr = passwordLastSetMatch[1].trim();
        const setDate = new Date(dateStr);
        if (!isNaN(setDate.getTime())) {
          passwordAge = Math.floor((Date.now() - setDate.getTime()) / (1000 * 60 * 60 * 24));
        }
      }
    }

    users.push({
      username,
      uid: undefined,
      isAdmin: adminUsers.has(username.toLowerCase()),
      lastLogin,
      passwordAge,
      shell: undefined,
    });
  }

  return users;
}

/**
 * Audit all local user accounts on the current platform
 * 稽核目前平台上所有本地使用者帳號
 *
 * Dispatches to platform-specific auditing methods:
 * - macOS: dscl . -list /Users + dscl . -read /Users/username
 * - Linux: /etc/passwd + /etc/group
 * - Windows: net user + net localgroup administrators
 * 分派到平台特定的稽核方法：
 * - macOS：dscl . -list /Users + dscl . -read /Users/username
 * - Linux：/etc/passwd + /etc/group
 * - Windows：net user + net localgroup administrators
 *
 * @returns Array of audited user accounts / 已稽核的使用者帳號陣列
 */
export async function auditUsers(): Promise<UserInfo[]> {
  const currentPlatform = osPlatform();

  logger.info(`Auditing users on ${currentPlatform}`);

  try {
    let users: UserInfo[] = [];

    switch (currentPlatform) {
      case 'darwin':
        users = await auditMacOSUsers();
        break;
      case 'linux':
        users = await auditLinuxUsers();
        break;
      case 'win32':
        users = await auditWindowsUsers();
        break;
      default:
        logger.warn(`Unsupported platform for user audit: ${currentPlatform}`);
        return [];
    }

    const adminCount = users.filter((u) => u.isAdmin).length;
    logger.info(`Audited ${users.length} users (${adminCount} admins)`);
    return users;
  } catch (err) {
    logger.error('User audit failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}
