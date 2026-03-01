/**
 * Compliance Assessors - Active system assessment for compliance controls
 * 合規評估器 - 主動評估系統狀態以判定合規控制項
 *
 * Each assessor checks real system state and generates ComplianceFinding objects.
 * The assessors run actual system commands (same approach as panguard-scan).
 *
 * @module @panguard-ai/panguard-report/assessors
 */

import { execFile } from 'node:child_process';
import { platform } from 'node:os';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { createLogger } from '@panguard-ai/core';
import type { ComplianceFinding } from '../types.js';

const logger = createLogger('panguard-report:assessors');

const os = platform();

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function execPromise(cmd: string, args: string[], timeout = 10000): Promise<string> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout }, (error, stdout) => {
      resolve(error ? '' : stdout.trim());
    });
  });
}

function makeFinding(
  id: string,
  severity: ComplianceFinding['severity'],
  title: string,
  description: string,
  category: string
): ComplianceFinding {
  return {
    findingId: id,
    severity,
    title,
    description,
    category,
    timestamp: new Date(),
    source: 'panguard-scan',
  };
}

// ---------------------------------------------------------------------------
// Access Control Assessor
// ---------------------------------------------------------------------------

export async function assessAccessControl(): Promise<ComplianceFinding[]> {
  const findings: ComplianceFinding[] = [];

  // Check password policy
  try {
    if (os === 'linux') {
      const pwquality = existsSync('/etc/security/pwquality.conf')
        ? readFileSync('/etc/security/pwquality.conf', 'utf-8')
        : '';
      const pamPassword = existsSync('/etc/pam.d/common-password')
        ? readFileSync('/etc/pam.d/common-password', 'utf-8')
        : '';

      const minLen = pwquality.match(/minlen\s*=\s*(\d+)/);
      const length = minLen ? parseInt(minLen[1]!, 10) : 0;

      if (length < 8) {
        findings.push(
          makeFinding(
            'AC-PWD-001',
            'high',
            'Weak password policy',
            `Minimum password length is ${length || 'not set'} (should be >= 12). /etc/security/pwquality.conf minlen is inadequate.`,
            'password'
          )
        );
      }

      if (!pamPassword.includes('pam_pwquality') && !pwquality.includes('minlen')) {
        findings.push(
          makeFinding(
            'AC-PWD-002',
            'medium',
            'Password quality module not enforced',
            'pam_pwquality is not configured in PAM. Password complexity is not enforced.',
            'password'
          )
        );
      }
    } else if (os === 'darwin') {
      const policy = await execPromise('/usr/bin/pwpolicy', ['getaccountpolicies']);
      if (!policy.includes('policyAttributePassword')) {
        findings.push(
          makeFinding(
            'AC-PWD-003',
            'medium',
            'No password policy configured',
            'macOS password policy is not configured via pwpolicy.',
            'password'
          )
        );
      }
    }
  } catch {
    logger.warn('Password policy check failed');
  }

  // Check for accounts without passwords (Linux)
  if (os === 'linux') {
    try {
      const shadow = existsSync('/etc/shadow') ? readFileSync('/etc/shadow', 'utf-8') : '';
      const emptyPasswords = shadow
        .split('\n')
        .filter((line) => {
          const parts = line.split(':');
          return parts[1] === '' || parts[1] === '!';
        })
        .map((line) => line.split(':')[0]);

      if (emptyPasswords.length > 0) {
        findings.push(
          makeFinding(
            'AC-PWD-004',
            'critical',
            'Accounts without passwords',
            `Found ${emptyPasswords.length} account(s) with empty or disabled passwords: ${emptyPasswords.slice(0, 5).join(', ')}`,
            'authentication'
          )
        );
      }
    } catch {
      // May not have permission to read shadow
    }
  }

  // Check sudo configuration
  if (os !== 'win32') {
    try {
      const sudoers = existsSync('/etc/sudoers') ? readFileSync('/etc/sudoers', 'utf-8') : '';
      if (sudoers.includes('NOPASSWD: ALL')) {
        findings.push(
          makeFinding(
            'AC-SUDO-001',
            'high',
            'NOPASSWD sudo access found',
            'One or more users have NOPASSWD:ALL in sudoers, allowing passwordless root access.',
            'access'
          )
        );
      }
    } catch {
      // May not have permission
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Firewall & Network Assessor
// ---------------------------------------------------------------------------

export async function assessFirewallAndNetwork(): Promise<ComplianceFinding[]> {
  const findings: ComplianceFinding[] = [];

  // Check firewall status
  try {
    if (os === 'darwin') {
      const fwStatus = await execPromise('/usr/libexec/ApplicationFirewall/socketfilterfw', [
        '--getglobalstate',
      ]);
      if (fwStatus.includes('disabled')) {
        findings.push(
          makeFinding(
            'FW-001',
            'high',
            'Firewall disabled',
            'macOS Application Firewall is disabled. System is exposed to inbound connections.',
            'firewall'
          )
        );
      }
    } else if (os === 'linux') {
      const iptables = await execPromise('/sbin/iptables', ['-L', '-n']);
      const ufw = await execPromise('/usr/sbin/ufw', ['status']);

      const hasRules = iptables.split('\n').length > 8; // More than default chain headers
      const ufwActive = ufw.includes('active');

      if (!hasRules && !ufwActive) {
        findings.push(
          makeFinding(
            'FW-002',
            'high',
            'No firewall rules configured',
            'Neither iptables rules nor UFW are active. System has no inbound traffic filtering.',
            'firewall'
          )
        );
      }
    }
  } catch {
    logger.warn('Firewall status check failed');
  }

  // Check for exposed services on common risky ports
  try {
    let openPorts: string[] = [];
    if (os === 'darwin') {
      const lsof = await execPromise('/usr/sbin/lsof', ['-iTCP', '-sTCP:LISTEN', '-P', '-n']);
      openPorts = lsof
        .split('\n')
        .filter((l) => l.includes('LISTEN'))
        .map((l) => {
          const match = l.match(/:(\d+)\s/);
          return match ? match[1]! : '';
        })
        .filter(Boolean);
    } else if (os === 'linux') {
      const ss = await execPromise('/usr/bin/ss', ['-tlnp']);
      openPorts = ss
        .split('\n')
        .filter((l) => l.includes('LISTEN'))
        .map((l) => {
          const match = l.match(/:(\d+)\s/);
          return match ? match[1]! : '';
        })
        .filter(Boolean);
    }

    const riskyPorts: Record<string, string> = {
      '21': 'FTP',
      '23': 'Telnet',
      '445': 'SMB',
      '3306': 'MySQL',
      '5432': 'PostgreSQL',
      '6379': 'Redis',
      '27017': 'MongoDB',
      '11211': 'Memcached',
    };

    const exposedRisky = openPorts.filter((p) => riskyPorts[p]);
    if (exposedRisky.length > 0) {
      const services = exposedRisky.map((p) => `${riskyPorts[p]} (${p})`).join(', ');
      findings.push(
        makeFinding(
          'NET-PORT-001',
          'high',
          'Risky services exposed',
          `The following services are listening on network interfaces: ${services}. These should be firewalled or disabled.`,
          'network'
        )
      );
    }
  } catch {
    logger.warn('Open port check failed');
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Encryption & Certificate Assessor
// ---------------------------------------------------------------------------

export async function assessEncryption(): Promise<ComplianceFinding[]> {
  const findings: ComplianceFinding[] = [];

  // Check disk encryption
  try {
    if (os === 'darwin') {
      const fdesetup = await execPromise('/usr/bin/fdesetup', ['status']);
      if (!fdesetup.includes('On')) {
        findings.push(
          makeFinding(
            'ENC-DISK-001',
            'high',
            'Disk encryption not enabled',
            'FileVault is not enabled. Data at rest is not encrypted.',
            'encryption'
          )
        );
      }
    } else if (os === 'linux') {
      const lsblk = await execPromise('/bin/lsblk', ['-o', 'NAME,TYPE,FSTYPE']);
      if (!lsblk.includes('crypt') && !lsblk.includes('luks')) {
        findings.push(
          makeFinding(
            'ENC-DISK-002',
            'medium',
            'No LUKS encryption detected',
            'No LUKS-encrypted partitions found. Data at rest may not be encrypted.',
            'encryption'
          )
        );
      }
    }
  } catch {
    logger.warn('Disk encryption check failed');
  }

  // Check SSH key security
  try {
    const sshDir = `${process.env['HOME']}/.ssh`;
    if (existsSync(sshDir)) {
      const files = readdirSync(sshDir);
      const privateKeys = files.filter(
        (f) => f.startsWith('id_') && !f.endsWith('.pub') && !f.includes('known_hosts')
      );

      for (const keyFile of privateKeys) {
        const keyPath = `${sshDir}/${keyFile}`;
        try {
          const content = readFileSync(keyPath, 'utf-8');
          if (content.includes('BEGIN RSA PRIVATE KEY') && !content.includes('ENCRYPTED')) {
            findings.push(
              makeFinding(
                `ENC-SSH-${keyFile}`,
                'medium',
                `Unencrypted SSH private key: ${keyFile}`,
                `SSH private key ${keyPath} is not passphrase-protected.`,
                'encryption'
              )
            );
          }
        } catch {
          // Permission denied is fine
        }
      }
    }
  } catch {
    logger.warn('SSH key check failed');
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Monitoring & Logging Assessor
// ---------------------------------------------------------------------------

export async function assessMonitoring(): Promise<ComplianceFinding[]> {
  const findings: ComplianceFinding[] = [];

  // Check syslog / journald
  try {
    if (os === 'linux') {
      const journalctl = await execPromise('/bin/journalctl', ['--disk-usage']);
      if (!journalctl || journalctl.includes('No journal files')) {
        findings.push(
          makeFinding(
            'MON-LOG-001',
            'high',
            'No system logging configured',
            'journald has no journal files. System events are not being recorded.',
            'logging'
          )
        );
      }
    } else if (os === 'darwin') {
      // macOS always has system logging via unified log
      const logStats = await execPromise('/usr/bin/log', ['stats']);
      if (!logStats) {
        findings.push(
          makeFinding(
            'MON-LOG-002',
            'medium',
            'System logging may be impaired',
            'Could not verify macOS unified log status.',
            'logging'
          )
        );
      }
    }
  } catch {
    logger.warn('Logging check failed');
  }

  // Check if audit daemon is running (Linux)
  if (os === 'linux') {
    try {
      const auditd = await execPromise('/bin/systemctl', ['is-active', 'auditd']);
      if (auditd !== 'active') {
        findings.push(
          makeFinding(
            'MON-AUDIT-001',
            'medium',
            'Audit daemon not active',
            'auditd is not running. System call auditing is not enabled.',
            'audit'
          )
        );
      }
    } catch {
      // auditd may not be installed
    }
  }

  // Check if Panguard Guard is running
  try {
    const processes = await execPromise(os === 'win32' ? 'tasklist' : '/bin/ps', [
      os === 'win32' ? '/FI' : 'aux',
      ...(os === 'win32' ? ['"IMAGENAME eq node.exe"'] : []),
    ]);
    if (!processes.includes('panguard') && !processes.includes('guard')) {
      findings.push(
        makeFinding(
          'MON-GUARD-001',
          'medium',
          'Panguard Guard not running',
          'Panguard Guard monitoring daemon is not detected. Real-time threat monitoring is inactive.',
          'monitoring'
        )
      );
    }
  } catch {
    logger.warn('Process check failed');
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Vulnerability & Patch Assessment
// ---------------------------------------------------------------------------

export async function assessPatching(): Promise<ComplianceFinding[]> {
  const findings: ComplianceFinding[] = [];

  // Check for available system updates
  try {
    if (os === 'darwin') {
      const updates = await execPromise('/usr/sbin/softwareupdate', ['-l'], 30000);
      const updateCount = (updates.match(/\*/g) || []).length;
      if (updateCount > 0) {
        findings.push(
          makeFinding(
            'PATCH-001',
            updateCount > 5 ? 'high' : 'medium',
            `${updateCount} pending system updates`,
            `There are ${updateCount} pending macOS software updates. Security patches should be applied promptly.`,
            'vulnerability'
          )
        );
      }
    } else if (os === 'linux') {
      // Check apt (Debian/Ubuntu)
      if (existsSync('/usr/bin/apt')) {
        const aptList = await execPromise('/usr/bin/apt', ['list', '--upgradable'], 30000);
        const updateLines = aptList.split('\n').filter((l) => l.includes('upgradable'));
        const secUpdates = updateLines.filter(
          (l) => l.includes('security') || l.includes('-security')
        );

        if (secUpdates.length > 0) {
          findings.push(
            makeFinding(
              'PATCH-002',
              secUpdates.length > 10 ? 'critical' : 'high',
              `${secUpdates.length} security updates pending`,
              `There are ${secUpdates.length} pending security updates. Apply them with: apt upgrade`,
              'vulnerability'
            )
          );
        }
      }
    }
  } catch {
    logger.warn('Patch check failed');
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Incident Response Assessment
// ---------------------------------------------------------------------------

export async function assessIncidentResponse(): Promise<ComplianceFinding[]> {
  const findings: ComplianceFinding[] = [];

  // Check if notification channels are configured in Panguard
  const panguardConfig = `${process.env['HOME']}/.panguard/config.json`;
  try {
    if (existsSync(panguardConfig)) {
      const config = JSON.parse(readFileSync(panguardConfig, 'utf-8'));
      if (!config.notifications || Object.keys(config.notifications).length === 0) {
        findings.push(
          makeFinding(
            'IR-NOTIFY-001',
            'medium',
            'No notification channels configured',
            'Panguard has no notification channels (Telegram/Slack/Email) configured. Incident alerts cannot be delivered.',
            'incident'
          )
        );
      }
    } else {
      findings.push(
        makeFinding(
          'IR-CONFIG-001',
          'low',
          'Panguard not configured',
          'No Panguard configuration found at ~/.panguard/config.json. Run `panguard init` to set up.',
          'incident'
        )
      );
    }
  } catch {
    // Config may not exist
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Master Assessment Runner
// ---------------------------------------------------------------------------

/** Category → Assessor function mapping */
const CATEGORY_ASSESSORS: Record<string, () => Promise<ComplianceFinding[]>> = {
  // TCSA categories
  access_control: assessAccessControl,
  authentication: assessAccessControl,
  system_protection: assessFirewallAndNetwork,
  network_security: assessFirewallAndNetwork,
  encryption: assessEncryption,
  monitoring: assessMonitoring,
  incident_response: assessIncidentResponse,
  asset_management: assessPatching,
  patch_management: assessPatching,
  audit: assessMonitoring,
  // SOC 2 categories
  logical_access: assessAccessControl,
  credentials: assessAccessControl,
  access_management: assessAccessControl,
  boundary_protection: assessFirewallAndNetwork,
  data_transmission: assessEncryption,
  anomaly_detection: assessMonitoring,
  incident_evaluation: assessMonitoring,
  change_management: assessPatching,
  // ISO 27001 categories
  technology: assessAccessControl,
  malware: assessMonitoring,
  vulnerability: assessPatching,
  configuration: assessFirewallAndNetwork,
  data_protection: assessEncryption,
  logging: assessMonitoring,
  network: assessFirewallAndNetwork,
  cryptography: assessEncryption,
  incident: assessIncidentResponse,
};

/**
 * Run all assessments for a given framework's control categories.
 * Returns deduplicated findings.
 */
export async function runAssessment(
  controlCategories: string[]
): Promise<ComplianceFinding[]> {
  const allFindings: ComplianceFinding[] = [];
  const ranAssessors = new Set<string>();

  for (const category of controlCategories) {
    const assessor = CATEGORY_ASSESSORS[category];
    if (!assessor) continue;

    // Deduplicate: don't run the same assessor function twice
    const assessorName = assessor.name;
    if (ranAssessors.has(assessorName)) continue;
    ranAssessors.add(assessorName);

    logger.info(`Running assessor: ${assessorName} for category: ${category}`);
    try {
      const findings = await assessor();
      allFindings.push(...findings);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Assessor ${assessorName} failed: ${msg}`);
    }
  }

  // Deduplicate by findingId
  const seen = new Set<string>();
  return allFindings.filter((f) => {
    if (seen.has(f.findingId)) return false;
    seen.add(f.findingId);
    return true;
  });
}

/**
 * Run full system assessment (all assessors).
 */
export async function runFullAssessment(): Promise<ComplianceFinding[]> {
  const allCategories = Object.keys(CATEGORY_ASSESSORS);
  return runAssessment(allCategories);
}
