/**
 * Built-in Sigma detection rules shipped with Guard
 * 內建 Sigma 偵測規則
 *
 * These rules provide baseline detection capability out of the box.
 * Additional rules can be loaded from disk or fetched from Threat Cloud.
 *
 * @module @panguard-ai/panguard-guard/rules/builtin-rules
 */

import type { SigmaRule } from '@panguard-ai/core';

export const BUILTIN_RULES: SigmaRule[] = [
  // -------------------------------------------------------------------------
  // Credential Access / 憑證存取
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-001',
    title: 'Brute Force Login Attempt',
    status: 'stable',
    description: 'Detects failed login attempts indicating brute force attack',
    author: 'Panguard AI',
    logsource: { category: 'authentication', product: 'any' },
    detection: {
      selection: {
        category: 'authentication',
        'description|contains': [
          'failed login',
          'authentication failure',
          'login failed',
          'invalid password',
          'Failed password',
        ],
      },
      condition: 'selection',
    },
    level: 'high',
    tags: ['attack.credential_access', 'attack.t1110'],
  },
  {
    id: 'panguard-builtin-002',
    title: 'SSH Brute Force',
    status: 'stable',
    description: 'Detects SSH authentication failures from sshd logs',
    author: 'Panguard AI',
    logsource: { category: 'authentication', service: 'sshd' },
    detection: {
      selection: {
        category: 'authentication',
        'description|contains': [
          'Failed password for',
          'Invalid user',
          'Connection closed by authenticating user',
        ],
      },
      condition: 'selection',
    },
    level: 'high',
    tags: ['attack.credential_access', 'attack.t1110.001'],
  },
  {
    id: 'panguard-builtin-003',
    title: 'Credential Dumping Tool',
    status: 'stable',
    description: 'Detects credential dumping tools like mimikatz',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'mimikatz',
          'sekurlsa',
          'lsadump',
          'hashdump',
          'credential dump',
        ],
      },
      condition: 'selection',
    },
    level: 'critical',
    tags: ['attack.credential_access', 'attack.t1003'],
  },

  // -------------------------------------------------------------------------
  // Execution / 執行
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-004',
    title: 'Suspicious Reverse Shell',
    status: 'stable',
    description: 'Detects reverse shell commands in process or log events',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection_bash: {
        'description|contains': ['bash -i >& /dev/tcp/', '/bin/bash -c "bash -i'],
      },
      selection_nc: {
        'description|contains': ['nc -e /bin/', 'ncat -e /bin/', 'netcat -e'],
      },
      selection_python: {
        'description|contains': [
          "python -c 'import socket",
          'python3 -c "import socket',
        ],
      },
      selection_perl: {
        'description|contains': ["perl -e 'use Socket"],
      },
      condition: 'selection_bash OR selection_nc OR selection_python OR selection_perl',
    },
    level: 'critical',
    tags: ['attack.execution', 'attack.t1059'],
  },
  {
    id: 'panguard-builtin-005',
    title: 'Command and Scripting Interpreter',
    status: 'stable',
    description: 'Detects suspicious use of scripting interpreters',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        category: 'process',
        'description|contains': [
          'powershell -enc',
          'powershell -e ',
          'cmd /c whoami',
          'bash -c "curl',
          'wget -O- |',
          'curl | bash',
          'python -c "import os',
        ],
      },
      condition: 'selection',
    },
    level: 'high',
    tags: ['attack.execution', 'attack.t1059'],
  },

  // -------------------------------------------------------------------------
  // Persistence / 持久化
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-006',
    title: 'Cron Job Persistence',
    status: 'stable',
    description: 'Detects new cron job creation for persistence',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'crontab -',
          '/etc/cron',
          '/var/spool/cron',
          'CRON[',
        ],
      },
      condition: 'selection',
    },
    level: 'medium',
    tags: ['attack.persistence', 'attack.t1053.003'],
  },
  {
    id: 'panguard-builtin-007',
    title: 'Systemd Service Creation',
    status: 'stable',
    description: 'Detects new systemd service installation for persistence',
    author: 'Panguard AI',
    logsource: { category: 'file_change' },
    detection: {
      selection: {
        'description|contains': [
          '/etc/systemd/system/',
          '/usr/lib/systemd/system/',
          'systemctl enable',
          'systemctl daemon-reload',
        ],
      },
      condition: 'selection',
    },
    level: 'medium',
    tags: ['attack.persistence', 'attack.t1543.002'],
  },
  {
    id: 'panguard-builtin-008',
    title: 'SSH Authorized Keys Modification',
    status: 'stable',
    description: 'Detects changes to SSH authorized_keys for backdoor access',
    author: 'Panguard AI',
    logsource: { category: 'file_change' },
    detection: {
      selection: {
        'description|contains': [
          'authorized_keys',
          '.ssh/authorized',
        ],
      },
      condition: 'selection',
    },
    level: 'high',
    tags: ['attack.persistence', 'attack.t1098.004'],
  },

  // -------------------------------------------------------------------------
  // Discovery & Reconnaissance / 偵察
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-009',
    title: 'Port Scan Detection',
    status: 'stable',
    description: 'Detects port scanning activity from network events',
    author: 'Panguard AI',
    logsource: { category: 'network_connection' },
    detection: {
      selection: {
        category: 'network',
        'description|contains': [
          'port scan',
          'SYN scan',
          'connection refused',
          'nmap',
        ],
      },
      condition: 'selection',
    },
    level: 'medium',
    tags: ['attack.discovery', 'attack.t1046'],
  },
  {
    id: 'panguard-builtin-010',
    title: 'Network Enumeration Commands',
    status: 'stable',
    description: 'Detects system/network enumeration commands',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'ifconfig -a',
          'ip addr show',
          'netstat -',
          'ss -tulnp',
          'arp -a',
          'route -n',
          'cat /etc/passwd',
          'cat /etc/shadow',
        ],
      },
      condition: 'selection',
    },
    level: 'medium',
    tags: ['attack.discovery', 'attack.t1016'],
  },

  // -------------------------------------------------------------------------
  // Lateral Movement / 橫向移動
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-011',
    title: 'Lateral Movement via SSH',
    status: 'stable',
    description: 'Detects outbound SSH connections that may indicate lateral movement',
    author: 'Panguard AI',
    logsource: { category: 'network_connection' },
    detection: {
      selection: {
        category: 'network',
        'description|contains': [
          'ssh connection to',
          'Accepted publickey',
          'sshpass',
        ],
      },
      condition: 'selection',
    },
    level: 'medium',
    tags: ['attack.lateral_movement', 'attack.t1021.004'],
  },

  // -------------------------------------------------------------------------
  // Defense Evasion / 防禦規避
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-012',
    title: 'Log Tampering',
    status: 'stable',
    description: 'Detects attempts to clear or tamper with system logs',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'truncate -s 0 /var/log',
          '> /var/log/',
          'rm -f /var/log/',
          'shred /var/log/',
          'history -c',
          'unset HISTFILE',
        ],
      },
      condition: 'selection',
    },
    level: 'critical',
    tags: ['attack.defense_evasion', 'attack.t1070.002'],
  },
  {
    id: 'panguard-builtin-013',
    title: 'Firewall Rule Modification',
    status: 'stable',
    description: 'Detects firewall rule changes that may disable security',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'iptables -F',
          'iptables -X',
          'ufw disable',
          'firewall-cmd --remove',
          'pfctl -d',
          'netsh advfirewall set',
        ],
      },
      condition: 'selection',
    },
    level: 'critical',
    tags: ['attack.defense_evasion', 'attack.t1562.004'],
  },

  // -------------------------------------------------------------------------
  // Impact / 衝擊
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-014',
    title: 'Crypto Mining Activity',
    status: 'stable',
    description: 'Detects cryptocurrency mining indicators',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'xmrig',
          'minerd',
          'stratum+tcp',
          'cryptonight',
          'coin-hive',
          'coinhive',
          'minergate',
        ],
      },
      condition: 'selection',
    },
    level: 'high',
    tags: ['attack.impact', 'attack.t1496'],
  },
  {
    id: 'panguard-builtin-015',
    title: 'Data Exfiltration Indicators',
    status: 'stable',
    description: 'Detects data exfiltration via common tools',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'curl -X POST.*--data',
          'wget --post-file',
          'scp.*@.*:',
          'rsync.*@.*:',
          'tar.*|.*nc ',
          'base64.*|.*curl',
        ],
      },
      condition: 'selection',
    },
    level: 'high',
    tags: ['attack.exfiltration', 'attack.t1048'],
  },

  // -------------------------------------------------------------------------
  // File Integrity / 檔案完整性
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-016',
    title: 'Critical System File Modification',
    status: 'stable',
    description: 'Detects changes to critical system configuration files',
    author: 'Panguard AI',
    logsource: { category: 'file_change' },
    detection: {
      selection: {
        category: 'file',
        'description|contains': [
          '/etc/passwd',
          '/etc/shadow',
          '/etc/sudoers',
          '/etc/hosts',
          '/etc/resolv.conf',
        ],
      },
      condition: 'selection',
    },
    level: 'critical',
    tags: ['attack.persistence', 'attack.t1222'],
  },
  {
    id: 'panguard-builtin-017',
    title: 'Web Shell Detection',
    status: 'stable',
    description: 'Detects potential web shell uploads or access',
    author: 'Panguard AI',
    logsource: { category: 'file_change' },
    detection: {
      selection: {
        'description|contains': [
          'webshell',
          'c99shell',
          'r57shell',
          'WSO shell',
          'eval(base64_decode',
          'system($_GET',
          'passthru(',
        ],
      },
      condition: 'selection',
    },
    level: 'critical',
    tags: ['attack.persistence', 'attack.t1505.003'],
  },

  // -------------------------------------------------------------------------
  // Privilege Escalation / 權限提升
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-018',
    title: 'Sudo Privilege Escalation',
    status: 'stable',
    description: 'Detects suspicious sudo usage for privilege escalation',
    author: 'Panguard AI',
    logsource: { category: 'authentication' },
    detection: {
      selection: {
        'description|contains': [
          'sudo:.*COMMAND=',
          'user NOT in sudoers',
          'sudo su -',
          'sudo bash',
          'sudo -i',
        ],
      },
      condition: 'selection',
    },
    level: 'medium',
    tags: ['attack.privilege_escalation', 'attack.t1548.003'],
  },
  {
    id: 'panguard-builtin-019',
    title: 'SUID/SGID Binary Exploitation',
    status: 'stable',
    description: 'Detects SUID/SGID file permission changes',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'chmod +s ',
          'chmod u+s',
          'chmod 4755',
          'chmod 6755',
          'find / -perm -4000',
        ],
      },
      condition: 'selection',
    },
    level: 'high',
    tags: ['attack.privilege_escalation', 'attack.t1548.001'],
  },

  // -------------------------------------------------------------------------
  // Malware / 惡意軟體
  // -------------------------------------------------------------------------
  {
    id: 'panguard-builtin-020',
    title: 'Ransomware Indicators',
    status: 'stable',
    description: 'Detects ransomware behavior patterns',
    author: 'Panguard AI',
    logsource: { category: 'process_creation' },
    detection: {
      selection: {
        'description|contains': [
          'vssadmin delete shadows',
          'wmic shadowcopy delete',
          'bcdedit /set.*recoveryenabled.*no',
          '.encrypted',
          'DECRYPT_INSTRUCTIONS',
          'YOUR_FILES_ARE_ENCRYPTED',
        ],
      },
      condition: 'selection',
    },
    level: 'critical',
    tags: ['attack.impact', 'attack.t1486'],
  },
];
