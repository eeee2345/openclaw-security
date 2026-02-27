export interface ChangelogEntry {
  version: string;
  date: string;
  title: string;
  description: string;
  changes: { type: 'feature' | 'fix' | 'improvement' | 'security'; text: string }[];
}

export const changelogEntries: ChangelogEntry[] = [
  {
    version: '1.3.0',
    date: '2026-02-20',
    title: 'Panguard Trap Public Beta',
    description: 'Intelligent honeypots are now available for all Pro and Enterprise plans.',
    changes: [
      { type: 'feature', text: 'Panguard Trap: deploy AI-generated honeypots on unused ports' },
      { type: 'feature', text: 'Attacker profiling with MITRE ATT&CK mapping' },
      { type: 'feature', text: 'Collective threat intelligence sharing (anonymized)' },
      { type: 'improvement', text: 'Dashboard now shows honeypot activity in real-time' },
    ],
  },
  {
    version: '1.2.1',
    date: '2026-02-10',
    title: 'SSH Brute-Force Detection Fix',
    description: 'Resolved false positive in SSH brute-force detection for high-traffic servers.',
    changes: [
      { type: 'fix', text: 'Fixed false positive when >100 legitimate SSH connections per minute' },
      { type: 'improvement', text: 'Improved confidence scoring for authentication events' },
    ],
  },
  {
    version: '1.2.0',
    date: '2026-01-28',
    title: 'LINE and Telegram Alert Channels',
    description: 'Panguard Chat now supports LINE and Telegram in addition to Slack.',
    changes: [
      { type: 'feature', text: 'LINE messaging integration for real-time alerts' },
      { type: 'feature', text: 'Telegram bot integration with rich formatting' },
      { type: 'improvement', text: 'Alert deduplication to prevent notification fatigue' },
      { type: 'improvement', text: 'Weekly digest summary messages' },
    ],
  },
  {
    version: '1.1.2',
    date: '2026-01-15',
    title: 'Scan Performance Boost',
    description: 'Panguard Scan now completes 40% faster on large servers.',
    changes: [
      { type: 'improvement', text: 'Scan engine optimized for servers with >10,000 packages' },
      { type: 'improvement', text: 'Parallel CVE lookup reduces scan time by 40%' },
      { type: 'fix', text: 'Fixed timeout on servers with slow DNS resolution' },
    ],
  },
  {
    version: '1.1.1',
    date: '2026-01-08',
    title: 'TLS Certificate Security Patch',
    description: 'Security patch for TLS certificate validation in agent-to-cloud communication.',
    changes: [
      {
        type: 'security',
        text: 'Updated TLS certificate validation to reject expired intermediate CAs',
      },
      { type: 'security', text: 'Added certificate pinning for agent-to-cloud communication' },
    ],
  },
  {
    version: '1.1.0',
    date: '2025-12-20',
    title: 'Traditional Chinese Support',
    description: 'Panguard Chat now supports Traditional Chinese for all notifications and Q&A.',
    changes: [
      { type: 'feature', text: 'Traditional Chinese language support in Panguard Chat' },
      { type: 'feature', text: 'Localized threat descriptions and remediation steps' },
      { type: 'improvement', text: 'Auto-detect user language preference from system locale' },
    ],
  },
  {
    version: '1.0.2',
    date: '2025-12-10',
    title: 'PDF Report Improvements',
    description: 'Better formatting and layout for generated compliance reports.',
    changes: [
      { type: 'improvement', text: 'Redesigned PDF report layout with executive summary' },
      { type: 'improvement', text: 'Added risk heatmap visualization to reports' },
      { type: 'fix', text: 'Fixed UTF-8 encoding issues in report filenames' },
    ],
  },
  {
    version: '1.0.1',
    date: '2025-12-01',
    title: 'Timezone Handling Fix',
    description: 'Fixed timezone handling in alert notifications and log timestamps.',
    changes: [
      { type: 'fix', text: "Alert timestamps now respect the endpoint's local timezone" },
      { type: 'fix', text: 'Fixed daylight saving time transition handling' },
    ],
  },
  {
    version: '1.0.0',
    date: '2025-11-15',
    title: 'Initial Public Release',
    description:
      'Panguard AI is officially available. One command to install. AI protects everything.',
    changes: [
      { type: 'feature', text: 'Panguard Scan: 60-second AI security audit' },
      { type: 'feature', text: 'Panguard Guard: 24/7 three-layer AI endpoint protection' },
      { type: 'feature', text: 'Panguard Chat: AI security copilot with Slack integration' },
      { type: 'feature', text: 'Panguard Report: auto-generated compliance reports' },
      {
        type: 'feature',
        text: '3,155+ Sigma detection rules (45 Panguard original + 3,110 SigmaHQ community)',
      },
      { type: 'feature', text: 'Context memory learning system' },
    ],
  },
];
