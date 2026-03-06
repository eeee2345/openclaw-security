/* ──────────────────────────  Types  ──────────────────────────── */

export interface Flag {
  name: string;
  /** i18n key suffix for this flag's description (resolved via t() in the component) */
  descKey: string;
  default?: string;
}

export interface Command {
  /** Unique identifier used as i18n key segment, e.g. "scan", "scanCode" */
  id: string;
  command: string;
  /** i18n key suffix for this command's description (resolved via t() in the component) */
  descKey: string;
  flags?: Flag[];
  example: string;
  tier: 'Free' | 'Pro' | 'Enterprise';
  maturity: 'GA' | 'Beta';
}

export interface CommandCategory {
  /** Unique identifier used as i18n key segment, e.g. "scanning", "protection" */
  id: string;
  commands: Command[];
}

/* ──────────────────────────  Data  ───────────────────────────── */

export const CATEGORIES: CommandCategory[] = [
  {
    id: 'scanning',
    commands: [
      {
        id: 'scan',
        command: 'panguard scan',
        descKey: 'cli.commands.scan.desc',
        flags: [
          { name: '--json', descKey: 'cli.commands.scan.flags.json' },
          { name: '--output <path>', descKey: 'cli.commands.scan.flags.output' },
          { name: '--verbose', descKey: 'cli.commands.scan.flags.verbose' },
          { name: '--lang <code>', descKey: 'cli.commands.scan.flags.lang', default: 'en' },
          { name: '--config <path>', descKey: 'cli.commands.scan.flags.config' },
        ],
        example: 'panguard scan --json --output report.json',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'scanCode',
        command: 'panguard scan code',
        descKey: 'cli.commands.scanCode.desc',
        flags: [
          { name: '--dir <path>', descKey: 'cli.commands.scanCode.flags.dir', default: '.' },
          { name: '--lang <language>', descKey: 'cli.commands.scanCode.flags.lang' },
          { name: '--json', descKey: 'cli.commands.scanCode.flags.json' },
          {
            name: '--fail-on <severity>',
            descKey: 'cli.commands.scanCode.flags.failOn',
            default: 'high',
          },
          { name: '--output <path>', descKey: 'cli.commands.scanCode.flags.output' },
        ],
        example: 'panguard scan code --dir ./src --lang ts --fail-on medium',
        tier: 'Pro',
        maturity: 'Beta',
      },
      {
        id: 'code',
        command: 'panguard code',
        descKey: 'cli.commands.code.desc',
        flags: [
          { name: '--dir <path>', descKey: 'cli.commands.code.flags.dir', default: '.' },
          { name: '--lang <language>', descKey: 'cli.commands.code.flags.lang' },
          { name: '--json', descKey: 'cli.commands.code.flags.json' },
          {
            name: '--fail-on <severity>',
            descKey: 'cli.commands.code.flags.failOn',
            default: 'high',
          },
          { name: '--output <path>', descKey: 'cli.commands.code.flags.output' },
        ],
        example: 'panguard code --dir ./src --json',
        tier: 'Pro',
        maturity: 'Beta',
      },
    ],
  },
  {
    id: 'protection',
    commands: [
      {
        id: 'guardStart',
        command: 'panguard guard start',
        descKey: 'cli.commands.guardStart.desc',
        flags: [
          {
            name: '--mode <mode>',
            descKey: 'cli.commands.guardStart.flags.mode',
            default: 'passive',
          },
          { name: '--verbose', descKey: 'cli.commands.guardStart.flags.verbose' },
          { name: '--dashboard-port <port>', descKey: 'cli.commands.guardStart.flags.dashboardPort', default: '9100' },
        ],
        example: 'panguard guard start --mode active --dashboard-port 9100',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'guardStop',
        command: 'panguard guard stop',
        descKey: 'cli.commands.guardStop.desc',
        example: 'panguard guard stop',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'guardStatus',
        command: 'panguard guard status',
        descKey: 'cli.commands.guardStatus.desc',
        flags: [
          { name: '--detailed', descKey: 'cli.commands.guardStatus.flags.detailed' },
        ],
        example: 'panguard guard status --detailed',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'guardConfig',
        command: 'panguard guard config',
        descKey: 'cli.commands.guardConfig.desc',
        example: 'panguard guard config',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'guardInstall',
        command: 'panguard guard install',
        descKey: 'cli.commands.guardInstall.desc',
        example: 'panguard guard install',
        tier: 'Pro',
        maturity: 'GA',
      },
    ],
  },
  {
    id: 'chat',
    commands: [
      {
        id: 'chatSetup',
        command: 'panguard chat setup',
        descKey: 'cli.commands.chatSetup.desc',
        flags: [
          { name: '--channel <type>', descKey: 'cli.commands.chatSetup.flags.channel' },
          { name: '--lang <code>', descKey: 'cli.commands.chatSetup.flags.lang', default: 'en' },
        ],
        example: 'panguard chat setup --channel telegram',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'chatTest',
        command: 'panguard chat test',
        descKey: 'cli.commands.chatTest.desc',
        flags: [
          { name: '--channel <type>', descKey: 'cli.commands.chatTest.flags.channel' },
        ],
        example: 'panguard chat test --channel slack',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'chatStatus',
        command: 'panguard chat status',
        descKey: 'cli.commands.chatStatus.desc',
        example: 'panguard chat status',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'chatPrefs',
        command: 'panguard chat prefs',
        descKey: 'cli.commands.chatPrefs.desc',
        flags: [
          { name: '--critical <on|off>', descKey: 'cli.commands.chatPrefs.flags.critical' },
          { name: '--daily <on|off>', descKey: 'cli.commands.chatPrefs.flags.daily' },
          { name: '--weekly <on|off>', descKey: 'cli.commands.chatPrefs.flags.weekly' },
        ],
        example: 'panguard chat prefs --critical on --daily off',
        tier: 'Pro',
        maturity: 'GA',
      },
    ],
  },
  {
    id: 'honeypots',
    commands: [
      {
        id: 'trapStart',
        command: 'panguard trap start',
        descKey: 'cli.commands.trapStart.desc',
        flags: [
          { name: '--services <types>', descKey: 'cli.commands.trapStart.flags.services' },
          { name: '--no-cloud', descKey: 'cli.commands.trapStart.flags.noCloud' },
        ],
        example: 'panguard trap start --services ssh,http,mysql',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'trapStop',
        command: 'panguard trap stop',
        descKey: 'cli.commands.trapStop.desc',
        example: 'panguard trap stop',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'trapStatus',
        command: 'panguard trap status',
        descKey: 'cli.commands.trapStatus.desc',
        example: 'panguard trap status',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'trapIntel',
        command: 'panguard trap intel',
        descKey: 'cli.commands.trapIntel.desc',
        example: 'panguard trap intel',
        tier: 'Pro',
        maturity: 'GA',
      },
    ],
  },
  {
    id: 'reporting',
    commands: [
      {
        id: 'reportGenerate',
        command: 'panguard report generate',
        descKey: 'cli.commands.reportGenerate.desc',
        flags: [
          { name: '--framework <name>', descKey: 'cli.commands.reportGenerate.flags.framework' },
          { name: '--language <lang>', descKey: 'cli.commands.reportGenerate.flags.language', default: 'en' },
          { name: '--format <fmt>', descKey: 'cli.commands.reportGenerate.flags.format', default: 'pdf' },
          { name: '--org <name>', descKey: 'cli.commands.reportGenerate.flags.org' },
        ],
        example: 'panguard report generate --framework iso27001 --org "My Corp"',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'reportSummary',
        command: 'panguard report summary',
        descKey: 'cli.commands.reportSummary.desc',
        example: 'panguard report summary',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'reportListFrameworks',
        command: 'panguard report list-frameworks',
        descKey: 'cli.commands.reportListFrameworks.desc',
        example: 'panguard report list-frameworks',
        tier: 'Free',
        maturity: 'GA',
      },
    ],
  },
  {
    id: 'infrastructure',
    commands: [
      {
        id: 'serve',
        command: 'panguard serve',
        descKey: 'cli.commands.serve.desc',
        flags: [
          { name: '--port <port>', descKey: 'cli.commands.serve.flags.port', default: '3000' },
          { name: '--host <host>', descKey: 'cli.commands.serve.flags.host', default: '127.0.0.1' },
        ],
        example: 'panguard serve --port 3000',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'managerStart',
        command: 'panguard manager start',
        descKey: 'cli.commands.managerStart.desc',
        flags: [
          { name: '--port <port>', descKey: 'cli.commands.managerStart.flags.port', default: '8443' },
          { name: '--api-key <key>', descKey: 'cli.commands.managerStart.flags.apiKey' },
        ],
        example: 'panguard manager start --port 8443',
        tier: 'Enterprise',
        maturity: 'GA',
      },
      {
        id: 'managerAgents',
        command: 'panguard manager agents',
        descKey: 'cli.commands.managerAgents.desc',
        example: 'panguard manager agents',
        tier: 'Enterprise',
        maturity: 'GA',
      },
      {
        id: 'threatStart',
        command: 'panguard threat start',
        descKey: 'cli.commands.threatStart.desc',
        flags: [
          { name: '--port <port>', descKey: 'cli.commands.threatStart.flags.port', default: '8080' },
        ],
        example: 'panguard threat start --port 8080',
        tier: 'Pro',
        maturity: 'GA',
      },
    ],
  },
  {
    id: 'hardening',
    commands: [
      {
        id: 'hardeningAudit',
        command: 'panguard hardening audit',
        descKey: 'cli.commands.hardeningAudit.desc',
        flags: [
          { name: '--json', descKey: 'cli.commands.hardeningAudit.flags.json' },
        ],
        example: 'panguard hardening audit --json',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'hardeningMigrate',
        command: 'panguard hardening migrate',
        descKey: 'cli.commands.hardeningMigrate.desc',
        flags: [
          { name: '--dry-run', descKey: 'cli.commands.hardeningMigrate.flags.dryRun' },
        ],
        example: 'panguard hardening migrate --dry-run',
        tier: 'Free',
        maturity: 'GA',
      },
    ],
  },
  {
    id: 'config',
    commands: [
      {
        id: 'configLlm',
        command: 'panguard config llm',
        descKey: 'cli.commands.configLlm.desc',
        flags: [
          { name: '--provider <name>', descKey: 'cli.commands.configLlm.flags.provider' },
          { name: '--model <model>', descKey: 'cli.commands.configLlm.flags.model' },
          { name: '--show', descKey: 'cli.commands.configLlm.flags.show' },
          { name: '--clear', descKey: 'cli.commands.configLlm.flags.clear' },
        ],
        example: 'panguard config llm --provider ollama --model llama3',
        tier: 'Free',
        maturity: 'GA',
      },
    ],
  },
  {
    id: 'system',
    commands: [
      {
        id: 'init',
        command: 'panguard init',
        descKey: 'cli.commands.init.desc',
        flags: [
          { name: '--lang <code>', descKey: 'cli.commands.init.flags.lang', default: 'en' },
          { name: '--advanced', descKey: 'cli.commands.init.flags.advanced' },
        ],
        example: 'panguard init --advanced',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'deploy',
        command: 'panguard deploy',
        descKey: 'cli.commands.deploy.desc',
        flags: [
          { name: '--dry-run', descKey: 'cli.commands.deploy.flags.dryRun' },
        ],
        example: 'panguard deploy --dry-run',
        tier: 'Pro',
        maturity: 'GA',
      },
      {
        id: 'status',
        command: 'panguard status',
        descKey: 'cli.commands.status.desc',
        flags: [
          { name: '--json', descKey: 'cli.commands.status.flags.json' },
        ],
        example: 'panguard status --json',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'doctor',
        command: 'panguard doctor',
        descKey: 'cli.commands.doctor.desc',
        flags: [
          { name: '--json', descKey: 'cli.commands.doctor.flags.json' },
        ],
        example: 'panguard doctor --json',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'demo',
        command: 'panguard demo',
        descKey: 'cli.commands.demo.desc',
        flags: [
          { name: '--lang <code>', descKey: 'cli.commands.demo.flags.lang', default: 'en' },
        ],
        example: 'panguard demo',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'login',
        command: 'panguard login',
        descKey: 'cli.commands.login.desc',
        example: 'panguard login',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'logout',
        command: 'panguard logout',
        descKey: 'cli.commands.logout.desc',
        example: 'panguard logout',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'whoami',
        command: 'panguard whoami',
        descKey: 'cli.commands.whoami.desc',
        example: 'panguard whoami --json',
        tier: 'Free',
        maturity: 'GA',
      },
      {
        id: 'upgrade',
        command: 'panguard upgrade',
        descKey: 'cli.commands.upgrade.desc',
        example: 'panguard upgrade',
        tier: 'Free',
        maturity: 'GA',
      },
    ],
  },
];
