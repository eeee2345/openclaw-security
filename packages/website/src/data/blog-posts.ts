export interface BlogPost {
  slug: string;
  title: string;
  excerpt: string;
  category: string;
  date: string;
  author: string;
  readingTime: string;
  content?: string[];
}

export const categories = [
  'All',
  'Engineering',
  'Threat Intelligence',
  'Product Updates',
  'Compliance',
  'Industry',
];

export const blogPosts: BlogPost[] = [
  {
    slug: 'ai-powered-threat-detection-vs-rules',
    title: 'Why AI-Powered Threat Detection Outperforms Rule-Based Systems',
    excerpt:
      'Traditional rule-based detection catches known threats. AI catches what rules miss. Here is how Panguard combines both approaches for 99.7% detection accuracy.',
    category: 'Engineering',
    date: '2026-02-20',
    author: 'Engineering Team',
    readingTime: '8 min',
  },
  {
    slug: 'true-cost-data-breach-small-business',
    title: 'The True Cost of a Data Breach for Small Businesses in 2026',
    excerpt:
      'The average cost of a data breach for SMBs reached $4.9M in 2025. We break down the numbers and explain why proactive security costs a fraction of incident response.',
    category: 'Industry',
    date: '2026-02-15',
    author: 'Security Research',
    readingTime: '6 min',
  },
  {
    slug: 'introducing-panguard-scan',
    title: 'Introducing Panguard Scan: Free 60-Second Security Audits',
    excerpt:
      'One command. 60 seconds. A complete security audit of your server with AI-prioritized findings. Available today, free forever.',
    category: 'Product Updates',
    date: '2026-02-10',
    author: 'Product Team',
    readingTime: '4 min',
    content: [
      '## The Problem: Security Audits Are Slow and Expensive',
      'Getting a security assessment for your server has traditionally meant one of two things: hiring a consultant for thousands of dollars, or spending days running fragmented open-source tools and trying to interpret the output. For solo developers and small teams, neither option works.',
      'We built Panguard Scan to change that.',
      '## What Panguard Scan Does',
      'Panguard Scan is a free, open-source security audit tool that runs a comprehensive check of your server in under 60 seconds. One command is all it takes:',
      '```\ncurl -fsSL https://get.panguard.ai/scan | sh\n```',
      'The scan engine checks 3,155 Sigma detection rules and 5,895 YARA malware signatures against your system. It examines SSH configuration, open ports, running services, file permissions, user accounts, cron jobs, and dozens of other attack surface vectors.',
      '## AI-Prioritized Findings',
      'Raw scan output is noise. Panguard Scan uses AI to prioritize findings by actual risk to your specific environment. A default SSH port on a public-facing web server is critical. The same finding on an internal development machine behind a VPN is informational. Context matters, and Panguard understands context.',
      'Each finding includes a plain-language explanation of what was found, why it matters, and exactly how to fix it. No CVE-code deciphering required.',
      '## The Output: A Professional PDF Report',
      'Every scan generates a clean, shareable PDF report. The report includes an executive summary with a security score, detailed findings grouped by severity, and step-by-step remediation guidance. Use it for internal review, share it with investors during due diligence, or attach it to compliance documentation.',
      '## Free Forever',
      'Panguard Scan is and will remain free. The scan engine is MIT licensed and available on GitHub. We believe every server deserves a baseline security assessment, regardless of budget.',
      'For teams that want continuous protection beyond the initial scan -- real-time threat detection, automated response, and 24/7 monitoring -- Panguard Guard starts at $9/month for solo developers.',
      '## Get Started',
      'Run your first scan today. No account required, no credit card, no installation footprint. One command, 60 seconds, and you will know exactly where your server stands.',
    ],
  },
  {
    slug: 'honeypot-intelligence-panguard-trap',
    title: 'Honeypot Intelligence: How Panguard Trap Learns from Attackers',
    excerpt:
      'Instead of waiting for attackers to find your real systems, deploy decoys that study their techniques. Panguard Trap turns offense into intelligence.',
    category: 'Threat Intelligence',
    date: '2026-02-05',
    author: 'Threat Research',
    readingTime: '10 min',
  },
  {
    slug: 'soc2-compliance-startups-guide',
    title: 'SOC 2 Compliance for Startups: A Practical Guide',
    excerpt:
      'SOC 2 does not require a $60K consultant. With the right tooling, a startup team can achieve compliance in weeks. Here is the playbook.',
    category: 'Compliance',
    date: '2026-01-28',
    author: 'Compliance Team',
    readingTime: '12 min',
    content: [
      '## Why SOC 2 Matters for Startups',
      'If you sell to enterprises, SOC 2 is no longer optional. It is table stakes. Prospects will ask for your SOC 2 report during security review. Without it, deals stall or die. The question is not whether to get SOC 2 certified -- it is how to do it without burning $60K on consultants or losing months of engineering time.',
      '## SOC 2 Demystified: What It Actually Requires',
      'SOC 2 is built around five Trust Service Criteria: Security, Availability, Processing Integrity, Confidentiality, and Privacy. Most startups only need Security (required) and Availability for their first audit. That narrows the scope significantly.',
      'The audit evaluates 64 controls across categories like access management, change control, incident response, risk assessment, and vendor management. For each control, you need two things: a policy (documentation) and evidence (proof you follow it).',
      '## The Traditional Approach: Slow and Expensive',
      'The legacy path looks like this: hire a compliance consultant ($20K-60K), spend 3-6 months writing policies, implement controls manually, collect evidence in spreadsheets, then pay an auditor ($15K-30K) to review everything. Total cost: $35K-90K. Total time: 4-8 months. And the moment the audit ends, your evidence starts going stale.',
      '## The Modern Approach: Automated Compliance',
      'Compliance automation tools like Panguard Report change the economics entirely. Instead of writing policies from scratch, you start with templates mapped to SOC 2 controls. Instead of collecting evidence manually, the tool continuously pulls evidence from your infrastructure -- cloud configurations, access logs, vulnerability scans, incident tickets.',
      '## A 6-Week SOC 2 Playbook',
      '**Week 1-2: Scope and Gap Analysis.** Run Panguard Scan on your infrastructure to get a baseline security assessment. Use Panguard Report to generate a gap analysis against SOC 2 controls. This tells you exactly what you already comply with and what needs work.',
      '**Week 3-4: Policy and Control Implementation.** Adopt the 64 control templates. Customize them for your organization. Implement the missing controls -- most are configuration changes, not engineering projects. Common gaps: MFA enforcement, access reviews, incident response procedures, and change management documentation.',
      '**Week 5: Evidence Collection.** Configure automated evidence collection. Panguard Report pulls from your cloud provider, identity provider, code repository, and endpoint fleet to continuously generate audit evidence. The result is a living compliance dashboard rather than a point-in-time spreadsheet.',
      '**Week 6: Auditor Readiness.** Generate your SOC 2 readiness report. Review it with your team. Engage an auditor. Because your evidence is machine-generated and continuously updated, the audit itself typically takes 2-4 weeks rather than 2-4 months.',
      '## Cost Comparison',
      'Traditional consultant approach: $35K-90K over 4-8 months. Panguard-automated approach: software cost plus auditor fees, typically under $20K total, completed in 6-8 weeks. For Taiwanese startups, the savings are even more significant when factoring in local consultant rates of NT$300K-800K.',
      '## SOC 2 + ISO 27001 + TCSA',
      'Many of the controls overlap. If you are targeting international markets, getting SOC 2 first gives you 60-70% coverage toward ISO 27001. If you are a Taiwanese company with government contracts, the Taiwan Cyber Security Act (TCSA) requirements share significant overlap with SOC 2 Security criteria. Panguard Report supports all three frameworks with a single evidence collection pipeline.',
      '## Get Started',
      'Run a free compliance gap analysis with Panguard Report. See exactly where you stand against SOC 2, ISO 27001, and TCSA requirements. No consultant required.',
    ],
  },
  {
    slug: 'lateral-movement-detection',
    title: 'Lateral Movement Detection: How Panguard Guard Stops Attackers',
    excerpt:
      "Once an attacker gets in, they move laterally. Panguard Guard's three-layer AI engine detects lateral movement in real time, before data exfiltration begins.",
    category: 'Engineering',
    date: '2026-01-20',
    author: 'Engineering Team',
    readingTime: '7 min',
  },
  {
    slug: 'security-speaks-human-design-philosophy',
    title: 'Building Security That Speaks Human: The Design Philosophy Behind Panguard Chat',
    excerpt:
      'Security alerts are useless if nobody understands them. We built Panguard Chat to explain threats in plain language, in the messaging apps teams already use.',
    category: 'Product Updates',
    date: '2026-01-15',
    author: 'Product Team',
    readingTime: '5 min',
  },
  {
    slug: 'open-source-scan-engine',
    title: 'Open Source Security: Why We Publish Our Scan Engine',
    excerpt:
      'Transparency builds trust. Our scan engine is MIT licensed. Every detection rule, every test, every line of code is auditable.',
    category: 'Engineering',
    date: '2026-01-10',
    author: 'Engineering Team',
    readingTime: '4 min',
  },
];
