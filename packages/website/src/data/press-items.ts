export interface PressItem {
  slug: string;
  title: string;
  type: 'press-release' | 'coverage';
  source?: string;
  date: string;
  excerpt: string;
}

export const pressItems: PressItem[] = [
  {
    slug: 'launch-free-scanner',
    title: 'Panguard AI Launches Free AI-Powered Security Scanner for Developers',
    type: 'press-release',
    date: '2026-02-10',
    excerpt:
      'Panguard AI today announced the general availability of Panguard Scan, a free 60-second AI security audit tool for servers and endpoints.',
  },
  {
    slug: 'seed-round',
    title: 'Panguard AI Raises Seed Round to Democratize Cybersecurity',
    type: 'press-release',
    date: '2026-01-15',
    excerpt:
      'Taipei-based cybersecurity startup Panguard AI has raised its seed round to accelerate development of its AI-powered endpoint security platform.',
  },
  {
    slug: 'soc2-certification',
    title: 'Panguard AI Announces SOC 2 Type II Certification Progress',
    type: 'press-release',
    date: '2025-12-20',
    excerpt:
      'Panguard AI is on track for SOC 2 Type II certification by Q3 2026, with automated evidence collection already exceeding 85% coverage.',
  },
  {
    slug: 'trap-beta',
    title: 'Panguard AI Opens Public Beta for Panguard Trap Honeypot System',
    type: 'press-release',
    date: '2025-11-15',
    excerpt:
      'Panguard Trap, the intelligent honeypot system that studies attacker behavior with AI, is now available in public beta.',
  },
  {
    slug: 'techcrunch-coverage',
    title: 'The Startup Making Enterprise Security Accessible to Everyone',
    type: 'coverage',
    source: 'TechCrunch',
    date: '2026-01-20',
    excerpt:
      'Panguard AI is betting that the future of cybersecurity is not more complex tools, but simpler ones that speak human.',
  },
  {
    slug: 'wired-ai-security',
    title: 'How AI Is Reshaping Endpoint Security for Small Teams',
    type: 'coverage',
    source: 'Wired',
    date: '2025-12-15',
    excerpt:
      'A new generation of AI security startups, including Panguard AI, is bringing CrowdStrike-level protection to teams of five.',
  },
];
