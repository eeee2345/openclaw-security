export interface CaseStudy {
  slug: string;
  company: string;
  industry: string;
  companySize: string;
  productsUsed: string[];
  headline: string;
  excerpt: string;
  challenge: string;
  solution: string;
  results: { metric: string; value: string }[];
  quote: string;
  quoteName: string;
  quoteRole: string;
  isScenario: true;
}

export const caseStudies: CaseStudy[] = [
  {
    slug: 'fintech-soc2-compliance',
    company: 'FinTech Startup',
    industry: 'Financial Services',
    companySize: '45 employees',
    productsUsed: ['Guard', 'Report', 'Chat'],
    headline: 'Scenario: Achieving SOC 2 compliance in 2 weeks with Panguard Report',
    excerpt:
      'A FinTech startup preparing for Series A needs SOC 2 compliance fast. Panguard automates evidence collection and report generation, cutting months of consultant work to days.',
    challenge:
      'A mid-stage startup raising a Series A finds every enterprise prospect requires SOC 2 certification. Traditional consultants quote $40K and a 3-month timeline. The 4-person engineering team cannot afford the distraction.',
    solution:
      'The team deploys Panguard Guard on all 12 endpoints and activates Panguard Report. Automated evidence collection starts immediately. The compliance dashboard shows real-time gap analysis against SOC 2 Trust Service Criteria.',
    results: [
      { metric: 'Time to compliance', value: '14 days' },
      { metric: 'Cost savings vs. consultant', value: '$38K' },
      { metric: 'Controls automated', value: '87%' },
      { metric: 'Audit findings', value: '0 critical' },
    ],
    quote:
      'This scenario illustrates how automated compliance reporting can compress months of manual preparation into days, at a fraction of the traditional cost.',
    quoteName: 'Panguard Team',
    quoteRole: 'Based on common FinTech security challenges',
    isScenario: true,
  },
  {
    slug: 'ecommerce-incident-reduction',
    company: 'E-Commerce Platform',
    industry: 'E-Commerce',
    companySize: '120 employees',
    productsUsed: ['Guard', 'Trap', 'Chat'],
    headline: 'Scenario: Reducing security incidents 94% with AI-powered endpoint protection',
    excerpt:
      'An e-commerce platform handling millions of transactions per month is losing $50K quarterly to security incidents. Panguard Guard automates detection and response across 50 endpoints.',
    challenge:
      'An infrastructure spanning 50 servers handles sensitive payment data. With no dedicated security team, the company relies on manual log reviews. Average time to detect a breach: 18 days.',
    solution:
      'Panguard Guard is deployed across all endpoints in under an hour. Panguard Trap adds honeypots on 8 unused ports. Panguard Chat sends real-time alerts to the engineering Slack channel.',
    results: [
      { metric: 'Security incidents', value: '-94%' },
      { metric: 'Mean time to detect', value: '< 30 seconds' },
      { metric: 'Quarterly incident cost', value: '$50K to $3K' },
      { metric: 'Deployment time', value: '47 minutes' },
    ],
    quote:
      'This scenario demonstrates how automated detection and honeypot intelligence can transform a reactive security posture into a proactive one.',
    quoteName: 'Panguard Team',
    quoteRole: 'Based on common e-commerce security challenges',
    isScenario: true,
  },
  {
    slug: 'saas-lateral-movement',
    company: 'SaaS Analytics Co.',
    industry: 'Technology',
    companySize: '30 employees',
    productsUsed: ['Guard', 'Trap', 'Scan'],
    headline: 'Scenario: Catching lateral movement with honeypot intelligence',
    excerpt:
      'A SaaS analytics company discovers an active intrusion through Panguard Trap honeypots that has been evading traditional detection for 6 days.',
    challenge:
      'A lean engineering team runs shared infrastructure. An attacker compromises a developer laptop through a phishing email. Standard AV tools show nothing suspicious.',
    solution:
      'Panguard Trap honeypots on unused internal ports detect unusual connection attempts from the compromised laptop. Panguard Guard correlates the activity with behavioral analysis and immediately alerts the team.',
    results: [
      { metric: 'Time to detection', value: '< 3 minutes' },
      { metric: 'Attacker dwell time', value: 'Reduced to 0' },
      { metric: 'Data exfiltration', value: '0 bytes' },
      { metric: 'Recovery time', value: '2 hours' },
    ],
    quote:
      'This scenario shows how honeypot intelligence can detect threats that bypass traditional endpoint protection tools entirely.',
    quoteName: 'Panguard Team',
    quoteRole: 'Based on common lateral movement attack patterns',
    isScenario: true,
  },
];
