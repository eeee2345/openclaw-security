export interface Resource {
  slug: string;
  title: string;
  type: 'Whitepaper' | 'Report' | 'Guide' | 'Webinar' | 'Infographic';
  description: string;
  date: string;
}

export const resourceTypes = ['All', 'Whitepaper', 'Report', 'Guide', 'Webinar', 'Infographic'];

export const resources: Resource[] = [
  {
    slug: 'ai-endpoint-security-paradigm',
    title: 'AI-Powered Endpoint Security: A New Paradigm for SMBs',
    type: 'Whitepaper',
    description:
      'How AI-driven detection, automated response, and natural language reporting are replacing traditional endpoint security for growing teams.',
    date: '2026-02',
  },
  {
    slug: 'state-of-smb-cybersecurity-2026',
    title: '2026 State of SMB Cybersecurity',
    type: 'Report',
    description:
      'Analysis of 10,000+ endpoints reveals the threats, costs, and defense strategies defining SMB cybersecurity in 2026.',
    date: '2026-01',
  },
  {
    slug: 'zero-to-soc2-startup-journey',
    title: "From Zero to SOC 2: A Startup's Compliance Journey",
    type: 'Guide',
    description:
      'A step-by-step playbook for startups achieving SOC 2 compliance without external consultants.',
    date: '2026-01',
  },
  {
    slug: 'honeypot-deployment-best-practices',
    title: 'Honeypot Deployment Best Practices',
    type: 'Guide',
    description:
      'How to deploy, configure, and maximize intelligence from AI-powered honeypots in production environments.',
    date: '2025-12',
  },
  {
    slug: 'anatomy-of-ransomware-attack',
    title: 'Anatomy of a Ransomware Attack',
    type: 'Infographic',
    description:
      'Visual breakdown of a modern ransomware attack chain and how each Panguard product layer responds.',
    date: '2025-12',
  },
  {
    slug: 'security-program-team-of-one',
    title: 'Building a Security Program with a Team of One',
    type: 'Webinar',
    description:
      'Recorded webinar: how solo developers and small teams can build enterprise-grade security programs with AI automation.',
    date: '2025-11',
  },
  {
    slug: 'cost-of-cybercrime-small-business',
    title: 'Cost of Cybercrime for Small Businesses 2026',
    type: 'Report',
    description:
      'Data-driven analysis of the financial impact of cyberattacks on businesses with fewer than 500 employees.',
    date: '2025-11',
  },
  {
    slug: 'choosing-ai-security-vendor',
    title: 'Choosing an AI Security Vendor: Evaluation Checklist',
    type: 'Guide',
    description:
      'A comprehensive checklist for evaluating AI-powered security platforms, including questions to ask, red flags, and comparison frameworks.',
    date: '2025-10',
  },
];
