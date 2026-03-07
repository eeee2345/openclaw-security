export interface Resource {
  slug: string;
  title: string;
  type: 'Guide' | 'Reference' | 'Tutorial';
  description: string;
  date: string;
  /** External link to docs site */
  docsUrl: string;
}

export const resourceTypes = ['All', 'Guide', 'Reference', 'Tutorial'];

/** Docs base URL — Mintlify docs site */
const DOCS = 'https://docs.panguard.ai';

export const resources: Resource[] = [
  {
    slug: 'first-scan-guide',
    title: 'Your First Panguard Scan',
    type: 'Tutorial',
    description:
      'Step-by-step guide to install Panguard, run your first 60-second security scan, and interpret the results.',
    date: '2026-03',
    docsUrl: `${DOCS}/guides/first-scan`,
  },
  {
    slug: 'real-time-protection-guide',
    title: 'Setting Up Real-Time Protection',
    type: 'Guide',
    description:
      'Deploy Panguard Guard for continuous endpoint monitoring with 3-layer AI detection and automated response.',
    date: '2026-03',
    docsUrl: `${DOCS}/guides/real-time-protection`,
  },
  {
    slug: 'honeypot-deployment',
    title: 'Honeypot Deployment Best Practices',
    type: 'Guide',
    description:
      'How to deploy, configure, and maximize intelligence from Panguard Trap honeypots across 8 protocols.',
    date: '2026-02',
    docsUrl: `${DOCS}/guides/honeypots`,
  },
  {
    slug: 'compliance-reports-guide',
    title: 'Generating Compliance Reports',
    type: 'Guide',
    description:
      'Automate ISO 27001, SOC 2, and Taiwan Cyber Security Act compliance evidence collection and report generation.',
    date: '2026-02',
    docsUrl: `${DOCS}/guides/compliance-reports`,
  },
  {
    slug: 'mcp-integration',
    title: 'MCP Integration for Claude & Cursor',
    type: 'Tutorial',
    description:
      'Connect Panguard to Claude Desktop or Cursor via Model Context Protocol for AI-powered security workflows.',
    date: '2026-02',
    docsUrl: `${DOCS}/guides/mcp-integration`,
  },
  {
    slug: 'multi-endpoint-management',
    title: 'Multi-Endpoint Management',
    type: 'Guide',
    description:
      'Scale from a single server to 25+ endpoints with centralized policy management and cross-agent threat correlation.',
    date: '2026-01',
    docsUrl: `${DOCS}/guides/multi-endpoint`,
  },
  {
    slug: 'cli-reference',
    title: 'CLI Command Reference',
    type: 'Reference',
    description:
      'Complete reference for all 22 Panguard CLI commands including scan, guard, trap, report, chat, and more.',
    date: '2026-01',
    docsUrl: `${DOCS}/cli/overview`,
  },
  {
    slug: 'api-reference',
    title: 'API Reference',
    type: 'Reference',
    description:
      'REST API documentation for Auth, Manager, and Threat Cloud services with authentication and endpoint details.',
    date: '2026-01',
    docsUrl: `${DOCS}/api-reference/overview`,
  },
];
