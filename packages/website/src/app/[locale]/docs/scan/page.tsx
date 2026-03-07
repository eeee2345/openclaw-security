import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ScanDocsContent from './ScanDocsContent';

export const metadata: Metadata = {
  title: 'Panguard Scan — Documentation',
  description: 'Run security audits with one command. Configure scans, interpret results, integrate with CI/CD, and automate with JSON output.',
  openGraph: {
    title: 'Panguard Scan — Panguard AI Docs',
    description: 'One-command security audits: infrastructure, code SAST, remote scanning, compliance reports.',
  },
};

export default function ScanDocsPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ScanDocsContent />
      </main>
      <Footer />
    </>
  );
}
