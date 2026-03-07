import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import TrapDocsContent from './TrapDocsContent';

export const metadata: Metadata = {
  title: 'Panguard Trap — Documentation',
  description: 'Deploy honeypot services to detect and profile attackers. SSH, HTTP, and DNS decoys with automatic threat intelligence.',
  openGraph: {
    title: 'Panguard Trap — Panguard AI Docs',
    description: 'Honeypot deployment, attacker profiling, and threat intelligence feeds.',
  },
};

export default function TrapDocsPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <TrapDocsContent />
      </main>
      <Footer />
    </>
  );
}
