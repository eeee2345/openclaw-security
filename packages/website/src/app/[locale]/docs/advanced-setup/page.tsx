import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import AdvancedSetupContent from './AdvancedSetupContent';

export const metadata: Metadata = {
  title: 'Advanced Setup — Panguard AI',
  description:
    'Enhance Panguard with Ollama (local LLM), Falco (eBPF monitoring), and Suricata (network IDS). Environment variables reference.',
  openGraph: {
    title: 'Advanced Setup — Panguard AI',
    description: 'Enhance Panguard with optional integrations: Ollama, Falco, Suricata.',
  },
};

export default function AdvancedSetupPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <AdvancedSetupContent />
      </main>
      <Footer />
    </>
  );
}
