import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import HowItWorksContent from './HowItWorksContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('howItWorks.title'),
    description: t('howItWorks.description'),
    alternates: buildAlternates('/how-it-works', params.locale),
    openGraph: {
      title: t('howItWorks.title'),
      description: t('howItWorks.description'),
      images: [{ url: '/og-image.png', width: 1200, height: 630 }],
    },
  };
}

const howToJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'HowTo',
  name: 'How Panguard AI Protects Your Servers',
  description:
    'Panguard uses a five-stage security pipeline with a three-tier AI funnel to detect, analyze, and respond to threats in real time.',
  step: [
    {
      '@type': 'HowToStep',
      position: 1,
      name: 'Detect',
      text: 'Rule-based scanning with 3,155 Sigma rules, 5,895 YARA signatures, and ATR (Agent Threat Rules) catches 90% of threats locally.',
    },
    {
      '@type': 'HowToStep',
      position: 2,
      name: 'Analyze',
      text: 'Behavioral AI analyzes suspicious patterns using local models (Ollama) or cloud AI for advanced correlation.',
    },
    {
      '@type': 'HowToStep',
      position: 3,
      name: 'Respond',
      text: 'Automated threat response isolates compromised processes, blocks malicious IPs, and quarantines files.',
    },
    {
      '@type': 'HowToStep',
      position: 4,
      name: 'Report',
      text: 'Generate compliance reports mapped to ISO 27001, SOC 2, and Taiwan TCSA frameworks with one command.',
    },
    {
      '@type': 'HowToStep',
      position: 5,
      name: 'Chat',
      text: 'AI security copilot answers plain-language questions about threats, logs, and system security posture.',
    },
  ],
};

export default function HowItWorksPage() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(howToJsonLd) }}
      />
      <NavBar />
      <main id="main-content">
        <HowItWorksContent />
      </main>
      <Footer />
    </>
  );
}
