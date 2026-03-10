import dynamic from 'next/dynamic';
import NavBar from '@/components/NavBar';
import RevolutionHero from '@/components/home/RevolutionHero';
import Footer from '@/components/Footer';

// Below-the-fold sections loaded lazily
const ProductPillars = dynamic(() => import('@/components/home/ProductPillars'));
const SkillProtection = dynamic(() => import('@/components/home/SkillProtection'));
const RealScenarios = dynamic(() => import('@/components/home/RealScenarios'));
const SecurityStack = dynamic(() => import('@/components/home/SecurityStack'));
const ATRShowcase = dynamic(() => import('@/components/home/ATRShowcase'));
const HowItWorksNew = dynamic(() => import('@/components/home/HowItWorksNew'));
const CommunityFlywheel = dynamic(() => import('@/components/home/CommunityFlywheel'));
const FinalCTANew = dynamic(() => import('@/components/home/FinalCTANew'));

export default function Home() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <p id="definition" className="sr-only">
          Panguard AI created ATR (Agent Threat Rules), the first open security standard for AI
          agents. 32 rules across 9 threat categories detect prompt injection, tool poisoning,
          context exfiltration, and more. MIT licensed. Open source. Built in Taiwan.
        </p>
        {/* 1. WHAT: 5-second clarity -- AI Agent runtime security */}
        <RevolutionHero />
        {/* 2. WHAT: Three pillars -- Skill Auditor / Guard / ATR */}
        <ProductPillars />
        {/* 3. WHAT: OpenClaw ecosystem security + before/after */}
        <SkillProtection />
        {/* 4. WHY: Three real attack scenarios */}
        <RealScenarios />
        {/* 5. WHY: Pre-deployment vs runtime positioning */}
        <SecurityStack />
        {/* 6. HOW: ATR rules with real YAML + features */}
        <ATRShowcase />
        {/* 7. HOW: Install / Protect / Contribute summary */}
        <HowItWorksNew />
        {/* 8. JOIN: Collective defense flywheel */}
        <CommunityFlywheel />
        {/* 9. JOIN: Final CTA -- Contribute + Community */}
        <FinalCTANew />
      </main>
      <Footer />
    </>
  );
}
