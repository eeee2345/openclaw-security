import dynamic from 'next/dynamic';
import NavBar from '@/components/NavBar';
import RevolutionHero from '@/components/home/RevolutionHero';
import Footer from '@/components/Footer';

// Below-the-fold sections loaded lazily
const PipelineFlow = dynamic(() => import('@/components/home/PipelineFlow'));
const ProductPillars = dynamic(() => import('@/components/home/ProductPillars'));
const SkillProtection = dynamic(() => import('@/components/home/SkillProtection'));
const RealScenarios = dynamic(() => import('@/components/home/RealScenarios'));
const SecurityStack = dynamic(() => import('@/components/home/SecurityStack'));
const HowItWorksNew = dynamic(() => import('@/components/home/HowItWorksNew'));
const CommunityFlywheel = dynamic(() => import('@/components/home/CommunityFlywheel'));
const FinalCTANew = dynamic(() => import('@/components/home/FinalCTANew'));

export default function Home() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <p id="definition" className="sr-only">
          Panguard AI provides the first Skills Audit for AI agents. It audits every skill before it
          runs, catches known threats with community ATR + Sigma + YARA rules, catches unknown threats
          with AI analysis, and shares new rules to protect everyone. MIT licensed. Open source.
        </p>
        {/* 1. Hero: The first Skills Audit for AI agents */}
        <RevolutionHero />
        {/* 2. Pipeline: 6-step visual flow diagram */}
        <PipelineFlow />
        {/* 3. Three pillars: Community Rules / Collective Defense / AI Fallback */}
        <ProductPillars />
        {/* 4. Before/after: With and without Panguard */}
        <SkillProtection />
        {/* 5. Three layers: Rules / AI / Cloud */}
        <RealScenarios />
        {/* 6. Your agent's immune system */}
        <SecurityStack />
        {/* 7. Simple summary: Install / Review / Evolve */}
        <HowItWorksNew />
        {/* 8. Collective immunity flywheel */}
        <CommunityFlywheel />
        {/* 9. Final CTA */}
        <FinalCTANew />
      </main>
      <Footer />
    </>
  );
}
