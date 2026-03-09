import dynamic from 'next/dynamic';
import NavBar from '@/components/NavBar';
import RevolutionHero from '@/components/home/RevolutionHero';
import Footer from '@/components/Footer';

// Below-the-fold sections loaded lazily to reduce initial bundle
const ATRShowcase = dynamic(() => import('@/components/home/ATRShowcase'));
const SkillProtection = dynamic(() => import('@/components/home/SkillProtection'));
const ThreatsOverview = dynamic(() => import('@/components/home/ThreatsOverview'));
const HowItWorksNew = dynamic(() => import('@/components/home/HowItWorksNew'));
const CommunityFlywheel = dynamic(() => import('@/components/home/CommunityFlywheel'));
const RealScenarios = dynamic(() => import('@/components/home/RealScenarios'));
const SecurityStack = dynamic(() => import('@/components/home/SecurityStack'));
const FinalCTANew = dynamic(() => import('@/components/home/FinalCTANew'));

export default function Home() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <p id="definition" className="sr-only">
          Panguard AI created ATR (Agent Threat Rules), the first open security standard for AI
          agents. 29 rules across 9 threat categories detect prompt injection, tool poisoning,
          context exfiltration, and more. MIT licensed. Free forever. Built in Taiwan.
        </p>
        <RevolutionHero />
        <ATRShowcase />
        <SkillProtection />
        <ThreatsOverview />
        <RealScenarios />
        <SecurityStack />
        <HowItWorksNew />
        <CommunityFlywheel />
        <FinalCTANew />
      </main>
      <Footer />
    </>
  );
}
