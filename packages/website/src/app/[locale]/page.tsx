import dynamic from 'next/dynamic';
import NavBar from '@/components/NavBar';
import Hero from '@/components/home/Hero';
import Footer from '@/components/Footer';

// Below-the-fold sections loaded lazily to reduce initial bundle
const IndustryProblem = dynamic(() => import('@/components/home/IndustryProblem'));
const WhyNowWhyUs = dynamic(() => import('@/components/home/WhyNowWhyUs'));
const NotAntivirus = dynamic(() => import('@/components/home/NotAntivirus'));
const ThreeRoads = dynamic(() => import('@/components/home/ThreeRoads'));
const Redefine = dynamic(() => import('@/components/home/Redefine'));
const ShowMuscle = dynamic(() => import('@/components/home/ShowMuscle'));
const ThreatCloudSection = dynamic(() => import('@/components/home/ThreatCloudSection'));
const The3AMStory = dynamic(() => import('@/components/home/The3AMStory'));
const UseCases = dynamic(() => import('@/components/home/UseCases'));
const ProductOverview = dynamic(() => import('@/components/home/ProductOverview'));
const NumbersWall = dynamic(() => import('@/components/home/NumbersWall'));
const Traction = dynamic(() => import('@/components/home/Traction'));
const HomePricing = dynamic(() => import('@/components/home/HomePricing'));
const FinalCTA = dynamic(() => import('@/components/home/FinalCTA'));

export default function Home() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <p id="definition" className="sr-only">
          Panguard AI is an open-source, AI-powered endpoint security platform that protects servers
          with behavioral AI, 3,155 Sigma rules, and 5,895 YARA signatures — installable in 60
          seconds via a single CLI command.
        </p>
        {/* S1: Hero */}
        <Hero />
        {/* S2: Industry Problem */}
        <IndustryProblem />
        {/* S3: Why Now / Why Us */}
        <WhyNowWhyUs />
        {/* S4: Not Antivirus (common misconception) */}
        <NotAntivirus />
        {/* S5: Three Roads */}
        <ThreeRoads />
        {/* S6: Redefine (transition) */}
        <Redefine />
        {/* S7: Show Muscle (5-person team + funnel + confidence) */}
        <ShowMuscle />
        {/* S8: Threat Cloud */}
        <ThreatCloudSection />
        {/* S9: 3AM Timeline */}
        <The3AMStory />
        {/* S10: Use Cases */}
        <UseCases />
        {/* S11: Product Overview */}
        <ProductOverview />
        {/* S12: Numbers Wall + Trust */}
        <NumbersWall />
        {/* S13: Traction / Built for Production */}
        <Traction />
        {/* S14: Pricing + Compliance */}
        <HomePricing />
        {/* S15: Final CTA */}
        <FinalCTA />
      </main>
      <Footer />
    </>
  );
}
