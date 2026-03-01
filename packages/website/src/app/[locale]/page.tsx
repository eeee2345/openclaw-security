import dynamic from 'next/dynamic';
import NavBar from '@/components/NavBar';
import Hero from '@/components/home/Hero';
import Footer from '@/components/Footer';

// Below-the-fold sections loaded lazily to reduce initial bundle
const IndustryProblem = dynamic(() => import('@/components/home/IndustryProblem'));
const NotAntivirus = dynamic(() => import('@/components/home/NotAntivirus'));
const ThreeRoads = dynamic(() => import('@/components/home/ThreeRoads'));
const Redefine = dynamic(() => import('@/components/home/Redefine'));
const ShowMuscle = dynamic(() => import('@/components/home/ShowMuscle'));
const ThreatCloudSection = dynamic(() => import('@/components/home/ThreatCloudSection'));
const The3AMStory = dynamic(() => import('@/components/home/The3AMStory'));
const UseCases = dynamic(() => import('@/components/home/UseCases'));
const ProductOverview = dynamic(() => import('@/components/home/ProductOverview'));
const NumbersWall = dynamic(() => import('@/components/home/NumbersWall'));
const HomePricing = dynamic(() => import('@/components/home/HomePricing'));
const FinalCTA = dynamic(() => import('@/components/home/FinalCTA'));

export default function Home() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        {/* S1: Hero */}
        <Hero />
        {/* S2: Industry Problem */}
        <IndustryProblem />
        {/* S3: Not Antivirus (common misconception) */}
        <NotAntivirus />
        {/* S4: Three Roads */}
        <ThreeRoads />
        {/* S5: Redefine (transition) */}
        <Redefine />
        {/* S6: Show Muscle (5-person team + funnel + confidence) */}
        <ShowMuscle />
        {/* S7: Threat Cloud */}
        <ThreatCloudSection />
        {/* S8: 3AM Timeline */}
        <The3AMStory />
        {/* S9: Use Cases */}
        <UseCases />
        {/* S10: Product Overview */}
        <ProductOverview />
        {/* S11: Numbers Wall + Trust */}
        <NumbersWall />
        {/* S12: Pricing + Compliance */}
        <HomePricing />
        {/* S13: Final CTA */}
        <FinalCTA />
      </main>
      <Footer />
    </>
  );
}
