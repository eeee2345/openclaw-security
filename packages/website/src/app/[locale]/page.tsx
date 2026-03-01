import dynamic from 'next/dynamic';
import NavBar from '@/components/NavBar';
import Hero from '@/components/home/Hero';
import Footer from '@/components/Footer';

// Below-the-fold sections loaded lazily to reduce initial bundle
const IndustryProblem = dynamic(() => import('@/components/home/IndustryProblem'));
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
        {/* S3: Three Roads */}
        <ThreeRoads />
        {/* S4: Redefine (transition) */}
        <Redefine />
        {/* S5: Show Muscle (5-person team + funnel + confidence) */}
        <ShowMuscle />
        {/* S6: Threat Cloud */}
        <ThreatCloudSection />
        {/* S7: 3AM Timeline */}
        <The3AMStory />
        {/* S8: Use Cases */}
        <UseCases />
        {/* S9: Product Overview */}
        <ProductOverview />
        {/* S10: Numbers Wall + Trust */}
        <NumbersWall />
        {/* S11: Pricing + Compliance */}
        <HomePricing />
        {/* S12: Final CTA */}
        <FinalCTA />
      </main>
      <Footer />
    </>
  );
}
