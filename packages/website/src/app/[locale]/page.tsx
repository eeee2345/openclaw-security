import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';

export const metadata: Metadata = {
  title: 'Panguard AI — AI-Powered Endpoint Security',
  description:
    'Protect your infrastructure with AI-driven threat detection, 24/7 monitoring, honeypots, and compliance reporting. Free tier available.',
  openGraph: {
    title: 'Panguard AI — AI-Powered Endpoint Security',
    description:
      'Protect your infrastructure with AI-driven threat detection, 24/7 monitoring, honeypots, and compliance reporting.',
    type: 'website',
    url: 'https://panguard.ai',
  },
};
import Hero from '@/components/home/Hero';
import IndustryProblem from '@/components/home/IndustryProblem';
import ThreeRoads from '@/components/home/ThreeRoads';
import Redefine from '@/components/home/Redefine';
import ShowMuscle from '@/components/home/ShowMuscle';
import ThreatCloudSection from '@/components/home/ThreatCloudSection';
import The3AMStory from '@/components/home/The3AMStory';
import UseCases from '@/components/home/UseCases';
import ProductOverview from '@/components/home/ProductOverview';
import NumbersWall from '@/components/home/NumbersWall';
import HomePricing from '@/components/home/HomePricing';
import FinalCTA from '@/components/home/FinalCTA';
import Footer from '@/components/Footer';

export default function Home() {
  return (
    <>
      <NavBar />
      <main>
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
