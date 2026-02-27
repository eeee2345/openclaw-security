import NavBar from '@/components/NavBar';
import Hero from '@/components/home/Hero';
import EraContext from '@/components/home/EraContext';
import PainPoint from '@/components/home/PainPoint';
import ProductGrid from '@/components/home/ProductGrid';
import ThreeSteps from '@/components/home/ThreeSteps';
import UseCases from '@/components/home/UseCases';
import SocialProof from '@/components/home/SocialProof';
import TimeComparison from '@/components/home/TimeComparison';
import TrustLayer from '@/components/home/TrustLayer';
import HomePricing from '@/components/home/HomePricing';
import FinalCTA from '@/components/home/FinalCTA';
import Footer from '@/components/Footer';

export default function Home() {
  return (
    <>
      <NavBar />
      <main>
        {/* 1. Hero — See threats. Respond automatically. Deploy in one line. */}
        <Hero />
        {/* 2. Era Context — AI deploys, who protects? */}
        <EraContext />
        {/* 3. Pain Point — Your server is being scanned. Now. */}
        <PainPoint />
        {/* 4. Product Grid — One platform. Six layers of defense. */}
        <ProductGrid />
        {/* 5. Three Steps — Install, Scan, Guard */}
        <ThreeSteps />
        {/* 6. Use Cases — 4 persona scenarios */}
        <UseCases />
        {/* 7. Stats Wall — 3,158 / 425 / 8 / 1,107 / 5 / 3 / 6 / MIT */}
        <SocialProof />
        {/* 8. Time Comparison — Without vs With Panguard */}
        <TimeComparison />
        {/* 9. Trust Layer — Open Source, Security, Privacy */}
        <TrustLayer />
        {/* 10. Pricing — Community / Solo / Pro / Business */}
        <HomePricing />
        {/* 11. Final CTA — 60 seconds. Free. No account needed. */}
        <FinalCTA />
      </main>
      <Footer />
    </>
  );
}
