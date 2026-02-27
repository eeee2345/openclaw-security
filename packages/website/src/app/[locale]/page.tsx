import { useTranslations } from 'next-intl';
import NavBar from '@/components/NavBar';
import Hero from '@/components/home/Hero';
import PainPoint from '@/components/home/PainPoint';
import Flip from '@/components/home/Flip';
import TechReveal from '@/components/home/TechReveal';
import ThreeSteps from '@/components/home/ThreeSteps';
import UseCases from '@/components/home/UseCases';
import TrustLayer from '@/components/home/TrustLayer';
import Comparison from '@/components/home/Comparison';
import SocialProof from '@/components/home/SocialProof';
import CallToAction from '@/components/home/CallToAction';
import Vision from '@/components/home/Vision';
import Footer from '@/components/Footer';
import CLIShowcase from '@/components/ui/CLIShowcase';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import FadeInUp from '@/components/FadeInUp';

export default function Home() {
  const t = useTranslations('home.cliShowcase');

  return (
    <>
      <NavBar />
      <main>
        {/* 1. Hero */}
        <Hero />
        {/* 2. PainPoint */}
        <PainPoint />
        {/* 3. Flip */}
        <Flip />
        {/* 4. TechReveal (new) */}
        <TechReveal />
        {/* 5. CLIShowcase */}
        <SectionWrapper>
          <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
          <div className="mt-14">
            <CLIShowcase />
          </div>
          <FadeInUp delay={0.3}>
            <p className="text-sm text-brand-sage text-center mt-6 font-medium">{t('callout')}</p>
          </FadeInUp>
        </SectionWrapper>
        {/* 6. ThreeSteps (new) */}
        <ThreeSteps />
        {/* 7. UseCases (new) */}
        <UseCases />
        {/* 8. SocialProof */}
        <SocialProof />
        {/* 9. TrustLayer (new) */}
        <TrustLayer />
        {/* 10. Comparison */}
        <Comparison />
        {/* 11. CallToAction */}
        <CallToAction />
        {/* 12. Vision */}
        <Vision />
      </main>
      {/* 13. Footer */}
      <Footer />
    </>
  );
}
