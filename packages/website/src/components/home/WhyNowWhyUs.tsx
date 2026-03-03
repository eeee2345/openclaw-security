'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '../FadeInUp';
import { Shield, Cpu, Scale, Eye, GitBranch, Terminal, Globe } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface CardData {
  icon: LucideIcon;
  title: string;
  description: string;
}

function Card({ card, delay }: { card: CardData; delay: number }) {
  const Icon = card.icon;
  return (
    <FadeInUp delay={delay}>
      <div className="bg-surface-1/50 border border-border rounded-2xl p-6 h-full">
        <Icon className="w-6 h-6 text-panguard-green mb-3" />
        <h3 className="text-lg font-bold text-text-primary mb-2">{card.title}</h3>
        <p className="text-sm text-gray-400 leading-relaxed">{card.description}</p>
      </div>
    </FadeInUp>
  );
}

export default function WhyNowWhyUs() {
  const t = useTranslations('home');

  const whyNowCards: readonly CardData[] = [
    {
      icon: Cpu,
      title: t('whyNow.card1.title'),
      description: t('whyNow.card1.desc'),
    },
    {
      icon: Shield,
      title: t('whyNow.card2.title'),
      description: t('whyNow.card2.desc'),
    },
    {
      icon: Scale,
      title: t('whyNow.card3.title'),
      description: t('whyNow.card3.desc'),
    },
  ];

  const whyUsCards: readonly CardData[] = [
    {
      icon: Eye,
      title: t('whyUs.card1.title'),
      description: t('whyUs.card1.desc'),
    },
    {
      icon: GitBranch,
      title: t('whyUs.card2.title'),
      description: t('whyUs.card2.desc'),
    },
    {
      icon: Terminal,
      title: t('whyUs.card3.title'),
      description: t('whyUs.card3.desc'),
    },
    {
      icon: Globe,
      title: t('whyUs.card4.title'),
      description: t('whyUs.card4.desc'),
    },
  ];

  return (
    <section className="bg-[#0a0a0a] px-4 sm:px-6 py-16 sm:py-24">
      <div className="max-w-[1200px] mx-auto">
        {/* Why Now */}
        <div className="mb-16">
          <FadeInUp>
            <div className="text-center mb-10">
              <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary">
                {t('whyNow.title')}
              </h2>
              <p className="text-lg text-gray-400 mt-4 max-w-2xl mx-auto">
                {t('whyNow.subtitle')}
              </p>
            </div>
          </FadeInUp>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-4xl mx-auto">
            {whyNowCards.map((card, i) => (
              <Card key={card.title} card={card} delay={i * 0.1} />
            ))}
          </div>
        </div>

        {/* Why Us */}
        <div>
          <FadeInUp>
            <div className="text-center mb-10">
              <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary">
                {t('whyUs.title')}
              </h2>
              <p className="text-lg text-gray-400 mt-4 max-w-2xl mx-auto">
                {t('whyUs.subtitle')}
              </p>
            </div>
          </FadeInUp>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-5xl mx-auto">
            {whyUsCards.map((card, i) => (
              <Card key={card.title} card={card} delay={i * 0.1} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
