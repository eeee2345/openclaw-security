'use client';
import { useEffect, useRef, useState } from 'react';
import { useInView } from 'framer-motion';
import { useTranslations } from 'next-intl';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';

/* Terminal lines stay in English (CLI/code output never translated) */
const lines = [
  { text: '$ curl -sSL panguard.ai/install | sh', color: 'text-brand-sage' },
  { text: 'Downloading Panguard AI v2.1.0...', color: 'text-text-secondary', prefix: true },
  { text: 'Detecting environment... Ubuntu 24.04 LTS', color: 'text-text-secondary', prefix: true },
  { text: 'Installing security agents...', color: 'text-text-secondary', prefix: true },
  { text: 'AI model loaded (Layer 1: 3,155 rules)', color: 'text-text-secondary', prefix: true },
  { text: 'Connected to Panguard Threat Cloud', color: 'text-text-secondary', prefix: true },
  { text: '', color: '' },
  {
    text: 'Protection active. Your system is now guarded.',
    color: 'text-text-primary',
    shield: true,
  },
  { text: '  Docs \u2192 https://docs.panguard.ai', color: 'text-text-tertiary' },
  { text: '  Status: PROTECTED', color: 'text-status-safe', dot: true },
];

export default function InstallDemo() {
  const t = useTranslations('home.installDemo');
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-100px' });
  const [visibleLines, setVisibleLines] = useState(0);
  const [charIndex, setCharIndex] = useState(0);
  const [done, setDone] = useState(false);

  const metrics = [
    { value: t('metric1Value'), label: t('metric1Label') },
    { value: t('metric2Value'), label: t('metric2Label') },
    { value: t('metric3Value'), label: t('metric3Label') },
  ];

  useEffect(() => {
    if (!isInView) return;
    if (visibleLines >= lines.length) {
      setDone(true);
      return;
    }
    const cur = lines[visibleLines];
    if (!cur.text) {
      const timer = setTimeout(() => {
        setVisibleLines((v) => v + 1);
        setCharIndex(0);
      }, 300);
      return () => clearTimeout(timer);
    }
    if (charIndex < cur.text.length) {
      const timer = setTimeout(() => setCharIndex((c) => c + 1), 25);
      return () => clearTimeout(timer);
    }
    const timer = setTimeout(() => {
      setVisibleLines((v) => v + 1);
      setCharIndex(0);
    }, 150);
    return () => clearTimeout(timer);
  }, [isInView, visibleLines, charIndex]);

  return (
    <SectionWrapper dark id="demo">
      <SectionTitle title={t('title')} subtitle={t('subtitle')} />

      <div ref={ref} className="max-w-2xl mx-auto mt-12">
        <div className="bg-surface-0 rounded-2xl border border-border overflow-hidden shadow-2xl">
          <div className="flex items-center gap-2 px-4 h-11 bg-[#1C1814] border-b border-border">
            <div className="w-3 h-3 rounded-full bg-[#EF4444]" />
            <div className="w-3 h-3 rounded-full bg-[#FBBF24]" />
            <div className="w-3 h-3 rounded-full bg-[#2ED573]" />
            <span className="ml-3 text-xs text-text-tertiary font-mono">
              panguard &mdash; zsh &mdash; 80x24
            </span>
          </div>

          <div className="p-6 font-mono text-[13px] leading-[1.8] min-h-[320px] bg-[#1A1614]">
            {lines.map((line, i) => {
              if (i > visibleLines) return null;
              const isCurrent = i === visibleLines;
              const displayText = isCurrent ? line.text.slice(0, charIndex) : line.text;
              if (!line.text) return <div key={i} className="h-4" />;
              return (
                <div key={i} className={`${line.color} whitespace-pre`}>
                  {line.prefix && <span className="text-status-safe">{'  \u2713 '}</span>}
                  {line.shield && <span className="text-brand-sage">{'>> '}</span>}
                  {displayText}
                  {line.dot && !isCurrent && (
                    <span className="inline-block w-2 h-2 rounded-full bg-status-safe ml-2 align-middle animate-pulse" />
                  )}
                  {isCurrent && !done && (
                    <span className="inline-block w-[2px] h-4 bg-brand-sage ml-0.5 align-middle animate-pulse" />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <div className="flex gap-10 justify-center mt-8">
          {metrics.map((m) => (
            <div key={m.label} className="text-center">
              <p className="text-lg font-bold text-text-primary">{m.value}</p>
              <p className="text-xs text-text-tertiary">{m.label}</p>
            </div>
          ))}
        </div>
      </div>
    </SectionWrapper>
  );
}
