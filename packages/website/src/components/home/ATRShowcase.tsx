'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Shield, TestTube, Zap, Globe, Github, ArrowUpRight } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

const YAML_CODE = `id: ATR-2026-001
name: Prompt Injection via Tool Output
category: prompt-injection
severity: critical
description: >
  Detects when an MCP tool returns output
  containing embedded instructions that
  attempt to override the agent's system
  prompt or redirect its behavior.
detection:
  scope: tool_output
  pattern: |
    /(ignore|disregard)\\s+(previous|above)
    \\s+instructions/i
response: block
tests:
  true_positive: 3
  true_negative: 5`;

const featureIcons = [Shield, TestTube, Zap, Globe] as const;
const featureKeys = ['agentNative', 'testable', 'actionable', 'collective'] as const;

export default function ATRShowcase() {
  const t = useTranslations('revolution.atrShowcase');

  return (
    <section className="bg-[#0e0f0e] px-5 sm:px-6 py-16 sm:py-24">
      <div className="max-w-6xl mx-auto">
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-2xl sm:text-3xl md:text-4xl font-bold text-text-primary text-center mb-12 sm:mb-16"
        >
          {t('title')}
        </motion.h2>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12">
          {/* Left: Code block */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.1, ease }}
          >
            <div className="bg-[#0a0a0a] border border-border rounded-xl overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
                <div className="w-3 h-3 rounded-full bg-red-500/60" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                <div className="w-3 h-3 rounded-full bg-green-500/60" />
                <span className="ml-2 text-xs text-text-muted font-mono">ATR-2026-001.yaml</span>
              </div>
              <pre className="p-4 sm:p-5 overflow-x-auto text-sm leading-relaxed">
                <code className="text-text-secondary">
                  {YAML_CODE.split('\n').map((line, i) => {
                    const isKey = /^\s*\w[\w-]*:/.test(line);
                    const isComment = line.trim().startsWith('#');
                    let colorClass = 'text-text-secondary';
                    if (isKey) colorClass = 'text-panguard-green';
                    if (isComment) colorClass = 'text-text-muted';
                    return (
                      <span key={i} className={colorClass}>
                        {line}
                        {'\n'}
                      </span>
                    );
                  })}
                </code>
              </pre>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-5 py-3 border-t border-border text-sm text-panguard-green hover:text-panguard-green-light transition-colors font-semibold"
              >
                <Github className="w-4 h-4" />
                {t('githubCta')}
                <ArrowUpRight className="w-3.5 h-3.5 ml-auto" />
              </a>
            </div>
          </motion.div>

          {/* Right: Feature cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {featureKeys.map((key, i) => {
              const Icon = featureIcons[i];
              return (
                <motion.div
                  key={key}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: '-40px' }}
                  transition={{ duration: 0.4, delay: 0.15 * i, ease }}
                  className="bg-[#0a0a0a] border border-border rounded-xl p-6 hover:border-brand-sage/40 transition-colors duration-300"
                >
                  <Icon className="w-5 h-5 text-panguard-green mb-3" />
                  <h3 className="text-base font-semibold text-text-primary mb-1.5">
                    {t(`features.${key}.title`)}
                  </h3>
                  <p className="text-sm text-text-muted leading-relaxed">
                    {t(`features.${key}.desc`)}
                  </p>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
