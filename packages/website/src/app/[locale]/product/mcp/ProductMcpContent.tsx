'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  IntegrationIcon,
  ScanIcon,
  ShieldIcon,
  BlockIcon,
  AnalyticsIcon,
  DeployIcon,
  TerminalIcon,
  SettingsIcon,
} from '@/components/ui/BrandIcons';
import { STATS } from '@/lib/stats';

/* ─── MCP Tools ─── */
const mcpTools = [
  { icon: ScanIcon, name: 'panguard_scan', desc: 'Run a full security health check and get risk score + findings' },
  { icon: ScanIcon, name: 'panguard_scan_code', desc: 'SAST source code scanning for vulnerabilities and secrets' },
  { icon: ShieldIcon, name: 'panguard_guard_start', desc: 'Start the Guard daemon for 24/7 real-time protection' },
  { icon: ShieldIcon, name: 'panguard_guard_stop', desc: 'Stop the Guard daemon gracefully' },
  { icon: AnalyticsIcon, name: 'panguard_status', desc: 'Get current system protection status and health' },
  { icon: AnalyticsIcon, name: 'panguard_alerts', desc: 'Fetch recent security alerts with severity and details' },
  { icon: BlockIcon, name: 'panguard_block_ip', desc: 'Block an attacker IP address immediately' },
  { icon: AnalyticsIcon, name: 'panguard_generate_report', desc: 'Generate ISO 27001, SOC 2, or TCSA compliance report' },
  { icon: SettingsIcon, name: 'panguard_init', desc: 'Initialize Panguard configuration on a new system' },
  { icon: DeployIcon, name: 'panguard_deploy', desc: 'Deploy security configuration to an endpoint' },
  { icon: TerminalIcon, name: 'panguard_skill_audit', desc: 'Audit AI agent SKILL.md files for security threats' },
];

/* ─── Compatible clients ─── */
const clients = [
  { name: 'Claude Desktop', desc: 'Anthropic\'s desktop app with native MCP support' },
  { name: 'Cursor', desc: 'AI-first code editor with MCP tool integration' },
  { name: 'Claude Code', desc: 'CLI agent that can call MCP tools directly' },
  { name: 'OpenClaw', desc: 'Native Skill (auto-installed via `panguard setup`)' },
  { name: 'Codex CLI', desc: 'OpenAI\'s coding agent with MCP tool support' },
  { name: 'Any MCP Client', desc: 'Any app implementing the Model Context Protocol' },
];

export default function ProductMcpContent() {
  const t = useTranslations('product.mcp');

  return (
    <>
      {/* ── Hero ── */}
      <section className="relative min-h-[50vh] flex items-center px-5 sm:px-6 lg:px-[120px] py-16 sm:py-28 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[700px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <div className="relative w-20 h-20 mx-auto mb-4 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-brand-sage/20 animate-[spin_12s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border border-brand-sage/10 animate-[spin_8s_linear_infinite_reverse]" />
              <IntegrationIcon className="w-10 h-10 text-brand-sage relative" />
            </div>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <div className="flex items-center justify-center gap-2 mb-4">
              <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold">
                {t('overline')}
              </p>
              <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-yellow-900/30 text-yellow-400">
                Beta
              </span>
            </div>
            <h1 className="text-[clamp(24px,4.5vw,56px)] font-extrabold leading-[1.08] tracking-tight text-text-primary max-w-3xl mx-auto">
              {t('title')} <span className="text-brand-sage">{t('titleHighlight')}</span>
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-xl mx-auto mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* ── How it works ── */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('howItWorks.overline')}
            </p>
            <h2 className="text-[clamp(20px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('howItWorks.title')}
            </h2>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-text-secondary mt-5 leading-relaxed">{t('howItWorks.desc')}</p>
          </FadeInUp>

          {/* Setup code */}
          <FadeInUp delay={0.15}>
            <div className="mt-8 bg-[#0c0d0c] border border-border rounded-xl overflow-hidden">
              <div className="px-4 py-2 border-b border-border/60">
                <span className="text-xs text-text-muted font-mono">claude_desktop_config.json</span>
              </div>
              <pre className="p-4 text-sm font-mono text-text-secondary overflow-x-auto leading-relaxed">
{`{
  "mcpServers": {
    "panguard": {
      "command": "npx",
      "args": ["-y", "@panguard-ai/panguard-mcp"]
    }
  }
}`}
              </pre>
            </div>
            <p className="text-xs text-text-muted mt-2">{t('howItWorks.configNote')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Tools Grid ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('tools.overline')}
          title={t('tools.title')}
          subtitle={`${STATS.mcpTools} tools available via MCP protocol`}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 mt-14">
          {mcpTools.map((tool, i) => {
            const Icon = tool.icon;
            return (
              <FadeInUp key={tool.name} delay={i * 0.05}>
                <div className="bg-surface-2 rounded-xl border border-border p-5 h-full">
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className="w-4 h-4 text-brand-sage shrink-0" />
                    <code className="text-xs font-mono text-text-primary">{tool.name}</code>
                  </div>
                  <p className="text-xs text-text-secondary leading-relaxed">{tool.desc}</p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── Compatible Clients ── */}
      <SectionWrapper>
        <SectionTitle overline={t('clients.overline')} title={t('clients.title')} />
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-14">
          {clients.map((client, i) => (
            <FadeInUp key={client.name} delay={i * 0.08}>
              <div className="bg-surface-1 rounded-xl border border-border p-6 h-full card-glow text-center">
                <IntegrationIcon className="w-8 h-8 text-brand-sage mx-auto mb-3" />
                <p className="text-sm font-bold text-text-primary mb-1">{client.name}</p>
                <p className="text-xs text-text-secondary">{client.desc}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── CTA ── */}
      <SectionWrapper dark>
        <div className="text-center">
          <FadeInUp>
            <h2 className="text-[clamp(20px,3vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-3 max-w-lg mx-auto">{t('cta.desc')}</p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/docs/installation"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/product"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.cta2')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
