'use client';

import { useState } from 'react';
import { useTranslations, useLocale } from 'next-intl';
import { Rss, Mail, MessageSquare } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { CheckIcon, AlertIcon, MonitorIcon } from '@/components/ui/BrandIcons';

/* ─── Types ─── */

type ServiceStatus = 'operational' | 'degraded' | 'outage';

type IncidentStatus = 'resolved' | 'investigating' | 'monitoring';

interface Service {
  name: string;
  status: ServiceStatus;
  uptime: number;
  uptimeHistory: ServiceStatus[];
}

interface Incident {
  date: string;
  title: string;
  status: IncidentStatus;
  description: string;
}

/* ─── Mock Data ─── */

function generateUptimeHistory(degradedDays: number[]): ServiceStatus[] {
  return Array.from({ length: 30 }, (_, i) =>
    degradedDays.includes(i) ? 'degraded' : 'operational'
  );
}

const services: Service[] = [
  {
    name: 'Panguard Guard \u2014 Endpoint Protection',
    status: 'operational',
    uptime: 99.99,
    uptimeHistory: generateUptimeHistory([]),
  },
  {
    name: 'Panguard Scan \u2014 Security Audits',
    status: 'operational',
    uptime: 99.98,
    uptimeHistory: generateUptimeHistory([4]),
  },
  {
    name: 'Panguard Chat \u2014 AI Copilot',
    status: 'operational',
    uptime: 99.95,
    uptimeHistory: generateUptimeHistory([7, 18]),
  },
  {
    name: 'Panguard Trap \u2014 Honeypot System',
    status: 'operational',
    uptime: 99.97,
    uptimeHistory: generateUptimeHistory([12]),
  },
  {
    name: 'Panguard Report \u2014 Compliance Engine',
    status: 'operational',
    uptime: 99.99,
    uptimeHistory: generateUptimeHistory([]),
  },
  {
    name: 'Dashboard & Web App',
    status: 'operational',
    uptime: 99.96,
    uptimeHistory: generateUptimeHistory([20]),
  },
  {
    name: 'API & Integrations',
    status: 'operational',
    uptime: 99.98,
    uptimeHistory: generateUptimeHistory([8]),
  },
  {
    name: 'Threat Intelligence Feed',
    status: 'operational',
    uptime: 99.99,
    uptimeHistory: generateUptimeHistory([]),
  },
];

const incidents: Incident[] = [
  {
    date: 'Feb 20, 2026',
    title: 'Scheduled Maintenance: Database Migration',
    status: 'resolved',
    description: 'Completed 15 minutes ahead of schedule. No service impact.',
  },
  {
    date: 'Feb 8, 2026',
    title: 'Brief API Latency Increase',
    status: 'resolved',
    description:
      'Elevated API response times for 12 minutes due to upstream provider. Automatically mitigated.',
  },
  {
    date: 'Jan 25, 2026',
    title: 'Scan Service Intermittent Errors',
    status: 'resolved',
    description:
      'Some scan requests returned timeout errors for 8 minutes. Root cause: connection pool exhaustion. Fix deployed.',
  },
];

/* ─── Helpers ─── */

const statusConfig: Record<ServiceStatus, { dotClass: string; barClass: string }> = {
  operational: {
    dotClass: 'bg-emerald-400',
    barClass: 'bg-brand-sage',
  },
  degraded: {
    dotClass: 'bg-amber-400',
    barClass: 'bg-amber-400/60',
  },
  outage: {
    dotClass: 'bg-red-400',
    barClass: 'bg-red-400',
  },
};

const incidentBadgeStyles: Record<IncidentStatus, string> = {
  resolved: 'bg-emerald-500/10 text-emerald-400',
  investigating: 'bg-amber-500/10 text-amber-400',
  monitoring: 'bg-blue-500/10 text-blue-400',
};

function getOverallStatus(svcs: Service[]): ServiceStatus {
  if (svcs.some((s) => s.status === 'outage')) return 'outage';
  if (svcs.some((s) => s.status === 'degraded')) return 'degraded';
  return 'operational';
}

function formatTimestamp(locale: string): string {
  return new Date().toLocaleString(locale === 'zh' ? 'zh-TW' : 'en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

/* ════════════════════════  Sub-components  ═══════════════════════ */

function OverallBanner({
  status,
  t,
  locale,
}: {
  status: ServiceStatus;
  t: ReturnType<typeof useTranslations>;
  locale: string;
}) {
  const isAllGood = status === 'operational';

  const bannerBg = isAllGood
    ? 'bg-brand-sage/10 border-brand-sage/20'
    : status === 'degraded'
      ? 'bg-amber-500/10 border-amber-500/20'
      : 'bg-red-500/10 border-red-500/20';

  const bannerText = isAllGood
    ? t('allOperational')
    : status === 'degraded'
      ? t('degraded')
      : t('outage');

  return (
    <FadeInUp>
      <div className={`border rounded-2xl p-6 text-center ${bannerBg}`}>
        <div className="flex items-center justify-center gap-3 mb-2">
          {isAllGood ? (
            <CheckIcon size={28} className="text-brand-sage" />
          ) : (
            <AlertIcon size={28} className="text-amber-400" />
          )}
          <h2 className="text-xl sm:text-2xl font-bold text-text-primary">{bannerText}</h2>
        </div>
        <p className="text-text-tertiary text-sm">
          {t('lastUpdated')} {formatTimestamp(locale)}
        </p>
      </div>
    </FadeInUp>
  );
}

function ServiceRow({
  service,
  index,
  statusLabel,
}: {
  service: Service;
  index: number;
  statusLabel: string;
}) {
  const cfg = statusConfig[service.status];

  return (
    <FadeInUp delay={index * 0.03}>
      <div className="border-b border-border py-4 flex items-center justify-between gap-4">
        <span className="text-text-primary text-sm sm:text-base font-medium truncate">
          {service.name}
        </span>
        <div className="flex items-center gap-4 shrink-0">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${cfg.dotClass}`} aria-hidden="true" />
            <span className="text-text-secondary text-sm hidden sm:inline">{statusLabel}</span>
          </div>
          <span className="text-text-tertiary text-sm font-mono w-16 text-right">
            {service.uptime.toFixed(2)}%
          </span>
        </div>
      </div>
    </FadeInUp>
  );
}

function UptimeChart({
  service,
  index,
  t,
}: {
  service: Service;
  index: number;
  t: ReturnType<typeof useTranslations>;
}) {
  return (
    <FadeInUp delay={index * 0.05}>
      <div className="bg-surface-1 border border-border rounded-xl p-5">
        <h4 className="text-text-primary text-sm font-semibold mb-3">{service.name}</h4>
        <div className="flex items-end gap-[3px]">
          {service.uptimeHistory.map((day, i) => {
            const cfg = statusConfig[day];
            return (
              <div
                key={i}
                className={`w-2 h-8 rounded-sm ${cfg.barClass} transition-all duration-200 hover:opacity-80`}
                title={`Day ${30 - i}`}
              />
            );
          })}
        </div>
        <div className="flex items-center justify-between mt-3">
          <span className="text-text-tertiary text-xs">{t('uptimeHistory.daysAgo')}</span>
          <span className="text-text-secondary text-xs font-medium">
            {t('uptimeHistory.uptimeLabel')} {service.uptime.toFixed(2)}%
          </span>
          <span className="text-text-tertiary text-xs">{t('uptimeHistory.today')}</span>
        </div>
      </div>
    </FadeInUp>
  );
}

function IncidentCard({
  incident,
  index,
  t,
}: {
  incident: Incident;
  index: number;
  t: ReturnType<typeof useTranslations>;
}) {
  const incidentLabels: Record<IncidentStatus, string> = {
    resolved: t('recentIncidents.resolved'),
    investigating: t('recentIncidents.investigating'),
    monitoring: t('recentIncidents.monitoring'),
  };

  return (
    <FadeInUp delay={index * 0.05}>
      <div className="bg-surface-1 border border-border rounded-xl p-5">
        <div className="flex flex-wrap items-center gap-3 mb-3">
          <span className="text-text-tertiary text-xs font-mono">{incident.date}</span>
          <span
            className={`inline-block rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
              incidentBadgeStyles[incident.status]
            }`}
          >
            {incidentLabels[incident.status]}
          </span>
        </div>
        <h4 className="text-text-primary text-sm font-semibold mb-2">{incident.title}</h4>
        <p className="text-text-secondary text-sm leading-relaxed">{incident.description}</p>
      </div>
    </FadeInUp>
  );
}

/* ════════════════════════  Main Component  ═══════════════════════ */

export default function StatusContent() {
  const t = useTranslations('status');
  const locale = useLocale();

  const [email, setEmail] = useState('');
  const [subStatus, setSubStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const overallStatus = getOverallStatus(services);

  const topServices = services.slice(0, 4);

  const statusLabels: Record<ServiceStatus, string> = {
    operational: t('operational'),
    degraded: t('degradedLabel'),
    outage: t('outageLabel'),
  };

  return (
    <>
      {/* ───────────── Hero ───────────── */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* ───────────── Overall Status Banner ───────────── */}
      <SectionWrapper spacing="tight">
        <OverallBanner status={overallStatus} t={t} locale={locale} />
      </SectionWrapper>

      {/* ───────────── Service Status List ───────────── */}
      <SectionWrapper>
        <FadeInUp>
          <h3 className="text-lg font-semibold text-text-primary mb-2">{t('currentStatus')}</h3>
          <p className="text-text-secondary text-sm mb-6">{t('currentStatusDesc')}</p>
        </FadeInUp>

        <div>
          {services.map((service, idx) => (
            <ServiceRow
              key={service.name}
              service={service}
              index={idx}
              statusLabel={statusLabels[service.status]}
            />
          ))}
        </div>
      </SectionWrapper>

      {/* ───────────── Uptime History Charts ───────────── */}
      <SectionWrapper dark>
        <FadeInUp>
          <h3 className="text-lg font-semibold text-text-primary mb-2">
            {t('uptimeHistory.title')}
          </h3>
          <p className="text-text-secondary text-sm mb-8">{t('uptimeHistory.desc')}</p>
        </FadeInUp>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {topServices.map((service, idx) => (
            <UptimeChart key={service.name} service={service} index={idx} t={t} />
          ))}
        </div>

        {/* Legend */}
        <FadeInUp delay={0.2}>
          <div className="flex items-center justify-center gap-6 mt-8">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-sm bg-brand-sage" />
              <span className="text-text-tertiary text-xs">{t('operational')}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-sm bg-amber-400/60" />
              <span className="text-text-tertiary text-xs">
                {t('uptimeHistory.degradedPerformance')}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-sm bg-red-400" />
              <span className="text-text-tertiary text-xs">{t('outageLabel')}</span>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Incident History ───────────── */}
      <SectionWrapper>
        <FadeInUp>
          <h3 className="text-lg font-semibold text-text-primary mb-2">
            {t('recentIncidents.title')}
          </h3>
          <p className="text-text-secondary text-sm mb-8">{t('recentIncidents.desc')}</p>
        </FadeInUp>

        <div className="space-y-4 max-w-3xl">
          {incidents.map((incident, idx) => (
            <IncidentCard
              key={incident.date + incident.title}
              incident={incident}
              index={idx}
              t={t}
            />
          ))}
        </div>

        {/* No incidents fallback */}
        {incidents.length === 0 && (
          <FadeInUp>
            <div className="text-center py-12">
              <CheckIcon size={32} className="text-brand-sage mx-auto mb-3" />
              <p className="text-text-secondary text-sm">{t('noIncidents')}</p>
            </div>
          </FadeInUp>
        )}
      </SectionWrapper>

      {/* ───────────── Subscribe Section ───────────── */}
      <SectionWrapper dark>
        <FadeInUp>
          <div className="text-center max-w-xl mx-auto">
            <MonitorIcon size={32} className="text-brand-sage mx-auto mb-5" />
            <h2 className="text-[clamp(24px,3vw,36px)] font-bold text-text-primary leading-[1.1]">
              {t('getUpdates.title')}
            </h2>
            <p className="text-text-secondary mt-3 leading-relaxed text-sm">
              {t('getUpdates.desc')}
            </p>

            {subStatus === 'success' ? (
              <p className="mt-8 text-sm text-status-safe font-medium">
                {t('getUpdates.success', { email })}
              </p>
            ) : (
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!email) return;
                  setSubStatus('loading');
                  try {
                    const res = await fetch('/api/waitlist', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ email, source: 'status-updates' }),
                    });
                    if (!res.ok) throw new Error('fail');
                    setSubStatus('success');
                  } catch {
                    setSubStatus('error');
                  }
                }}
                className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3"
              >
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder={t('getUpdates.emailPlaceholder')}
                  aria-label={t('getUpdates.emailAriaLabel')}
                  className="w-full sm:w-auto sm:min-w-[280px] rounded-full border border-border bg-surface-1 px-5 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
                />
                <button
                  type="submit"
                  disabled={subStatus === 'loading'}
                  className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3 text-sm hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] whitespace-nowrap disabled:opacity-60"
                >
                  {subStatus === 'loading' ? '...' : t('getUpdates.subscribe')}
                </button>
              </form>
            )}
            {subStatus === 'error' && (
              <p className="mt-3 text-sm text-status-alert">{t('getUpdates.error')}</p>
            )}

            {/* Notification channels */}
            <div className="flex items-center justify-center gap-6 mt-8">
              <span className="flex items-center gap-2 text-text-muted text-sm">
                <Rss size={16} />
                <span>{t('channels.rss')}</span>
              </span>
              <span className="flex items-center gap-2 text-text-muted text-sm">
                <MessageSquare size={16} />
                <span>{t('channels.slack')}</span>
              </span>
              <span className="flex items-center gap-2 text-text-muted text-sm">
                <Mail size={16} />
                <span>{t('channels.email')}</span>
              </span>
            </div>
            <p className="text-[11px] text-text-muted mt-2">{t('channels.note')}</p>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
