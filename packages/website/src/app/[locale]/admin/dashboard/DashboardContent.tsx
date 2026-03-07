'use client';

import { useState, useEffect } from 'react';
import FadeInUp from '@/components/FadeInUp';
import {
  Monitor,
  ShieldAlert,
  Cpu,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Clock,
  ArrowUpRight,
  Wifi,
  WifiOff,
  Download,
} from 'lucide-react';
import { SEVERITY_CONFIG, type ThreatSeverity } from '../config/threat-cloud';
import { fetchAgents, connectManagerSSE, type ManagerAgent } from '@/lib/manager-api';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface StatCard {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  readonly change: string;
  readonly changeType: 'positive' | 'negative' | 'neutral';
  readonly icon: React.ComponentType<{ className?: string }>;
  readonly accentColor: string;
}

interface RecentAlert {
  readonly id: string;
  readonly severity: ThreatSeverity;
  readonly message: string;
  readonly source: string;
  readonly timestamp: string;
}

interface AgentStatus {
  readonly id: string;
  readonly hostname: string;
  readonly os: string;
  readonly status: 'online' | 'offline' | 'warning';
  readonly version: string;
  readonly lastSeen: string;
  readonly threatCount: number;
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */

function StatCardComponent({ stat, index }: { stat: StatCard; index: number }) {
  const Icon = stat.icon;
  const ChangeIcon = stat.changeType === 'negative' ? TrendingDown : TrendingUp;

  return (
    <FadeInUp delay={index * 0.08}>
      <div className="bg-surface-1 border border-border rounded-xl p-5 card-glow">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs text-text-tertiary uppercase tracking-wider font-medium">
            {stat.label}
          </span>
          <div className={`${stat.accentColor} bg-surface-2 p-2 rounded-lg`}>
            <Icon className="w-4 h-4" />
          </div>
        </div>
        <p className="text-3xl font-bold text-text-primary font-mono">{stat.value}</p>
        <div className="flex items-center gap-1.5 mt-2">
          <ChangeIcon
            className={`w-3.5 h-3.5 ${
              stat.changeType === 'positive'
                ? 'text-status-safe'
                : stat.changeType === 'negative'
                  ? 'text-status-caution'
                  : 'text-text-tertiary'
            }`}
          />
          <span className="text-xs text-text-secondary">{stat.change}</span>
        </div>
      </div>
    </FadeInUp>
  );
}

function SeverityBadge({ severity }: { severity: ThreatSeverity }) {
  const config = SEVERITY_CONFIG[severity];
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${config.bgColor} ${config.color} ${config.borderColor}`}
    >
      {config.label}
    </span>
  );
}

function StatusDot({ status }: { status: 'online' | 'offline' | 'warning' }) {
  const colorMap = {
    online: 'bg-status-safe',
    warning: 'bg-status-caution',
    offline: 'bg-status-danger',
  } as const;

  return (
    <span className="relative flex h-2.5 w-2.5">
      {status === 'online' && (
        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${colorMap[status]} opacity-40`} />
      )}
      <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${colorMap[status]}`} />
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Empty State                                                        */
/* ------------------------------------------------------------------ */

function EmptyState({ icon: Icon, title, description }: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="bg-surface-2 p-3 rounded-xl mb-4">
        <Icon className="w-6 h-6 text-text-muted" />
      </div>
      <p className="text-sm font-medium text-text-secondary">{title}</p>
      <p className="text-xs text-text-tertiary mt-1 max-w-sm">{description}</p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main Component                                                     */
/* ------------------------------------------------------------------ */

export default function DashboardContent() {
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [liveAgents, setLiveAgents] = useState<AgentStatus[] | null>(null);
  const [liveAlerts] = useState<RecentAlert[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    let cancelled = false;

    // Try to fetch real agent data from manager
    fetchAgents().then((agents) => {
      if (cancelled || !agents) return;
      setLiveAgents(
        agents.map((a: ManagerAgent) => ({
          id: a.agentId,
          hostname: a.hostname,
          os: a.os,
          status: a.status,
          version: a.version,
          lastSeen: a.lastSeen,
          threatCount: a.threatCount,
        }))
      );
      setIsConnected(true);
    });

    // Connect to SSE for real-time updates
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const cleanup = connectManagerSSE((type, _) => {
      if (type === 'agent_online' || type === 'agent_offline' || type === 'threats_reported') {
        // Refetch agents on status changes
        fetchAgents().then((agents) => {
          if (cancelled || !agents) return;
          setLiveAgents(
            agents.map((a: ManagerAgent) => ({
              id: a.agentId,
              hostname: a.hostname,
              os: a.os,
              status: a.status,
              version: a.version,
              lastSeen: a.lastSeen,
              threatCount: a.threatCount,
            }))
          );
        });
      }
    });

    return () => {
      cancelled = true;
      cleanup();
    };
  }, []);

  const displayedAgents = liveAgents ?? [];
  const onlineCount = displayedAgents.filter((a) => a.status === 'online').length;
  const threatCount = displayedAgents.reduce((sum, a) => sum + a.threatCount, 0);

  const statCards: readonly StatCard[] = [
    {
      id: 'endpoints',
      label: 'Endpoints Monitored',
      value: String(displayedAgents.length),
      change: displayedAgents.length === 0 ? 'Install Guard to get started' : `${onlineCount} online`,
      changeType: 'neutral',
      icon: Monitor,
      accentColor: 'text-brand-sage',
    },
    {
      id: 'threats',
      label: 'Active Threats',
      value: String(threatCount),
      change: threatCount === 0 ? 'All clear' : `${threatCount} detected`,
      changeType: threatCount === 0 ? 'positive' : 'negative',
      icon: ShieldAlert,
      accentColor: threatCount > 0 ? 'text-status-danger' : 'text-status-safe',
    },
    {
      id: 'agents',
      label: 'Guard Agents Online',
      value: String(onlineCount),
      change: displayedAgents.length === 0 ? 'No agents connected' : `${displayedAgents.length} total`,
      changeType: 'neutral',
      icon: Cpu,
      accentColor: 'text-status-safe',
    },
    {
      id: 'blocked',
      label: 'Threats Blocked (30d)',
      value: '0',
      change: 'No data yet',
      changeType: 'neutral',
      icon: TrendingUp,
      accentColor: 'text-status-caution',
    },
  ] as const;

  return (
    <div className="space-y-6 max-w-[1400px]">
      {/* Page header */}
      <FadeInUp>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-text-primary">Security Dashboard</h1>
            <p className="text-sm text-text-secondary mt-1">
              Real-time overview of your security posture
            </p>
          </div>
          <div className="hidden sm:flex items-center gap-2 text-xs text-text-tertiary">
            <Clock className="w-3.5 h-3.5" />
            <span>Last updated: just now</span>
          </div>
        </div>
      </FadeInUp>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((stat, i) => (
          <StatCardComponent key={stat.id} stat={stat} index={i} />
        ))}
      </div>

      {/* Threat trend + Recent alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Threat Trend Chart */}
        <FadeInUp delay={0.1}>
          <div className="lg:col-span-3 bg-surface-1 border border-border rounded-xl p-5 card-glow">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-sm font-semibold text-text-primary">Threat Trend (14 days)</h2>
              <span className="text-xs text-text-tertiary">Daily detected threats</span>
            </div>
            <EmptyState
              icon={TrendingUp}
              title="No threat data yet"
              description="Threat trends will appear here once Guard agents start reporting."
            />
          </div>
        </FadeInUp>

        {/* Recent Alerts */}
        <FadeInUp delay={0.15}>
          <div className="lg:col-span-2 bg-surface-1 border border-border rounded-xl p-5 card-glow">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-status-caution" />
                Recent Alerts
              </h2>
              <a
                href="/admin/threats"
                className="text-xs text-brand-sage hover:text-brand-sage-light transition-colors flex items-center gap-1"
              >
                View all <ArrowUpRight className="w-3 h-3" />
              </a>
            </div>
            {liveAlerts.length === 0 ? (
              <EmptyState
                icon={ShieldAlert}
                title="No alerts"
                description="Security alerts will appear here when threats are detected."
              />
            ) : (
              <div className="space-y-3 max-h-[300px] overflow-y-auto">
                {liveAlerts.map((alert) => (
                  <button
                    key={alert.id}
                    onClick={() => setSelectedAlertId(selectedAlertId === alert.id ? null : alert.id)}
                    className={`w-full text-left p-3 rounded-lg border transition-all duration-200 ${
                      selectedAlertId === alert.id
                        ? 'bg-surface-2 border-brand-sage/30'
                        : 'bg-surface-2/50 border-transparent hover:border-border-hover'
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      <SeverityBadge severity={alert.severity} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-text-primary leading-relaxed line-clamp-2">
                          {alert.message}
                        </p>
                        <div className="flex items-center gap-2 mt-1.5">
                          <span className="text-[10px] text-text-tertiary font-mono">
                            {alert.source}
                          </span>
                          <span className="text-[10px] text-text-muted">{alert.timestamp}</span>
                        </div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </FadeInUp>
      </div>

      {/* Agent Status Grid */}
      <FadeInUp delay={0.2}>
        <div className="bg-surface-1 border border-border rounded-xl p-5 card-glow">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Cpu className="w-4 h-4 text-brand-sage" />
              Guard Agent Status
            </h2>
            <div className="flex items-center gap-4 text-xs text-text-tertiary">
              <span className="flex items-center gap-1.5">
                <StatusDot status="online" />
                Online
              </span>
              <span className="flex items-center gap-1.5">
                <StatusDot status="warning" />
                Warning
              </span>
              <span className="flex items-center gap-1.5">
                <StatusDot status="offline" />
                Offline
              </span>
            </div>
          </div>

          {displayedAgents.length === 0 ? (
            <EmptyState
              icon={Download}
              title="No Guard agents connected"
              description="Install Panguard Guard on your endpoints to see them here. Run: curl -fsSL https://get.panguard.ai | bash"
            />
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {displayedAgents.map((agent) => (
                <div
                  key={agent.id}
                  className={`p-3 rounded-lg border transition-colors ${
                    agent.status === 'offline'
                      ? 'bg-surface-2/30 border-border opacity-60'
                      : agent.status === 'warning'
                        ? 'bg-surface-2/50 border-status-caution/20'
                        : 'bg-surface-2/50 border-border hover:border-border-hover'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <StatusDot status={agent.status} />
                      <span className="text-sm font-medium text-text-primary truncate font-mono">
                        {agent.hostname}
                      </span>
                    </div>
                    {agent.threatCount > 0 && (
                      <span className="text-[10px] font-semibold bg-status-danger/10 text-status-danger border border-status-danger/20 px-1.5 py-0.5 rounded-full">
                        {agent.threatCount}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-text-tertiary">
                    <span>{agent.os}</span>
                    <span>v{agent.version}</span>
                  </div>
                  <div className="flex items-center gap-1 mt-1.5">
                    <Clock className="w-3 h-3 text-text-muted" />
                    <span className="text-[10px] text-text-muted">{agent.lastSeen}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </FadeInUp>

      {/* Connection Status */}
      <FadeInUp delay={0.25}>
        <div className="bg-surface-1 border border-border rounded-xl p-5 card-glow">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`${isConnected ? 'bg-status-safe/10' : 'bg-surface-2'} p-2 rounded-lg`}>
                {isConnected ? (
                  <Wifi className="w-5 h-5 text-status-safe" />
                ) : (
                  <WifiOff className="w-5 h-5 text-text-muted" />
                )}
              </div>
              <div>
                <h2 className="text-sm font-semibold text-text-primary">
                  {isConnected ? 'Manager Connected' : 'Waiting for Connection'}
                </h2>
                <p className="text-xs text-text-tertiary mt-0.5">
                  {isConnected
                    ? `Live data from ${displayedAgents.length} agents via manager SSE stream`
                    : 'Connect Guard agents to see real-time data'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </FadeInUp>
    </div>
  );
}
