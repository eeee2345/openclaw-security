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
/*  Mock Data                                                          */
/* ------------------------------------------------------------------ */

const STAT_CARDS: readonly StatCard[] = [
  {
    id: 'endpoints',
    label: 'Endpoints Monitored',
    value: '247',
    change: '+12 this week',
    changeType: 'positive',
    icon: Monitor,
    accentColor: 'text-brand-sage',
  },
  {
    id: 'threats',
    label: 'Active Threats',
    value: '8',
    change: '-3 from yesterday',
    changeType: 'positive',
    icon: ShieldAlert,
    accentColor: 'text-status-danger',
  },
  {
    id: 'agents',
    label: 'Guard Agents Online',
    value: '241',
    change: '97.6% uptime',
    changeType: 'neutral',
    icon: Cpu,
    accentColor: 'text-status-safe',
  },
  {
    id: 'blocked',
    label: 'Threats Blocked (30d)',
    value: '1,429',
    change: '+18% vs last month',
    changeType: 'negative',
    icon: TrendingUp,
    accentColor: 'text-status-caution',
  },
] as const;

const RECENT_ALERTS: readonly RecentAlert[] = [
  {
    id: 'a1',
    severity: 'critical',
    message: 'Rootkit installation attempt detected on prod-web-03',
    source: '192.168.1.45',
    timestamp: '2 min ago',
  },
  {
    id: 'a2',
    severity: 'high',
    message: 'Suspicious outbound connection to known C2 server',
    source: '10.0.2.18',
    timestamp: '15 min ago',
  },
  {
    id: 'a3',
    severity: 'medium',
    message: 'Unusual privilege escalation pattern on dev-api-01',
    source: '172.16.0.22',
    timestamp: '42 min ago',
  },
  {
    id: 'a4',
    severity: 'high',
    message: 'Port scan detected from external IP targeting SSH services',
    source: '203.0.113.42',
    timestamp: '1h ago',
  },
  {
    id: 'a5',
    severity: 'low',
    message: 'New package installed outside maintenance window',
    source: '10.0.1.55',
    timestamp: '2h ago',
  },
  {
    id: 'a6',
    severity: 'medium',
    message: 'Modified system binary checksum mismatch on staging-db-02',
    source: '172.16.0.88',
    timestamp: '3h ago',
  },
] as const;

const AGENT_STATUSES: readonly AgentStatus[] = [
  { id: 'g1', hostname: 'prod-web-01', os: 'Ubuntu 22.04', status: 'online', version: '0.9.3', lastSeen: 'Just now', threatCount: 0 },
  { id: 'g2', hostname: 'prod-web-02', os: 'Ubuntu 22.04', status: 'online', version: '0.9.3', lastSeen: 'Just now', threatCount: 1 },
  { id: 'g3', hostname: 'prod-web-03', os: 'Ubuntu 22.04', status: 'warning', version: '0.9.2', lastSeen: '5 min ago', threatCount: 3 },
  { id: 'g4', hostname: 'prod-api-01', os: 'Debian 12', status: 'online', version: '0.9.3', lastSeen: 'Just now', threatCount: 0 },
  { id: 'g5', hostname: 'prod-db-01', os: 'Rocky Linux 9', status: 'online', version: '0.9.3', lastSeen: '1 min ago', threatCount: 0 },
  { id: 'g6', hostname: 'staging-web-01', os: 'Ubuntu 22.04', status: 'online', version: '0.9.3', lastSeen: 'Just now', threatCount: 0 },
  { id: 'g7', hostname: 'staging-db-02', os: 'Rocky Linux 9', status: 'warning', version: '0.9.1', lastSeen: '8 min ago', threatCount: 2 },
  { id: 'g8', hostname: 'dev-api-01', os: 'macOS 14.3', status: 'online', version: '0.9.3', lastSeen: '2 min ago', threatCount: 1 },
  { id: 'g9', hostname: 'dev-ml-gpu-01', os: 'Ubuntu 22.04', status: 'offline', version: '0.9.0', lastSeen: '2 days ago', threatCount: 0 },
  { id: 'g10', hostname: 'ci-runner-01', os: 'Debian 12', status: 'online', version: '0.9.3', lastSeen: 'Just now', threatCount: 0 },
  { id: 'g11', hostname: 'ci-runner-02', os: 'Debian 12', status: 'online', version: '0.9.3', lastSeen: '1 min ago', threatCount: 0 },
  { id: 'g12', hostname: 'backup-srv-01', os: 'Rocky Linux 9', status: 'online', version: '0.9.2', lastSeen: '3 min ago', threatCount: 0 },
] as const;

/** Bar chart data: threats per day for the last 14 days */
const THREAT_TREND_DATA: readonly { day: string; count: number }[] = [
  { day: 'Feb 17', count: 12 },
  { day: 'Feb 18', count: 8 },
  { day: 'Feb 19', count: 15 },
  { day: 'Feb 20', count: 22 },
  { day: 'Feb 21', count: 18 },
  { day: 'Feb 22', count: 9 },
  { day: 'Feb 23', count: 6 },
  { day: 'Feb 24', count: 14 },
  { day: 'Feb 25', count: 28 },
  { day: 'Feb 26', count: 19 },
  { day: 'Feb 27', count: 11 },
  { day: 'Feb 28', count: 7 },
  { day: 'Mar 1', count: 16 },
  { day: 'Mar 2', count: 8 },
] as const;

const MAX_THREAT_COUNT = Math.max(...THREAT_TREND_DATA.map((d) => d.count));

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
/*  Main Component                                                     */
/* ------------------------------------------------------------------ */

export default function DashboardContent() {
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [liveAgents, setLiveAgents] = useState<AgentStatus[] | null>(null);
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

  const displayedAgents = liveAgents ?? [...AGENT_STATUSES];

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
        {STAT_CARDS.map((stat, i) => (
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
            <div className="flex items-end gap-1.5 h-40">
              {THREAT_TREND_DATA.map((bar) => {
                const heightPct = MAX_THREAT_COUNT > 0 ? (bar.count / MAX_THREAT_COUNT) * 100 : 0;
                const isHigh = bar.count > 20;
                return (
                  <div key={bar.day} className="flex-1 flex flex-col items-center gap-1 group">
                    <span className="text-[10px] text-text-tertiary opacity-0 group-hover:opacity-100 transition-opacity font-mono">
                      {bar.count}
                    </span>
                    <div className="w-full relative">
                      <div
                        className={`w-full rounded-t transition-all duration-300 group-hover:opacity-80 ${
                          isHigh ? 'bg-status-caution' : 'bg-brand-sage'
                        }`}
                        style={{ height: `${Math.max(4, (heightPct / 100) * 120)}px` }}
                      />
                    </div>
                    <span className="text-[9px] text-text-muted truncate w-full text-center hidden sm:block">
                      {bar.day.split(' ')[1]}
                    </span>
                  </div>
                );
              })}
            </div>
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
            <div className="space-y-3 max-h-[300px] overflow-y-auto">
              {RECENT_ALERTS.map((alert) => (
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
        </div>
      </FadeInUp>

      {/* Threat Cloud Status */}
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
                  {isConnected ? 'Manager Connected' : 'Threat Cloud Connected'}
                </h2>
                <p className="text-xs text-text-tertiary mt-0.5">
                  {isConnected
                    ? `Live data from ${displayedAgents.length} agents via manager SSE stream`
                    : 'Receiving real-time threat intelligence from 12,847 global sensors'}
                </p>
              </div>
            </div>
            <div className="hidden sm:flex items-center gap-4 text-xs">
              <div className="text-center">
                <p className="font-mono text-text-primary font-semibold">48ms</p>
                <p className="text-text-muted">Avg latency</p>
              </div>
              <div className="w-px h-8 bg-border" />
              <div className="text-center">
                <p className="font-mono text-text-primary font-semibold">99.97%</p>
                <p className="text-text-muted">Uptime</p>
              </div>
              <div className="w-px h-8 bg-border" />
              <div className="text-center">
                <p className="font-mono text-text-primary font-semibold">2.1M</p>
                <p className="text-text-muted">IoCs cached</p>
              </div>
            </div>
          </div>
        </div>
      </FadeInUp>
    </div>
  );
}
