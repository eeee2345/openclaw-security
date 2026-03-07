'use client';

import { useState, useMemo } from 'react';
import FadeInUp from '@/components/FadeInUp';
import {
  ShieldAlert,
  Search,
  Filter,
  Clock,
  Globe,
  Monitor,
  ArrowUpDown,
  AlertTriangle,
  Crosshair,
  Network,
  Bug,
  KeyRound,
  Wifi,
  FileWarning,
  ShieldCheck,
} from 'lucide-react';
import { SEVERITY_CONFIG, type ThreatSeverity } from '../config/threat-cloud';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type ThreatType =
  | 'rootkit'
  | 'c2_communication'
  | 'privilege_escalation'
  | 'port_scan'
  | 'unauthorized_package'
  | 'binary_modification'
  | 'brute_force'
  | 'data_exfiltration'
  | 'malware_download'
  | 'reverse_shell';

type SeverityFilter = 'all' | ThreatSeverity;

interface ThreatEvent {
  readonly id: string;
  readonly severity: ThreatSeverity;
  readonly type: ThreatType;
  readonly typeLabel: string;
  readonly description: string;
  readonly sourceIp: string;
  readonly targetEndpoint: string;
  readonly timestamp: string;
  readonly timestampRelative: string;
  readonly seenOnEndpoints: number;
  readonly status: 'active' | 'mitigated' | 'investigating';
  readonly confidence: number;
}

/* ------------------------------------------------------------------ */
/*  Live data — starts empty, populated by manager SSE                */
/* ------------------------------------------------------------------ */

const THREAT_EVENTS: readonly ThreatEvent[] = [];

/* ------------------------------------------------------------------ */
/*  Utility                                                            */
/* ------------------------------------------------------------------ */

function getThreatIcon(type: ThreatType) {
  const iconMap: Record<ThreatType, React.ComponentType<{ className?: string }>> = {
    rootkit: Bug,
    c2_communication: Network,
    privilege_escalation: KeyRound,
    port_scan: Crosshair,
    unauthorized_package: FileWarning,
    binary_modification: FileWarning,
    brute_force: KeyRound,
    data_exfiltration: Wifi,
    malware_download: Bug,
    reverse_shell: Network,
  };
  const Icon = iconMap[type];
  return <Icon className="w-4 h-4" />;
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

function StatusBadge({ status }: { status: 'active' | 'mitigated' | 'investigating' }) {
  const styles = {
    active: 'bg-status-danger/10 text-status-danger border-status-danger/20',
    investigating: 'bg-status-caution/10 text-status-caution border-status-caution/20',
    mitigated: 'bg-status-safe/10 text-status-safe border-status-safe/20',
  } as const;

  const labels = {
    active: 'Active',
    investigating: 'Investigating',
    mitigated: 'Mitigated',
  } as const;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${styles[status]}`}
    >
      {labels[status]}
    </span>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const color =
    confidence >= 90
      ? 'bg-status-danger'
      : confidence >= 70
        ? 'bg-status-caution'
        : 'bg-status-info';

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-surface-3 rounded-full">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${confidence}%` }}
        />
      </div>
      <span className="text-[10px] font-mono text-text-muted">{confidence}%</span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Filter config                                                      */
/* ------------------------------------------------------------------ */

const SEVERITY_FILTERS: readonly { value: SeverityFilter; label: string }[] = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
] as const;

/* ------------------------------------------------------------------ */
/*  Main Component                                                     */
/* ------------------------------------------------------------------ */

export default function ThreatsContent() {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'time' | 'severity' | 'confidence'>('time');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredThreats = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();

    const filtered = THREAT_EVENTS.filter((threat) => {
      if (severityFilter !== 'all' && threat.severity !== severityFilter) return false;
      if (query) {
        return (
          threat.description.toLowerCase().includes(query) ||
          threat.typeLabel.toLowerCase().includes(query) ||
          threat.sourceIp.includes(query) ||
          threat.targetEndpoint.toLowerCase().includes(query)
        );
      }
      return true;
    });

    const sorted = [...filtered];
    sorted.sort((a, b) => {
      switch (sortBy) {
        case 'severity': {
          const order: Record<ThreatSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
          return order[a.severity] - order[b.severity];
        }
        case 'confidence':
          return b.confidence - a.confidence;
        default:
          return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      }
    });

    return sorted;
  }, [severityFilter, searchQuery, sortBy]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { all: THREAT_EVENTS.length };
    for (const t of THREAT_EVENTS) {
      counts[t.severity] = (counts[t.severity] || 0) + 1;
    }
    return counts;
  }, []);

  return (
    <div className="space-y-6 max-w-[1400px]">
      {/* Page header */}
      <FadeInUp>
        <div>
          <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-status-danger" />
            Threat Feed
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Aggregated threats across all monitored endpoints
          </p>
        </div>
      </FadeInUp>

      {/* Summary cards */}
      <FadeInUp delay={0.05}>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
            const config = SEVERITY_CONFIG[sev];
            const count = severityCounts[sev] || 0;
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? 'all' : sev)}
                className={`bg-surface-1 border rounded-xl p-4 text-left transition-all duration-200 ${
                  severityFilter === sev
                    ? `${config.borderColor} border-2`
                    : 'border-border hover:border-border-hover'
                }`}
              >
                <span className={`text-xs uppercase tracking-wider font-medium ${config.color}`}>
                  {config.label}
                </span>
                <p className="text-2xl font-bold text-text-primary font-mono mt-1">{count}</p>
              </button>
            );
          })}
        </div>
      </FadeInUp>

      {THREAT_EVENTS.length > 0 && (
        <>
          {/* Filters */}
          <FadeInUp delay={0.08}>
            <div className="flex flex-col sm:flex-row gap-3">
              {/* Search */}
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                <input
                  type="text"
                  placeholder="Search by description, type, IP, or endpoint..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-surface-1 border border-border rounded-lg pl-9 pr-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-brand-sage focus:border-brand-sage transition-colors"
                />
              </div>

              {/* Severity filter pills */}
              <div className="flex items-center gap-1.5">
                <Filter className="w-4 h-4 text-text-muted mr-1" />
                {SEVERITY_FILTERS.map((filter) => (
                  <button
                    key={filter.value}
                    onClick={() => setSeverityFilter(filter.value)}
                    className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-200 ${
                      severityFilter === filter.value
                        ? 'bg-brand-sage/15 text-brand-sage border border-brand-sage/30'
                        : 'bg-surface-2 text-text-secondary border border-transparent hover:border-border-hover'
                    }`}
                  >
                    {filter.label}
                  </button>
                ))}
              </div>

              {/* Sort */}
              <div className="flex items-center gap-1.5">
                <ArrowUpDown className="w-4 h-4 text-text-muted" />
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
                  className="bg-surface-2 border border-border rounded-lg px-3 py-1.5 text-xs text-text-secondary focus:outline-none focus:ring-1 focus:ring-brand-sage appearance-none cursor-pointer"
                >
                  <option value="time">Most recent</option>
                  <option value="severity">Severity</option>
                  <option value="confidence">Confidence</option>
                </select>
              </div>
            </div>
          </FadeInUp>
        </>
      )}

      {/* Threat list */}
      <FadeInUp delay={0.12}>
        <div className="space-y-3">
          {filteredThreats.length === 0 && (
            <div className="bg-surface-1 border border-border rounded-xl px-5 py-16 text-center card-glow">
              <div className="bg-surface-2 p-3 rounded-xl inline-block mb-4">
                <ShieldCheck className="w-6 h-6 text-status-safe" />
              </div>
              <p className="text-sm font-medium text-text-secondary">No threats detected</p>
              <p className="text-xs text-text-tertiary mt-1 max-w-sm mx-auto">
                {THREAT_EVENTS.length === 0
                  ? 'Threats will appear here once Guard agents start monitoring your endpoints.'
                  : 'Try adjusting the severity filter or search query'}
              </p>
            </div>
          )}

          {filteredThreats.map((threat) => {
            const isExpanded = expandedId === threat.id;

            return (
              <button
                key={threat.id}
                onClick={() => setExpandedId(isExpanded ? null : threat.id)}
                className="w-full text-left bg-surface-1 border border-border rounded-xl overflow-hidden transition-all duration-200 hover:border-border-hover card-glow"
              >
                {/* Main row */}
                <div className="px-5 py-4">
                  <div className="flex items-start gap-3">
                    {/* Threat type icon */}
                    <div className={`mt-0.5 ${SEVERITY_CONFIG[threat.severity].color}`}>
                      {getThreatIcon(threat.type)}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center flex-wrap gap-2 mb-1.5">
                        <SeverityBadge severity={threat.severity} />
                        <span className="text-xs font-semibold text-text-primary">
                          {threat.typeLabel}
                        </span>
                        <StatusBadge status={threat.status} />
                        {threat.seenOnEndpoints > 1 && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-status-info bg-status-info/10 border border-status-info/20 px-1.5 py-0.5 rounded-full font-medium">
                            <Globe className="w-3 h-3" />
                            Seen on {threat.seenOnEndpoints} endpoints
                          </span>
                        )}
                      </div>

                      <p className={`text-sm text-text-secondary leading-relaxed ${isExpanded ? '' : 'line-clamp-1'}`}>
                        {threat.description}
                      </p>

                      {/* Meta row */}
                      <div className="flex items-center flex-wrap gap-x-4 gap-y-1 mt-2">
                        <span className="flex items-center gap-1 text-xs text-text-tertiary">
                          <Globe className="w-3 h-3" />
                          <span className="font-mono">{threat.sourceIp}</span>
                        </span>
                        <span className="flex items-center gap-1 text-xs text-text-tertiary">
                          <Monitor className="w-3 h-3" />
                          <span className="font-mono">{threat.targetEndpoint}</span>
                        </span>
                        <span className="flex items-center gap-1 text-xs text-text-tertiary">
                          <Clock className="w-3 h-3" />
                          {threat.timestampRelative}
                        </span>
                        <div className="flex items-center gap-1 text-xs text-text-tertiary">
                          <AlertTriangle className="w-3 h-3" />
                          <ConfidenceBar confidence={threat.confidence} />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="px-5 pb-4 pt-0 border-t border-border/50">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-3">
                      <div>
                        <span className="text-[10px] uppercase tracking-wider text-text-muted font-medium">
                          Threat ID
                        </span>
                        <p className="text-xs font-mono text-text-secondary mt-0.5">{threat.id}</p>
                      </div>
                      <div>
                        <span className="text-[10px] uppercase tracking-wider text-text-muted font-medium">
                          Full Timestamp
                        </span>
                        <p className="text-xs font-mono text-text-secondary mt-0.5">
                          {new Date(threat.timestamp).toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <span className="text-[10px] uppercase tracking-wider text-text-muted font-medium">
                          Confidence Score
                        </span>
                        <p className="text-xs text-text-secondary mt-0.5">{threat.confidence}%</p>
                      </div>
                    </div>
                    <div className="mt-3">
                      <span className="text-[10px] uppercase tracking-wider text-text-muted font-medium">
                        Full Description
                      </span>
                      <p className="text-xs text-text-secondary leading-relaxed mt-0.5">
                        {threat.description}
                      </p>
                    </div>
                  </div>
                )}
              </button>
            );
          })}
        </div>
      </FadeInUp>
    </div>
  );
}
