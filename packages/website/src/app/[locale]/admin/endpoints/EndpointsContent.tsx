'use client';

import { useState, useMemo, useEffect } from 'react';
import FadeInUp from '@/components/FadeInUp';
import {
  Monitor,
  Search,
  Filter,
  Clock,
  ArrowUpDown,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Download,
} from 'lucide-react';
import { fetchAgents, type ManagerAgent } from '@/lib/manager-api';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type EndpointStatus = 'online' | 'offline' | 'warning';
type StatusFilter = 'all' | EndpointStatus;

interface Endpoint {
  readonly id: string;
  readonly hostname: string;
  readonly os: string;
  readonly guardVersion: string;
  readonly status: EndpointStatus;
  readonly lastHeartbeat: string;
  readonly lastHeartbeatRelative: string;
  readonly threatCount: number;
  readonly ipAddress: string;
  readonly cpuUsage: number;
  readonly memoryUsage: number;
  readonly tags: readonly string[];
}

/* ------------------------------------------------------------------ */
/*  Utility                                                            */
/* ------------------------------------------------------------------ */

function getStatusIcon(status: EndpointStatus) {
  switch (status) {
    case 'online':
      return <CheckCircle className="w-4 h-4 text-status-safe" />;
    case 'warning':
      return <AlertTriangle className="w-4 h-4 text-status-caution" />;
    case 'offline':
      return <XCircle className="w-4 h-4 text-status-danger" />;
  }
}

function getStatusLabel(status: EndpointStatus): string {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

function getUsageColor(pct: number): string {
  if (pct >= 80) return 'bg-status-danger';
  if (pct >= 60) return 'bg-status-caution';
  return 'bg-brand-sage';
}

/* ------------------------------------------------------------------ */
/*  Filter bar items                                                   */
/* ------------------------------------------------------------------ */

const STATUS_FILTERS: readonly { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'online', label: 'Online' },
  { value: 'warning', label: 'Warning' },
  { value: 'offline', label: 'Offline' },
] as const;

/* ------------------------------------------------------------------ */
/*  Main Component                                                     */
/* ------------------------------------------------------------------ */

export default function EndpointsContent() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'hostname' | 'status' | 'threats'>('hostname');

  useEffect(() => {
    fetchAgents()
      .then((agents) => {
        if (!agents) return;
        setEndpoints(
          agents.map((a: ManagerAgent) => ({
            id: a.agentId,
            hostname: a.hostname,
            os: a.os,
            guardVersion: a.version,
            status: a.status,
            lastHeartbeat: a.lastSeen,
            lastHeartbeatRelative: a.lastSeen,
            threatCount: a.threatCount,
            ipAddress: '',
            cpuUsage: 0,
            memoryUsage: 0,
            tags: [],
          }))
        );
      })
      .finally(() => setLoading(false));
  }, []);

  const filteredEndpoints = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();

    const filtered = endpoints.filter((ep) => {
      if (statusFilter !== 'all' && ep.status !== statusFilter) return false;
      if (query) {
        return (
          ep.hostname.toLowerCase().includes(query) ||
          ep.os.toLowerCase().includes(query) ||
          ep.ipAddress.includes(query) ||
          ep.tags.some((tag) => tag.toLowerCase().includes(query))
        );
      }
      return true;
    });

    const sortedEndpoints = [...filtered];
    sortedEndpoints.sort((a, b) => {
      switch (sortBy) {
        case 'status': {
          const order = { warning: 0, offline: 1, online: 2 };
          return order[a.status] - order[b.status];
        }
        case 'threats':
          return b.threatCount - a.threatCount;
        default:
          return a.hostname.localeCompare(b.hostname);
      }
    });

    return sortedEndpoints;
  }, [endpoints, statusFilter, searchQuery, sortBy]);

  const statusCounts = useMemo(() => {
    const counts = { all: endpoints.length, online: 0, warning: 0, offline: 0 };
    for (const ep of endpoints) {
      counts[ep.status]++;
    }
    return counts;
  }, [endpoints]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <RefreshCw className="w-5 h-5 text-brand-sage animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-[1400px]">
      {/* Page header */}
      <FadeInUp>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
              <Monitor className="w-6 h-6 text-brand-sage" />
              Endpoints
            </h1>
            <p className="text-sm text-text-secondary mt-1">
              {endpoints.length === 0
                ? 'No endpoints registered yet'
                : `${endpoints.length} endpoints registered across your infrastructure`}
            </p>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="inline-flex items-center gap-2 rounded-full bg-surface-2 border border-border text-text-secondary text-sm px-4 py-2 hover:border-brand-sage hover:text-text-primary transition-all duration-200"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </FadeInUp>

      {endpoints.length === 0 ? (
        <FadeInUp delay={0.05}>
          <div className="bg-surface-1 border border-border rounded-xl px-5 py-16 text-center card-glow">
            <div className="bg-surface-2 p-3 rounded-xl inline-block mb-4">
              <Download className="w-6 h-6 text-text-muted" />
            </div>
            <p className="text-sm font-medium text-text-secondary">No endpoints connected</p>
            <p className="text-xs text-text-tertiary mt-1 max-w-md mx-auto">
              Install Panguard Guard on your endpoints to monitor them here.
            </p>
            <code className="block mt-4 text-xs bg-surface-2 text-brand-sage px-4 py-2 rounded-lg font-mono max-w-md mx-auto">
              curl -fsSL https://get.panguard.ai | bash
            </code>
          </div>
        </FadeInUp>
      ) : (
        <>
          {/* Filters */}
          <FadeInUp delay={0.05}>
            <div className="flex flex-col sm:flex-row gap-3">
              {/* Search */}
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                <input
                  type="text"
                  placeholder="Search by hostname, IP, OS, or tag..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-surface-1 border border-border rounded-lg pl-9 pr-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-brand-sage focus:border-brand-sage transition-colors"
                />
              </div>

              {/* Status filter pills */}
              <div className="flex items-center gap-1.5">
                <Filter className="w-4 h-4 text-text-muted mr-1" />
                {STATUS_FILTERS.map((filter) => (
                  <button
                    key={filter.value}
                    onClick={() => setStatusFilter(filter.value)}
                    className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-200 ${
                      statusFilter === filter.value
                        ? 'bg-brand-sage/15 text-brand-sage border border-brand-sage/30'
                        : 'bg-surface-2 text-text-secondary border border-transparent hover:border-border-hover'
                    }`}
                  >
                    {filter.label}
                    <span className="ml-1.5 text-text-muted">
                      {statusCounts[filter.value]}
                    </span>
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
                  <option value="hostname">Sort by name</option>
                  <option value="status">Sort by status</option>
                  <option value="threats">Sort by threats</option>
                </select>
              </div>
            </div>
          </FadeInUp>

          {/* Endpoint list */}
          <FadeInUp delay={0.1}>
            <div className="bg-surface-1 border border-border rounded-xl overflow-hidden card-glow">
              {/* Table header */}
              <div className="hidden lg:grid grid-cols-[1fr_140px_100px_100px_120px_100px_80px] gap-4 px-5 py-3 border-b border-border text-xs text-text-tertiary uppercase tracking-wider font-medium">
                <span>Hostname</span>
                <span>Operating System</span>
                <span>Guard Ver.</span>
                <span>Status</span>
                <span>Last Heartbeat</span>
                <span>CPU / Mem</span>
                <span className="text-right">Threats</span>
              </div>

              {/* Table rows */}
              {filteredEndpoints.length === 0 && (
                <div className="px-5 py-12 text-center">
                  <Monitor className="w-8 h-8 text-text-muted mx-auto mb-3" />
                  <p className="text-sm text-text-secondary">No endpoints match your filters</p>
                  <p className="text-xs text-text-tertiary mt-1">Try adjusting the search or status filter</p>
                </div>
              )}

              {filteredEndpoints.map((ep, index) => (
                <div
                  key={ep.id}
                  className={`lg:grid lg:grid-cols-[1fr_140px_100px_100px_120px_100px_80px] gap-4 px-5 py-4 items-center transition-colors hover:bg-surface-2/30 ${
                    index < filteredEndpoints.length - 1 ? 'border-b border-border/50' : ''
                  }`}
                >
                  {/* Hostname + IP */}
                  <div className="flex items-center gap-3 mb-2 lg:mb-0">
                    <Monitor className="w-4 h-4 text-text-muted shrink-0 hidden sm:block" />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-text-primary font-mono truncate">
                        {ep.hostname}
                      </p>
                      {ep.ipAddress && (
                        <p className="text-[11px] text-text-muted font-mono">{ep.ipAddress}</p>
                      )}
                    </div>
                    {/* Tags */}
                    {ep.tags.length > 0 && (
                      <div className="hidden xl:flex items-center gap-1 ml-2">
                        {ep.tags.map((tag) => (
                          <span
                            key={tag}
                            className="text-[9px] uppercase tracking-wider bg-surface-2 text-text-tertiary px-1.5 py-0.5 rounded"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* OS */}
                  <div className="hidden lg:block">
                    <span className="text-xs text-text-secondary">{ep.os}</span>
                  </div>

                  {/* Guard version */}
                  <div className="hidden lg:block">
                    <span className="text-xs font-mono text-text-secondary">
                      v{ep.guardVersion}
                    </span>
                  </div>

                  {/* Status */}
                  <div className="flex items-center gap-1.5">
                    {getStatusIcon(ep.status)}
                    <span
                      className={`text-xs font-medium ${
                        ep.status === 'online'
                          ? 'text-status-safe'
                          : ep.status === 'warning'
                            ? 'text-status-caution'
                            : 'text-status-danger'
                      }`}
                    >
                      {getStatusLabel(ep.status)}
                    </span>
                  </div>

                  {/* Last heartbeat */}
                  <div className="hidden lg:flex items-center gap-1.5">
                    <Clock className="w-3 h-3 text-text-muted" />
                    <span className="text-xs text-text-tertiary">{ep.lastHeartbeatRelative}</span>
                  </div>

                  {/* CPU / Memory */}
                  <div className="hidden lg:block">
                    {ep.status !== 'offline' && (ep.cpuUsage > 0 || ep.memoryUsage > 0) ? (
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <div className="w-full h-1 bg-surface-3 rounded-full">
                            <div
                              className={`h-full rounded-full ${getUsageColor(ep.cpuUsage)}`}
                              style={{ width: `${ep.cpuUsage}%` }}
                            />
                          </div>
                          <span className="text-[10px] font-mono text-text-muted w-7 text-right">
                            {ep.cpuUsage}%
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-full h-1 bg-surface-3 rounded-full">
                            <div
                              className={`h-full rounded-full ${getUsageColor(ep.memoryUsage)}`}
                              style={{ width: `${ep.memoryUsage}%` }}
                            />
                          </div>
                          <span className="text-[10px] font-mono text-text-muted w-7 text-right">
                            {ep.memoryUsage}%
                          </span>
                        </div>
                      </div>
                    ) : (
                      <span className="text-xs text-text-muted">--</span>
                    )}
                  </div>

                  {/* Threat count */}
                  <div className="lg:text-right">
                    {ep.threatCount > 0 ? (
                      <span className="inline-flex items-center gap-1 text-xs font-semibold bg-status-danger/10 text-status-danger border border-status-danger/20 px-2 py-0.5 rounded-full">
                        <ShieldAlert className="w-3 h-3" />
                        {ep.threatCount}
                      </span>
                    ) : (
                      <span className="text-xs text-text-muted">0</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </FadeInUp>
        </>
      )}
    </div>
  );
}
