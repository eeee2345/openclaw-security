import { useLanguage } from '../../context/LanguageContext';
import { useApi } from '../../hooks/useApi';
import FeatureGate from '../../components/FeatureGate';

interface ThreatStats {
  totalThreats: number;
  totalRules: number;
  last24hThreats: number;
  topAttackTypes: Array<{ type: string; count: number; label: string }>;
  topMitreTechniques: Array<{ technique: string; name: string; count: number }>;
  regionDistribution: Array<{ region: string; count: number }>;
}

export default function DashboardThreat() {
  const { t } = useLanguage();
  const stats = useApi<ThreatStats>('/api/threat/stats');

  const maxAttackCount = stats.data
    ? Math.max(...stats.data.topAttackTypes.map(a => a.count), 1)
    : 1;

  const maxTechniqueCount = stats.data
    ? Math.max(...stats.data.topMitreTechniques.map(t => t.count), 1)
    : 1;

  return (
    <FeatureGate
      requiredTier="solo"
      featureNameEn="Threat Intelligence"
      featureNameZh="威脅情報"
      descriptionEn="Global threat landscape with MITRE ATT&CK mapping and regional distribution."
      descriptionZh="全球威脅態勢，含 MITRE ATT&CK 對照與區域分佈。"
    >
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold">{t('Threat Intelligence', '威脅情報')}</h1>
        <p className="text-sm text-brand-muted">
          {t('Global threat landscape overview', '全球威脅態勢總覽')}
        </p>
      </div>

      {stats.loading && (
        <div className="py-12 text-center text-brand-muted">{t('Loading...', '載入中...')}</div>
      )}

      {stats.error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
          {stats.error}
        </div>
      )}

      {stats.data && (
        <>
          {/* Stats Cards */}
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="card text-center">
              <div className="text-3xl font-bold text-brand-cyan">{stats.data.totalThreats.toLocaleString()}</div>
              <div className="mt-1 text-xs text-brand-muted">{t('Total Threats', '總威脅數')}</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold text-brand-cyan">{stats.data.totalRules}</div>
              <div className="mt-1 text-xs text-brand-muted">{t('Detection Rules', '偵測規則')}</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold text-yellow-400">{stats.data.last24hThreats}</div>
              <div className="mt-1 text-xs text-brand-muted">{t('Last 24h', '最近 24 小時')}</div>
            </div>
          </div>

          {/* Two column layout */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Top Attack Types */}
            <div className="card">
              <h3 className="mb-4 font-semibold">{t('Top Attack Types', '主要攻擊類型')}</h3>
              <div className="space-y-3">
                {stats.data.topAttackTypes.map(a => (
                  <div key={a.type}>
                    <div className="mb-1 flex items-center justify-between text-sm">
                      <span>{a.label}</span>
                      <span className="font-mono text-brand-cyan">{a.count}</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-brand-dark">
                      <div
                        className="h-full rounded-full bg-brand-cyan"
                        style={{ width: `${(a.count / maxAttackCount) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* MITRE ATT&CK Techniques */}
            <div className="card">
              <h3 className="mb-4 font-semibold">{t('MITRE ATT&CK Techniques', 'MITRE ATT&CK 技術')}</h3>
              <div className="space-y-3">
                {stats.data.topMitreTechniques.map(tech => (
                  <div key={tech.technique}>
                    <div className="mb-1 flex items-center justify-between text-sm">
                      <span>
                        <span className="mr-2 font-mono text-xs text-brand-cyan">{tech.technique}</span>
                        {tech.name}
                      </span>
                      <span className="font-mono text-brand-cyan">{tech.count}</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-brand-dark">
                      <div
                        className="h-full rounded-full bg-purple-500"
                        style={{ width: `${(tech.count / maxTechniqueCount) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Region Distribution */}
            <div className="card lg:col-span-2">
              <h3 className="mb-4 font-semibold">{t('Regional Distribution', '地區分布')}</h3>
              <div className="flex gap-6">
                {stats.data.regionDistribution.map(r => {
                  const total = stats.data!.totalThreats;
                  const pct = total > 0 ? Math.round((r.count / total) * 100) : 0;
                  return (
                    <div key={r.region} className="flex-1 text-center">
                      <div className="text-2xl font-bold">{pct}%</div>
                      <div className="mt-1 text-sm text-brand-muted">{r.region}</div>
                      <div className="mt-1 font-mono text-xs text-brand-cyan">{r.count.toLocaleString()}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
    </FeatureGate>
  );
}
