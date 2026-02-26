import { useLanguage } from '../../context/LanguageContext';
import { useApi } from '../../hooks/useApi';
import FeatureGate from '../../components/FeatureGate';

interface AgentInfo {
  name: string;
  status: string;
  description: string;
}

interface GuardStatus {
  running: boolean;
  pid: number | null;
  mode: string;
  agents: AgentInfo[];
  license: { tier: string; features: string[] };
  dashboard: { enabled: boolean };
  message: string;
}

export default function DashboardGuard() {
  const { t } = useLanguage();
  const guard = useApi<GuardStatus>('/api/guard/status');

  const modeColor = (mode: string) => {
    if (mode === 'protection') return 'text-green-400';
    if (mode === 'learning') return 'text-yellow-400';
    return 'text-red-400';
  };

  return (
    <FeatureGate
      requiredTier="solo"
      featureNameEn="Panguard Guard"
      featureNameZh="Panguard Guard 守護引擎"
      descriptionEn="Real-time endpoint monitoring with AI-powered threat detection and auto-response."
      descriptionZh="即時端點監控，搭配 AI 驅動的威脅偵測與自動回應。"
    >
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold">{t('Guard Engine', '守護引擎')}</h1>
        <p className="text-sm text-brand-muted">
          {t('Real-time endpoint protection status', '即時端點防護狀態')}
        </p>
      </div>

      {guard.loading && (
        <div className="py-12 text-center text-brand-muted">{t('Loading...', '載入中...')}</div>
      )}

      {guard.error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
          {guard.error}
        </div>
      )}

      {guard.data && (
        <>
          {/* Status Cards */}
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="card text-center">
              <div className={`text-3xl font-bold ${guard.data.running ? 'text-green-400' : 'text-red-400'}`}>
                {guard.data.running ? t('RUNNING', '運行中') : t('STOPPED', '已停止')}
              </div>
              <div className="mt-1 text-xs text-brand-muted">{t('Engine Status', '引擎狀態')}</div>
            </div>
            <div className="card text-center">
              <div className={`text-3xl font-bold ${modeColor(guard.data.mode)}`}>
                {guard.data.mode.toUpperCase()}
              </div>
              <div className="mt-1 text-xs text-brand-muted">{t('Current Mode', '目前模式')}</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold font-mono text-brand-cyan">
                {guard.data.pid ?? '--'}
              </div>
              <div className="mt-1 text-xs text-brand-muted">{t('Process ID', '程序 ID')}</div>
            </div>
          </div>

          {/* Agent Pipeline */}
          <h2 className="mb-4 text-lg font-semibold">{t('Agent Pipeline', 'Agent 管線')}</h2>
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {guard.data.agents.map((agent) => (
              <div key={agent.name} className="card flex items-center gap-4">
                <div className={`h-3 w-3 rounded-full ${agent.status === 'active' ? 'bg-green-400' : 'bg-red-400'}`} />
                <div>
                  <div className="font-semibold font-mono text-sm">{agent.name}</div>
                  <div className="text-xs text-brand-muted">{agent.description}</div>
                  <div className={`mt-1 text-xs ${agent.status === 'active' ? 'text-green-400' : 'text-red-400'}`}>
                    {agent.status}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* License */}
          <h2 className="mb-4 text-lg font-semibold">{t('License', '授權')}</h2>
          <div className="mb-8 card">
            <div className="flex items-center justify-between mb-4">
              <span className="text-brand-muted">{t('Tier', '等級')}</span>
              <span className="font-mono font-bold text-brand-cyan uppercase">{guard.data.license.tier}</span>
            </div>
            <div>
              <span className="text-brand-muted text-sm">{t('Features', '功能')}</span>
              <div className="mt-2 flex flex-wrap gap-2">
                {guard.data.license.features.map((feat) => (
                  <span key={feat} className="rounded-full bg-brand-cyan/10 px-3 py-1 text-xs text-brand-cyan">
                    {feat.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Message */}
          <div className="rounded-xl border border-brand-border bg-brand-card/50 p-4">
            <div className="text-sm font-mono text-brand-muted">{guard.data.message}</div>
          </div>
        </>
      )}
    </div>
    </FeatureGate>
  );
}
