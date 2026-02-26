import { useLanguage } from '../../context/LanguageContext';
import { useApi } from '../../hooks/useApi';
import FeatureGate from '../../components/FeatureGate';

interface TrapService {
  type: string;
  port: number;
  enabled: boolean;
  listening: boolean;
}

interface TrapStatus {
  running: boolean;
  services: TrapService[];
  activeServices: number;
  message: string;
}

const SERVICE_LABELS: Record<string, string> = {
  ssh: 'SSH', http: 'HTTP', ftp: 'FTP', telnet: 'Telnet',
  mysql: 'MySQL', redis: 'Redis', smb: 'SMB', rdp: 'RDP',
};

export default function DashboardTrap() {
  const { t } = useLanguage();
  const trap = useApi<TrapStatus>('/api/trap/status');

  return (
    <FeatureGate
      requiredTier="team"
      featureNameEn="Panguard Trap"
      featureNameZh="Panguard Trap 蜜罐系統"
      descriptionEn="Deploy 8 honeypot services (SSH, HTTP, FTP, etc.) to detect and profile attackers."
      descriptionZh="部署 8 種蜜罐服務（SSH、HTTP、FTP 等），偵測並分析攻擊者行為。"
    >
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold">{t('Honeypot System', '蜜罐系統')}</h1>
        <p className="text-sm text-brand-muted">
          {t('Decoy services to detect and track attackers', '偽裝服務，偵測並追蹤攻擊者')}
        </p>
      </div>

      {trap.loading && (
        <div className="py-12 text-center text-brand-muted">{t('Loading...', '載入中...')}</div>
      )}

      {trap.error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
          {trap.error}
        </div>
      )}

      {trap.data && (
        <>
          {/* Summary Cards */}
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="card text-center">
              <div className={`text-3xl font-bold ${trap.data.running ? 'text-green-400' : 'text-red-400'}`}>
                {trap.data.running ? t('ACTIVE', '啟用') : t('INACTIVE', '未啟用')}
              </div>
              <div className="mt-1 text-xs text-brand-muted">{t('System Status', '系統狀態')}</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold text-brand-cyan">{trap.data.activeServices}</div>
              <div className="mt-1 text-xs text-brand-muted">{t('Active Services', '活躍服務')}</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold text-brand-muted">{trap.data.services.length}</div>
              <div className="mt-1 text-xs text-brand-muted">{t('Total Services', '總服務數')}</div>
            </div>
          </div>

          {/* Service Grid */}
          <h2 className="mb-4 text-lg font-semibold">{t('Honeypot Services', '蜜罐服務')}</h2>
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {trap.data.services.map((svc) => (
              <div
                key={svc.type}
                className={`card ${svc.listening ? 'border-green-500/30' : ''}`}
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="text-lg font-semibold">{SERVICE_LABELS[svc.type] ?? svc.type.toUpperCase()}</span>
                  <div className={`h-3 w-3 rounded-full ${
                    svc.listening ? 'bg-green-400' : svc.enabled ? 'bg-yellow-400' : 'bg-brand-muted/30'
                  }`} />
                </div>
                <div className="space-y-1 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-brand-muted">{t('Port', '端口')}</span>
                    <span className="font-mono text-brand-cyan">{svc.port}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-brand-muted">{t('Enabled', '啟用')}</span>
                    <span className={svc.enabled ? 'text-green-400' : 'text-brand-muted'}>
                      {svc.enabled ? t('Yes', '是') : t('No', '否')}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-brand-muted">{t('Listening', '監聽中')}</span>
                    <span className={svc.listening ? 'text-green-400' : 'text-red-400'}>
                      {svc.listening ? t('Yes', '是') : t('No', '否')}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Message */}
          <div className="rounded-xl border border-brand-border bg-brand-card/50 p-4">
            <div className="text-sm font-mono text-brand-muted">{trap.data.message}</div>
          </div>
        </>
      )}
    </div>
    </FeatureGate>
  );
}
