import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useLanguage } from '../../context/LanguageContext';
import { useApi } from '../../hooks/useApi';
import { getAllReportAddons } from '@openclaw/panguard-web';

interface Framework {
  id: string;
  name: string;
  nameZh: string;
  description: string;
}

interface ReportResult {
  report: Record<string, unknown>;
  summary: string;
}

interface ReportAccess {
  tier: string;
  hasBusinessAccess: boolean;
  purchasedAddons: string[];
}

export default function DashboardReport() {
  const { language, t } = useLanguage();
  const frameworks = useApi<Framework[]>('/api/report/frameworks');
  const access = useApi<ReportAccess>('/api/report/access');
  const [selectedFramework, setSelectedFramework] = useState('iso27001');
  const [selectedLang, setSelectedLang] = useState(language === 'zh-TW' ? 'zh-TW' : 'en');
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState<ReportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const addons = getAllReportAddons();

  const canGenerateReport = (frameworkId: string): boolean => {
    if (!access.data) return false;
    if (access.data.hasBusinessAccess) return true;
    return access.data.purchasedAddons.includes(frameworkId);
  };

  const generate = useCallback(async () => {
    setGenerating(true);
    setError(null);
    setResult(null);

    try {
      const token = localStorage.getItem('panguard_token');
      const res = await fetch('/api/report/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ framework: selectedFramework, language: selectedLang }),
      });
      const json = await res.json() as { ok: boolean; data?: ReportResult; error?: string };

      if (json.ok && json.data) {
        setResult(json.data);
      } else {
        setError(json.error ?? 'Failed to generate report');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  }, [selectedFramework, selectedLang]);

  const hasAnyAccess = access.data?.hasBusinessAccess || (access.data?.purchasedAddons.length ?? 0) > 0;

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold">{t('Compliance Reports', '合規報告')}</h1>
        <p className="text-sm text-brand-muted">
          {t('Generate compliance reports for various frameworks', '產生各種合規框架的報告')}
        </p>
      </div>

      {/* Loading state */}
      {access.loading && (
        <div className="py-12 text-center text-brand-muted">{t('Loading...', '載入中...')}</div>
      )}

      {/* Report generation controls — show when user has access */}
      {access.data && hasAnyAccess && (
        <div className="mb-8">
          <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
            {/* Framework selector */}
            <div>
              <label className="mb-2 block text-xs font-semibold text-brand-muted">
                {t('Framework', '框架')}
              </label>
              <select
                value={selectedFramework}
                onChange={e => setSelectedFramework(e.target.value)}
                className="w-full rounded-lg border border-brand-border bg-brand-card px-4 py-2.5 text-sm text-brand-text focus:border-brand-cyan focus:outline-none"
              >
                {frameworks.data?.map(f => (
                  <option key={f.id} value={f.id}>
                    {language === 'en' ? f.name : f.nameZh}
                    {!canGenerateReport(f.id) ? ` (${t('not purchased', '未購買')})` : ''}
                  </option>
                )) ?? (
                  <>
                    <option value="iso27001">ISO 27001</option>
                    <option value="soc2">SOC 2</option>
                    <option value="tw_cyber_security_act">
                      {t('Taiwan Cyber Security Act', '資通安全管理法')}
                    </option>
                  </>
                )}
              </select>
            </div>

            {/* Language selector */}
            <div>
              <label className="mb-2 block text-xs font-semibold text-brand-muted">
                {t('Report Language', '報告語言')}
              </label>
              <select
                value={selectedLang}
                onChange={e => setSelectedLang(e.target.value)}
                className="w-full rounded-lg border border-brand-border bg-brand-card px-4 py-2.5 text-sm text-brand-text focus:border-brand-cyan focus:outline-none"
              >
                <option value="en">English</option>
                <option value="zh-TW">繁體中文</option>
              </select>
            </div>

            {/* Generate button */}
            <div className="flex items-end">
              <button
                onClick={generate}
                disabled={generating || !canGenerateReport(selectedFramework)}
                className={`btn-primary w-full justify-center ${
                  generating || !canGenerateReport(selectedFramework) ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                {generating
                  ? t('Generating...', '產生中...')
                  : !canGenerateReport(selectedFramework)
                    ? t('Purchase Required', '需要購買')
                    : t('Generate Report', '產生報告')}
              </button>
            </div>
          </div>

          {access.data.hasBusinessAccess && (
            <p className="text-xs text-green-400">
              {t(
                'Your Business/Enterprise plan includes compliance reports.',
                '你的 Business/Enterprise 方案已包含合規報告。',
              )}
            </p>
          )}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="mb-8 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Report result */}
      {result && (
        <div className="mb-8">
          <h2 className="mb-4 text-lg font-semibold">{t('Report Summary', '報告摘要')}</h2>
          <div className="code-block max-h-[600px] overflow-auto whitespace-pre-wrap text-xs leading-relaxed">
            {result.summary}
          </div>
        </div>
      )}

      {/* Report Add-on Purchase Section */}
      {access.data && !access.data.hasBusinessAccess && (
        <section>
          <h2 className="mb-4 text-lg font-semibold">
            {t('Available Reports — Purchase to Generate', '可用報告 — 購買後產生')}
          </h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {addons.map((addon) => {
              const owned = access.data!.purchasedAddons.includes(addon.id);
              const name = language === 'en' ? addon.nameEn : addon.nameZh;
              const desc = language === 'en' ? addon.descriptionEn : addon.descriptionZh;
              const price = language === 'en' ? addon.priceDisplayEn : addon.priceDisplayZh;

              return (
                <div key={addon.id} className={`card ${owned ? 'border-green-500/30' : ''}`}>
                  <h3 className="mb-1 font-semibold">{name}</h3>
                  <p className="mb-3 text-xs text-brand-muted">{desc}</p>
                  <div className="mb-3 text-lg font-bold">{price}</div>
                  {owned ? (
                    <button
                      onClick={() => setSelectedFramework(addon.framework)}
                      className="btn-primary w-full justify-center text-sm"
                    >
                      {t('Generate', '產生報告')}
                    </button>
                  ) : access.data!.tier === 'free' ? (
                    <Link to="/pricing" className="btn-secondary w-full justify-center text-sm">
                      {t('Upgrade to Purchase', '升級方案以購買')}
                    </Link>
                  ) : (
                    <button
                      className="btn-secondary w-full justify-center text-sm"
                      onClick={() => {
                        // In a real app, this would open Stripe checkout
                        // For now, show a message
                        setError(t(
                          'Payment integration coming soon. Contact sales for early access.',
                          '付款整合即將推出。聯繫業務以提前使用。',
                        ));
                      }}
                    >
                      {t('Purchase', '購買')}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Framework info cards — show when no report generated */}
      {!result && !generating && access.data && hasAnyAccess && (
        <>
          <h2 className="mb-4 text-lg font-semibold">{t('Available Frameworks', '可用框架')}</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {(frameworks.data ?? []).map(f => (
              <div
                key={f.id}
                onClick={() => setSelectedFramework(f.id)}
                className={`card cursor-pointer transition-all ${
                  selectedFramework === f.id ? 'border-brand-cyan/50 shadow-lg shadow-brand-cyan/10' : ''
                }`}
              >
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">{language === 'en' ? f.name : f.nameZh}</h3>
                  {canGenerateReport(f.id) && (
                    <span className="rounded-full bg-green-500/20 px-2 py-0.5 text-xs text-green-400">
                      {t('Available', '可用')}
                    </span>
                  )}
                </div>
                <p className="mt-2 text-xs text-brand-muted">{f.description}</p>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
