import { useState, useCallback } from 'react';
import { useLanguage } from '../../context/LanguageContext';
import { useApi } from '../../hooks/useApi';
import FeatureGate from '../../components/FeatureGate';

interface ChannelInfo {
  type: string;
  label: string;
  configured: boolean;
  envHint: string;
}

interface ChatStatus {
  channels: ChannelInfo[];
  configuredCount: number;
  totalChannels: number;
  preferences: Record<string, boolean>;
  message: string;
}

const CHANNEL_ICONS: Record<string, string> = {
  line: 'LINE', telegram: 'TG', slack: 'SL', email: '@', webhook: '</>',
};

const PREF_LABELS: Record<string, [string, string]> = {
  criticalAlerts: ['Critical Alerts', '即時高危告警'],
  dailySummary: ['Daily Summary', '每日摘要'],
  weeklySummary: ['Weekly Summary', '每週摘要'],
  peacefulReport: ['Peace Report', '平安報告'],
};

export default function DashboardChat() {
  const { t } = useLanguage();
  const chat = useApi<ChatStatus>('/api/chat/status');
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ channel: string; ok: boolean; msg: string } | null>(null);

  const sendTest = useCallback(async (channelType: string) => {
    setTesting(channelType);
    setTestResult(null);
    try {
      const token = localStorage.getItem('panguard_token');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/chat/test', {
        method: 'POST',
        headers,
        body: JSON.stringify({ channel: channelType }),
      });
      const json = await res.json() as { ok: boolean; data?: { message: string }; error?: string };
      setTestResult({
        channel: channelType,
        ok: json.ok,
        msg: json.ok ? (json.data?.message ?? 'Sent') : (json.error ?? 'Failed'),
      });
    } catch (err) {
      setTestResult({
        channel: channelType,
        ok: false,
        msg: err instanceof Error ? err.message : 'Network error',
      });
    } finally {
      setTesting(null);
    }
  }, []);

  return (
    <FeatureGate
      requiredTier="solo"
      featureNameEn="Panguard Chat"
      featureNameZh="Panguard Chat 通知管道"
      descriptionEn="Multi-channel security notifications via LINE, Telegram, Slack, and Email."
      descriptionZh="透過 LINE、Telegram、Slack 和 Email 的多管道資安通知。"
    >
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold">{t('Notifications', '通知管道')}</h1>
        <p className="text-sm text-brand-muted">
          {t('Manage notification channels and preferences', '管理通知管道與偏好設定')}
        </p>
      </div>

      {chat.loading && (
        <div className="py-12 text-center text-brand-muted">{t('Loading...', '載入中...')}</div>
      )}

      {chat.error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
          {chat.error}
        </div>
      )}

      {chat.data && (
        <>
          {/* Summary */}
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="card text-center">
              <div className="text-3xl font-bold text-brand-cyan">
                {chat.data.configuredCount}/{chat.data.totalChannels}
              </div>
              <div className="mt-1 text-xs text-brand-muted">
                {t('Channels Configured', '已配置管道')}
              </div>
            </div>
            <div className="card text-center">
              <div className={`text-3xl font-bold ${chat.data.configuredCount > 0 ? 'text-green-400' : 'text-red-400'}`}>
                {chat.data.configuredCount > 0 ? t('READY', '就緒') : t('NOT SET', '未設定')}
              </div>
              <div className="mt-1 text-xs text-brand-muted">
                {t('Notification Status', '通知狀態')}
              </div>
            </div>
          </div>

          {/* Test result banner */}
          {testResult && (
            <div className={`mb-6 rounded-lg border p-4 text-sm ${
              testResult.ok
                ? 'border-green-500/30 bg-green-500/10 text-green-400'
                : 'border-red-500/30 bg-red-500/10 text-red-400'
            }`}>
              {testResult.msg}
            </div>
          )}

          {/* Channel Grid */}
          <h2 className="mb-4 text-lg font-semibold">{t('Channels', '管道')}</h2>
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {chat.data.channels.map((ch) => (
              <div key={ch.type} className={`card ${ch.configured ? 'border-green-500/30' : ''}`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-dark font-mono text-sm font-bold text-brand-cyan">
                      {CHANNEL_ICONS[ch.type] ?? '?'}
                    </span>
                    <div>
                      <div className="font-semibold">{ch.label}</div>
                      <div className={`text-xs ${ch.configured ? 'text-green-400' : 'text-brand-muted'}`}>
                        {ch.configured ? t('Connected', '已連接') : t('Not configured', '未配置')}
                      </div>
                    </div>
                  </div>
                  <div className={`h-3 w-3 rounded-full ${ch.configured ? 'bg-green-400' : 'bg-brand-muted/30'}`} />
                </div>

                {!ch.configured && (
                  <div className="mt-2 rounded-lg bg-brand-dark p-3">
                    <div className="text-xs text-brand-muted mb-1">
                      {t('Required env vars:', '需要的環境變數:')}
                    </div>
                    <code className="text-xs font-mono text-brand-cyan">{ch.envHint}</code>
                  </div>
                )}

                {ch.configured && (
                  <button
                    onClick={() => void sendTest(ch.type)}
                    disabled={testing === ch.type}
                    className={`mt-3 w-full rounded-lg border border-brand-border px-3 py-2 text-xs font-semibold transition-colors hover:border-brand-cyan hover:text-brand-cyan ${
                      testing === ch.type ? 'opacity-50 cursor-not-allowed' : ''
                    }`}
                  >
                    {testing === ch.type
                      ? t('Sending...', '發送中...')
                      : t('Send Test', '發送測試')}
                  </button>
                )}
              </div>
            ))}
          </div>

          {/* Notification Preferences */}
          <h2 className="mb-4 text-lg font-semibold">{t('Notification Preferences', '通知偏好')}</h2>
          <div className="mb-8 card">
            <div className="space-y-3">
              {Object.entries(chat.data.preferences).map(([key, enabled]) => {
                const pair = PREF_LABELS[key];
                const label = pair ? t(pair[0], pair[1]) : key;
                return (
                  <div key={key} className="flex items-center justify-between">
                    <span className="text-sm">{label}</span>
                    <span className={`rounded-full px-3 py-0.5 text-xs font-semibold ${
                      enabled
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-brand-dark text-brand-muted'
                    }`}>
                      {enabled ? t('ON', '開') : t('OFF', '關')}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Message */}
          <div className="rounded-xl border border-brand-border bg-brand-card/50 p-4">
            <div className="text-sm font-mono text-brand-muted">{chat.data.message}</div>
          </div>
        </>
      )}
    </div>
    </FeatureGate>
  );
}
