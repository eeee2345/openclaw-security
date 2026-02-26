import { Link } from 'react-router-dom';
import { useLanguage } from '../context/LanguageContext';
import CopyCommand from './CopyCommand';
import WaitlistForm from './WaitlistForm';

export default function Hero() {
  const { t } = useLanguage();

  return (
    <section className="grid-bg relative overflow-hidden py-24 md:py-32">
      <div className="mx-auto max-w-4xl px-4 text-center sm:px-6">
        <h1 className="mb-6 text-4xl font-extrabold tracking-tight md:text-6xl">
          {t('One Command.', '一行指令。')}
          <br />
          <span className="gradient-text">
            {t('AI Protects Everything.', 'AI 全自動保護。')}
          </span>
        </h1>

        <p className="mx-auto mb-10 max-w-2xl text-lg text-brand-muted md:text-xl">
          {t(
            'Install in 60 seconds. AI auto-configures, learns your environment in 7 days, and protects you 24/7. When threats happen, we tell you in plain language.',
            '60 秒安裝。AI 自動設定，7 天學習你的環境，全天候保護。有事用人話告訴你，沒事什麼都不用做。',
          )}
        </p>

        <CopyCommand
          command="curl -fsSL https://get.panguard.ai | sh"
          className="mx-auto mb-10 max-w-xl"
        />

        <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
          <Link to="/guide" className="btn-primary text-base">
            {t('Find Your Plan', '\u627E\u5230\u4F60\u7684\u65B9\u6848')}
          </Link>
          <Link to="/features" className="btn-secondary text-base">
            {t('See How It Works', '\u4E86\u89E3\u904B\u4F5C\u65B9\u5F0F')}
          </Link>
        </div>

        <div className="mx-auto mt-12 max-w-md">
          <p className="mb-4 text-sm text-brand-muted">
            {t('Get early access - join the waitlist:', '\u6436\u5148\u9AD4\u9A57 - \u52A0\u5165\u767D\u540D\u55AE\uFF1A')}
          </p>
          <WaitlistForm />
        </div>
      </div>
    </section>
  );
}
