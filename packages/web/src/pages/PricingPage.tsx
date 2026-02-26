import { getAllPricingPlans, getAllReportAddons } from '@openclaw/panguard-web';
import { useLanguage } from '../context/LanguageContext';
import PricingCard from '../components/PricingCard';
import ReportAddonCard from '../components/ReportAddonCard';

export default function PricingPage() {
  const { language, t } = useLanguage();
  const plans = getAllPricingPlans();
  const addons = getAllReportAddons();

  const faqs = [
    {
      qEn: 'Can I switch plans later?',
      qZh: '之後可以切換方案嗎？',
      aEn: 'Yes, you can upgrade or downgrade at any time. Your data and configurations are preserved across plan changes.',
      aZh: '可以，你可以隨時升級或降級。你的資料和設定在方案變更時都會保留。',
    },
    {
      qEn: 'Is there a free trial for paid plans?',
      qZh: '付費方案有免費試用嗎？',
      aEn: 'All paid plans include a 14-day free trial with full feature access. No credit card required.',
      aZh: '所有付費方案都包含 14 天免費試用，可使用全部功能。不需要信用卡。',
    },
    {
      qEn: 'What compliance frameworks are supported?',
      qZh: '支援哪些合規框架？',
      aEn: 'We support Taiwan Cyber Security Management Act, ISO 27001, and SOC 2. Enterprise plans include custom framework mapping.',
      aZh: '我們支援台灣資通安全管理法、ISO 27001 和 SOC 2。企業方案包含自訂框架對應。',
    },
    {
      qEn: 'How do compliance report add-ons work?',
      qZh: '合規報告加購如何運作？',
      aEn: 'Report add-ons are purchased separately from your subscription. Any paid plan can buy reports. Business plan includes basic compliance reports.',
      aZh: '合規報告獨立於訂閱方案購買。任何付費方案都可以購買報告。企業版已包含基礎合規報告。',
    },
    {
      qEn: 'How does per-endpoint pricing work?',
      qZh: '按端點計費如何運作？',
      aEn: 'Team ($14/endpoint/mo) and Business ($10/endpoint/mo) plans charge per monitored endpoint. Volume discounts apply automatically.',
      aZh: 'Team（$14/端點/月）和 Business（$10/端點/月）方案按受監控的端點數計費。量大自動折扣。',
    },
    {
      qEn: 'How does the AI learning period work?',
      qZh: 'AI 學習期如何運作？',
      aEn: 'Panguard AI takes 7 days to learn your environment baseline. During this period, you receive regular progress updates and the system operates in observation mode.',
      aZh: 'Panguard AI 需要 7 天來學習你的環境基準線。在此期間，你會收到定期進度更新，系統以觀察模式運作。',
    },
  ];

  return (
    <div className="mx-auto max-w-7xl px-4 py-12">
      {/* Header */}
      <div className="mb-16 text-center">
        <h1 className="mb-4 text-4xl font-bold">
          {t('Pricing Plans', '方案價格')}
        </h1>
        <p className="mx-auto max-w-2xl text-brand-muted">
          {t(
            'AI watches for you, at self-serve prices. Start free and scale as you grow.',
            'AI 幫你看，價格接近自己看。免費開始，隨著成長擴展。',
          )}
        </p>
        <p className="mt-2 text-sm text-brand-muted/70">
          {t(
            'All paid plans include a 14-day free trial | Annual billing saves 20%',
            '所有付費方案 14 天免費試用 | 年繳享 20% 折扣',
          )}
        </p>
      </div>

      {/* Pricing Cards — 5 plans */}
      <div className="mb-8 grid gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        {plans.map((plan) => (
          <PricingCard key={plan.plan} plan={plan} />
        ))}
      </div>

      {/* Enterprise Banner */}
      <div className="mb-20 rounded-xl border border-brand-border bg-brand-card p-8 text-center">
        <h3 className="mb-2 text-xl font-bold">
          {t('Enterprise', '企業客製')}
        </h3>
        <p className="mb-4 text-brand-muted">
          {t(
            '500+ endpoints? Contact us for a custom quote with dedicated support, SLA, and custom compliance frameworks.',
            '500+ 端點？聯繫我們取得專屬報價，含專屬支援、SLA 及客製合規框架。',
          )}
        </p>
        <a
          href="mailto:enterprise@panguard.ai"
          className="btn-primary"
        >
          {t('Contact Sales', '聯繫業務')}
        </a>
      </div>

      {/* Report Add-ons Section */}
      <section className="mb-20">
        <div className="mb-8 text-center">
          <h2 className="section-title">
            {t('Compliance Reports — On-Demand Add-ons', '合規報告 — 按需加購')}
          </h2>
          <p className="mx-auto max-w-2xl text-brand-muted">
            {t(
              'Purchase compliance reports independently from your subscription. Any paid plan can buy reports. Business plan includes basic compliance.',
              '合規報告獨立於訂閱方案購買。任何付費方案都可購買。企業版已含基礎合規報告。',
            )}
          </p>
        </div>
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {addons.map((addon) => (
            <ReportAddonCard key={addon.id} addon={addon} />
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section>
        <h2 className="section-title text-center">
          {t('Frequently Asked Questions', '常見問題')}
        </h2>
        <div className="mx-auto max-w-3xl space-y-6">
          {faqs.map((faq, i) => (
            <div key={i} className="card">
              <h3 className="mb-2 font-semibold">
                {language === 'en' ? faq.qEn : faq.qZh}
              </h3>
              <p className="text-sm text-brand-muted">
                {language === 'en' ? faq.aEn : faq.aZh}
              </p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
