import type { ReportAddon } from '@openclaw/panguard-web';
import { useLanguage } from '../context/LanguageContext';

interface ReportAddonCardProps {
  addon: ReportAddon;
}

export default function ReportAddonCard({ addon }: ReportAddonCardProps) {
  const { language, t } = useLanguage();
  const name = language === 'en' ? addon.nameEn : addon.nameZh;
  const description = language === 'en' ? addon.descriptionEn : addon.descriptionZh;
  const price = language === 'en' ? addon.priceDisplayEn : addon.priceDisplayZh;

  return (
    <div className="card flex flex-col">
      <div className="mb-4">
        <h3 className="text-lg font-bold">{name}</h3>
        <p className="mt-1 text-sm text-brand-muted">{description}</p>
      </div>

      <div className="mb-4 mt-auto">
        <span className="text-2xl font-extrabold">{price}</span>
        {addon.pricingModel === 'subscription' && addon.annualPriceDisplayEn && (
          <p className="mt-1 text-xs text-brand-muted">
            {t(
              `or ${addon.annualPriceDisplayEn} annually (save 17%)`,
              `或 ${addon.annualPriceDisplayZh} 年繳（省 17%）`,
            )}
          </p>
        )}
      </div>

      <span className="inline-block rounded-full bg-brand-border/50 px-3 py-1 text-center text-xs text-brand-muted">
        {addon.pricingModel === 'subscription'
          ? t('Monthly subscription', '月訂閱')
          : t('Per report', '按份計費')}
      </span>
    </div>
  );
}
