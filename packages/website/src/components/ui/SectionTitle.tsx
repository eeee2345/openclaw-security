import FadeInUp from '../FadeInUp';

export default function SectionTitle({
  overline,
  title,
  subtitle,
  center = true,
  serif = false,
}: {
  overline?: string;
  title: string;
  subtitle?: string;
  center?: boolean;
  serif?: boolean;
}) {
  const align = center ? 'text-center mx-auto' : '';
  return (
    <FadeInUp className={`max-w-2xl ${align}`}>
      {overline && (
        <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
          {overline}
        </p>
      )}
      <h2
        className={`text-[clamp(36px,4vw,48px)] text-text-primary leading-[1.1] ${
          serif ? 'font-display italic' : 'font-bold'
        }`}
      >
        {title}
      </h2>
      {subtitle && <p className="text-text-secondary mt-4 leading-relaxed">{subtitle}</p>}
    </FadeInUp>
  );
}
