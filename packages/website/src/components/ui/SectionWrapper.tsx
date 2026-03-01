import { ReactNode } from 'react';

type Spacing = 'tight' | 'default' | 'spacious';

const spacingClasses: Record<Spacing, string> = {
  tight: 'py-8 sm:py-12',
  default: 'py-12 sm:py-16',
  spacious: 'py-16 sm:py-20',
};

export default function SectionWrapper({
  children,
  className = '',
  id,
  dark = false,
  bg,
  spacing = 'default',
  fadeBorder = true,
}: {
  children: ReactNode;
  className?: string;
  id?: string;
  dark?: boolean;
  bg?: string;
  spacing?: Spacing;
  fadeBorder?: boolean;
}) {
  const bgClass = bg ?? (dark ? 'bg-surface-1' : 'bg-surface-0');

  return (
    <section
      id={id}
      className={`${spacingClasses[spacing]} px-4 sm:px-6 ${
        fadeBorder ? 'section-fade' : ''
      } ${bgClass} ${className}`}
    >
      <div className="max-w-[1200px] mx-auto">{children}</div>
    </section>
  );
}
