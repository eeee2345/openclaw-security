import { ReactNode } from 'react';

type Spacing = 'tight' | 'default' | 'spacious';

const spacingClasses: Record<Spacing, string> = {
  tight: 'py-12 sm:py-16',
  default: 'py-16 sm:py-24',
  spacious: 'py-20 sm:py-32',
};

export default function SectionWrapper({
  children,
  className = '',
  id,
  dark = false,
  spacing = 'default',
  fadeBorder = false,
}: {
  children: ReactNode;
  className?: string;
  id?: string;
  dark?: boolean;
  spacing?: Spacing;
  fadeBorder?: boolean;
}) {
  return (
    <section
      id={id}
      className={`${spacingClasses[spacing]} px-6 ${
        fadeBorder ? 'section-fade' : 'border-b border-border'
      } ${dark ? 'bg-surface-1' : 'bg-surface-0'} ${className}`}
    >
      <div className="max-w-[1200px] mx-auto">{children}</div>
    </section>
  );
}
