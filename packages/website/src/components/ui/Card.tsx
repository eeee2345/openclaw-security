import { ReactNode } from 'react';

type CardVariant = 'default' | 'elevated' | 'featured' | 'glass';

const variantClasses: Record<CardVariant, string> = {
  default: 'bg-surface-1 border border-border card-glow',
  elevated:
    'bg-surface-1 border border-border shadow-[0_8px_32px_rgba(0,0,0,0.3)] hover:shadow-[0_16px_48px_rgba(0,0,0,0.4)] hover:-translate-y-1',
  featured: 'bg-surface-1 border border-brand-sage card-glow',
  glass: 'bg-surface-1/40 backdrop-blur-xl border border-white/5',
};

interface CardProps {
  variant?: CardVariant;
  children: ReactNode;
  className?: string;
  padding?: 'sm' | 'md' | 'lg';
}

const paddingClasses = {
  sm: 'p-4',
  md: 'p-6',
  lg: 'p-8',
};

export default function Card({
  variant = 'default',
  children,
  className = '',
  padding = 'md',
}: CardProps) {
  return (
    <div
      className={`rounded-2xl transition-all duration-500 ${variantClasses[variant]} ${paddingClasses[padding]} ${className}`}
    >
      {children}
    </div>
  );
}
