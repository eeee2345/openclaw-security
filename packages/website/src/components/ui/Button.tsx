import { Link } from '@/navigation';
import { ReactNode } from 'react';

type ButtonVariant = 'primary' | 'secondary' | 'ghost';
type ButtonSize = 'sm' | 'md' | 'lg';

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    'bg-brand-sage text-surface-0 font-semibold hover:bg-brand-sage-light active:scale-[0.98]',
  secondary:
    'border border-border text-text-secondary font-semibold hover:border-brand-sage hover:text-text-primary',
  ghost: 'text-brand-sage hover:text-brand-sage-light font-medium',
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'px-5 py-2.5 text-sm',
  md: 'px-8 py-3.5 text-sm',
  lg: 'px-10 py-4 text-base',
};

const baseClasses =
  'inline-flex items-center justify-center gap-2 rounded-full transition-all duration-200 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-sage focus-visible:ring-offset-2 focus-visible:ring-offset-surface-0';

interface ButtonProps {
  variant?: ButtonVariant;
  size?: ButtonSize;
  href?: string;
  children: ReactNode;
  className?: string;
  disabled?: boolean;
  onClick?: () => void;
  type?: 'button' | 'submit';
}

export default function Button({
  variant = 'primary',
  size = 'md',
  href,
  children,
  className = '',
  disabled = false,
  onClick,
  type = 'button',
}: ButtonProps) {
  const classes = `${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${
    disabled ? 'opacity-40 cursor-not-allowed pointer-events-none' : ''
  } ${className}`;

  if (href) {
    return (
      <Link href={href} className={classes}>
        {children}
      </Link>
    );
  }

  return (
    <button type={type} className={classes} disabled={disabled} onClick={onClick}>
      {children}
    </button>
  );
}
