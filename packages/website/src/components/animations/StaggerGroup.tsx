'use client';
import { ReactNode } from 'react';
import { useScrollReveal } from '@/hooks/useScrollReveal';

export function StaggerGroup({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
  stagger?: number;
}) {
  const ref = useScrollReveal({ margin: '-60px' });

  return (
    <div ref={ref} className={`stagger-group ${className}`}>
      {children}
    </div>
  );
}

export function StaggerItem({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`animate-on-scroll ${className}`}>{children}</div>;
}
