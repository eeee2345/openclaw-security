'use client';

import { BRAND_LOGO_PATHS, BRAND_LOGO_VIEWBOX } from './BrandLogo';

function BrandShieldSVG({ width, height }: { width: number; height: number }) {
  return (
    <svg width={width} height={height} viewBox={BRAND_LOGO_VIEWBOX} fill="none">
      {BRAND_LOGO_PATHS.filter((p) => p.role === 'fg').map((p, i) => (
        <path key={i} fill="#8B9A8E" d={p.d} />
      ))}
    </svg>
  );
}

export function ShieldSpinner({
  size = 48,
  className = '',
}: {
  size?: number;
  className?: string;
}) {
  return (
    <div className={`relative inline-flex items-center justify-center ${className}`}>
      {/* Rotating ring */}
      <svg
        width={size}
        height={size}
        viewBox="0 0 48 48"
        className="animate-[shield-spin_3s_linear_infinite] absolute"
      >
        <circle
          cx="24"
          cy="24"
          r="22"
          fill="none"
          stroke="#8B9A8E"
          strokeWidth="1.5"
          strokeDasharray="20 80"
          strokeLinecap="round"
          opacity="0.4"
        />
      </svg>
      {/* Brand shield mark */}
      <div className="animate-[breathe_3s_ease-in-out_infinite]">
        <BrandShieldSVG width={size * 0.6} height={size * 0.65} />
      </div>
    </div>
  );
}

export function PulseLoader({ size = 48, className = '' }: { size?: number; className?: string }) {
  return (
    <div
      className={`relative inline-flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
    >
      {/* Pulse rings */}
      <div
        className="absolute rounded-full bg-brand-sage/10 animate-[pulse-ring_2s_ease-out_infinite]"
        style={{ width: size, height: size }}
      />
      <div
        className="absolute rounded-full bg-brand-sage/10 animate-[pulse-ring_2s_ease-out_infinite_0.5s]"
        style={{ width: size * 0.7, height: size * 0.7 }}
      />
      {/* Center shield */}
      <BrandShieldSVG width={size * 0.4} height={size * 0.43} />
    </div>
  );
}

export function ScanLoader({ size = 48, className = '' }: { size?: number; className?: string }) {
  return (
    <div
      className={`relative inline-flex items-center justify-center overflow-hidden ${className}`}
      style={{ width: size, height: size }}
    >
      {/* Shield */}
      <BrandShieldSVG width={size * 0.6} height={size * 0.65} />
      {/* Scan line overlay */}
      <div
        className="absolute left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-brand-sage to-transparent animate-[scan-line_2s_ease-in-out_infinite]"
        style={{ top: 0 }}
      />
    </div>
  );
}
