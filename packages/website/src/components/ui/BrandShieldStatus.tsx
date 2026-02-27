/**
 * Panguard AI Shield with Status Overlay
 *
 * Real brand shield mark with status indicators:
 * Safe (green check), Warning (yellow !), Alert (orange triangle),
 * Critical (red X), Loading (spinner), Disabled (dimmed)
 *
 * Ref: brand-assets/02-logo-icons/PANGUARD_AI_Icon_Variations.png
 */
import { BRAND_LOGO_PATHS, BRAND_LOGO_VIEWBOX } from './BrandLogo';

type Status = 'safe' | 'warning' | 'alert' | 'critical' | 'loading' | 'disabled';

const statusColors: Record<Status, string> = {
  safe: '#2ED573',
  warning: '#FBBF24',
  alert: '#FF6B35',
  critical: '#EF4444',
  loading: '#8B9A8E',
  disabled: '#4A4540',
};

export default function BrandShieldStatus({
  status,
  size = 48,
  className = '',
}: {
  status: Status;
  size?: number;
  className?: string;
}) {
  const color = statusColors[status];
  const shieldColor = status === 'disabled' ? '#4A4540' : '#8B9A8E';

  return (
    <svg width={size} height={size} viewBox="0 0 48 52" fill="none" className={className}>
      {/* Real brand shield logo */}
      <svg x="2" y="2" width="44" height="44" viewBox={BRAND_LOGO_VIEWBOX} fill="none">
        {BRAND_LOGO_PATHS.filter((p) => p.role === 'fg').map((p, i) => (
          <path key={i} fill={shieldColor} d={p.d} />
        ))}
      </svg>

      {/* Status overlay */}
      {status === 'safe' && (
        <path
          d="M17 33L22 38L31 28"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
      {status === 'warning' && (
        <>
          <path d="M24 28v5" stroke={color} strokeWidth="3" strokeLinecap="round" />
          <circle cx="24" cy="38" r="1.5" fill={color} />
        </>
      )}
      {status === 'alert' && (
        <>
          <path d="M24 26l-7 12h14l-7-12z" stroke={color} strokeWidth="2" strokeLinejoin="round" />
          <path d="M24 31v3" stroke={color} strokeWidth="2" strokeLinecap="round" />
          <circle cx="24" cy="36" r="0.8" fill={color} />
        </>
      )}
      {status === 'critical' && (
        <>
          <path d="M19 28L29 38" stroke={color} strokeWidth="3" strokeLinecap="round" />
          <path d="M29 28L19 38" stroke={color} strokeWidth="3" strokeLinecap="round" />
        </>
      )}
      {status === 'loading' && (
        <circle
          cx="24"
          cy="33"
          r="6"
          stroke={color}
          strokeWidth="2"
          strokeDasharray="20 12"
          fill="none"
        >
          <animateTransform
            attributeName="transform"
            type="rotate"
            values="0 24 33;360 24 33"
            dur="1s"
            repeatCount="indefinite"
          />
        </circle>
      )}
    </svg>
  );
}
