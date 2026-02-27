/**
 * Panguard AI Product Badges
 *
 * 6 branded trust/certification badges recreated from:
 * brand-assets/01-brand-identity/PANGUARD_AI_Product_Badges.png
 *
 * All SVG + CSS, sage green on dark. Uses real brand logo paths.
 */
import { BRAND_LOGO_PATHS, BRAND_LOGO_VIEWBOX } from './BrandLogo';

type BadgeProps = { size?: number; className?: string };

const sage = '#8B9A8E';

/* Shared: mini brand shield rendered inside badges */
function BadgeShield({ x, y, w, h }: { x: number; y: number; w: number; h: number }) {
  return (
    <svg x={x} y={y} width={w} height={h} viewBox={BRAND_LOGO_VIEWBOX} fill="none">
      {BRAND_LOGO_PATHS.filter((p) => p.role === 'fg').map((p, i) => (
        <path key={i} fill={sage} d={p.d} />
      ))}
    </svg>
  );
}

/* ── Protected By Panguard AI -- circular badge ──────────────────── */
export function ProtectedByBadge({ size = 80, className = '' }: BadgeProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none" className={className}>
      <circle cx="40" cy="40" r="38" stroke={sage} strokeWidth="1.5" />
      <circle cx="40" cy="40" r="34" stroke={sage} strokeWidth="0.5" strokeOpacity="0.3" />
      <BadgeShield x={28} y={22} w={24} h={26} />
      <text
        fill={sage}
        fontSize="5"
        fontFamily="system-ui"
        fontWeight="600"
        letterSpacing="0.8"
        textAnchor="middle"
      >
        <textPath href="#protArc">PROTECTED BY PANGUARD AI</textPath>
      </text>
      <defs>
        <path id="protArc" d="M12,52 A30,30 0 0,1 68,52" />
      </defs>
    </svg>
  );
}

/* ── Certified Secure -- hexagonal badge ─────────────────────────── */
export function CertifiedSecureBadge({ size = 80, className = '' }: BadgeProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none" className={className}>
      <polygon points="40,4 72,22 72,58 40,76 8,58 8,22" stroke={sage} strokeWidth="1.5" />
      <BadgeShield x={28} y={18} w={24} h={26} />
      <path
        d="M34 39L38 43L46 35"
        stroke="#2ED573"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <text
        x="40"
        y="62"
        fill={sage}
        fontSize="5.5"
        fontFamily="system-ui"
        fontWeight="700"
        textAnchor="middle"
        letterSpacing="1"
      >
        CERTIFIED SECURE
      </text>
      <text
        x="40"
        y="69"
        fill={sage}
        fontSize="4.5"
        fontFamily="system-ui"
        fontWeight="400"
        textAnchor="middle"
      >
        2026
      </text>
    </svg>
  );
}

/* ── AI Powered Security -- rectangular badge ────────────────────── */
export function AIPoweredBadge({ size = 80, className = '' }: BadgeProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none" className={className}>
      <rect x="4" y="10" width="72" height="60" rx="4" stroke={sage} strokeWidth="1.5" />
      <BadgeShield x={28} y={14} w={24} h={26} />
      {/* Circuit nodes */}
      <circle cx="22" cy="30" r="1.5" fill={sage} />
      <circle cx="58" cy="30" r="1.5" fill={sage} />
      <circle cx="22" cy="45" r="1.5" fill={sage} />
      <circle cx="58" cy="45" r="1.5" fill={sage} />
      <path d="M23.5 30H28" stroke={sage} strokeWidth="0.8" />
      <path d="M52 30H56.5" stroke={sage} strokeWidth="0.8" />
      <path d="M23.5 45H28" stroke={sage} strokeWidth="0.8" />
      <path d="M52 45H56.5" stroke={sage} strokeWidth="0.8" />
      <text
        x="40"
        y="60"
        fill={sage}
        fontSize="5"
        fontFamily="system-ui"
        fontWeight="700"
        textAnchor="middle"
        letterSpacing="0.8"
      >
        AI POWERED
      </text>
      <text
        x="40"
        y="66"
        fill={sage}
        fontSize="4"
        fontFamily="system-ui"
        fontWeight="500"
        textAnchor="middle"
        letterSpacing="0.5"
      >
        SECURITY
      </text>
    </svg>
  );
}

/* ── Enterprise Grade -- shield-shaped badge ─────────────────────── */
export function EnterpriseGradeBadge({ size = 80, className = '' }: BadgeProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none" className={className}>
      <path
        d="M40 4L8 18V48L40 76L72 48V18L40 4z"
        stroke={sage}
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <BadgeShield x={28} y={16} w={24} h={26} />
      <text
        x="40"
        y="56"
        fill={sage}
        fontSize="5"
        fontFamily="system-ui"
        fontWeight="700"
        textAnchor="middle"
        letterSpacing="0.8"
      >
        ENTERPRISE
      </text>
      <text
        x="40"
        y="63"
        fill={sage}
        fontSize="4.5"
        fontFamily="system-ui"
        fontWeight="500"
        textAnchor="middle"
        letterSpacing="0.5"
      >
        GRADE
      </text>
    </svg>
  );
}

/* ── 24/7 Monitoring -- circular with arrows ─────────────────────── */
export function MonitoringBadge({ size = 80, className = '' }: BadgeProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none" className={className}>
      <circle cx="40" cy="40" r="38" stroke={sage} strokeWidth="1.5" />
      {/* Rotating arrows */}
      <path d="M40 14a26 26 0 0118 8" stroke={sage} strokeWidth="1.5" strokeLinecap="round" />
      <path
        d="M58 22l2-6-6 1"
        stroke={sage}
        strokeWidth="1"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M40 66a26 26 0 01-18-8" stroke={sage} strokeWidth="1.5" strokeLinecap="round" />
      <path
        d="M22 58l-2 6 6-1"
        stroke={sage}
        strokeWidth="1"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <BadgeShield x={30} y={24} w={20} h={22} />
      <text
        x="40"
        y="58"
        fill={sage}
        fontSize="6"
        fontFamily="system-ui"
        fontWeight="700"
        textAnchor="middle"
        letterSpacing="1"
      >
        24/7
      </text>
      <text
        x="40"
        y="65"
        fill={sage}
        fontSize="4"
        fontFamily="system-ui"
        fontWeight="500"
        textAnchor="middle"
        letterSpacing="0.5"
      >
        MONITORING
      </text>
    </svg>
  );
}

/* ── Zero Trust -- rectangular with lock ─────────────────────────── */
export function ZeroTrustBadge({ size = 80, className = '' }: BadgeProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none" className={className}>
      <rect x="4" y="10" width="72" height="60" rx="4" stroke={sage} strokeWidth="1.5" />
      {/* Lock icon */}
      <rect x="32" y="30" width="16" height="12" rx="2" stroke={sage} strokeWidth="1.5" />
      <path d="M35 30v-4a5 5 0 0110 0v4" stroke={sage} strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="40" cy="36" r="1.5" fill={sage} />
      <text
        x="40"
        y="56"
        fill={sage}
        fontSize="5"
        fontFamily="system-ui"
        fontWeight="700"
        textAnchor="middle"
        letterSpacing="0.8"
      >
        ZERO TRUST
      </text>
      <text
        x="40"
        y="63"
        fill={sage}
        fontSize="4"
        fontFamily="system-ui"
        fontWeight="500"
        textAnchor="middle"
        letterSpacing="0.5"
      >
        ARCHITECTURE
      </text>
    </svg>
  );
}
