/**
 * Panguard AI Brand Icon System
 *
 * 18 custom icons matching the brand design reference:
 * /brand-assets/02-logo-icons/PANGUARD_AI_Complete_Icon_System.png
 *
 * Style: rounded stroke, sage green on dark, consistent 1.5 strokeWidth
 * NOT Lucide — these are brand-specific designs.
 */

type IconProps = { size?: number; className?: string };

const defaults = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.5,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
};

/* ── Shield (protection) — brand 3D shield mark ────────────────── */
export function ShieldIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="385 323 1278 1403" className={className} fill="none">
      <path
        fill="currentColor"
        d="M 1021.5 830.423 C 1026.54 829.911 1045.81 832.659 1051.64 833.401 C 1072.38 835.99 1093.1 838.746 1113.8 841.667 L 1329.99 871.428 L 1329.95 1306.51 L 1330 1422.21 C 1330.01 1450.54 1332.08 1491.81 1325.18 1518.04 C 1318.79 1541.46 1305.62 1562.47 1287.31 1578.42 C 1269.98 1593.59 1234.62 1610.78 1212.96 1622.97 C 1151.4 1657.6 1087.44 1689.5 1026.42 1725.08 L 1024.58 1725.72 C 1020.72 1724.57 1005.67 1715.74 1001.44 1713.38 C 986.676 1705.08 971.857 1696.88 956.982 1688.79 L 836.342 1623.07 C 818.678 1613.37 800.537 1603.48 783.285 1593.93 C 741.183 1570.62 718.225 1528.6 718.162 1480.8 C 718.14 1463.85 718.093 1446.28 718.119 1429.07 L 718.13 1313.33 L 718.15 871.408 C 819.171 858.462 920.068 841.835 1021.5 830.423 z"
      />
      <path
        fill="currentColor"
        d="M 687.515 577.4 C 696.504 576.451 715.718 579.584 725.68 580.913 L 782.266 588.553 C 853.62 598.25 926.853 607.634 997.939 618.387 L 997.872 779.654 C 966.188 784.487 928.734 789.954 897.039 793.352 L 897.073 705.399 C 831.524 696.853 760.432 685.286 694.176 678.356 C 683.151 677.203 646.195 683.753 632.643 685.485 L 487.112 705.406 C 488.77 841.757 487.098 980.17 487.357 1116.69 L 487.339 1188.98 C 487.213 1243.94 479.328 1246.69 530.666 1273.69 C 574.625 1298.03 623.372 1322.43 666.093 1347.35 C 665.454 1385.26 666.06 1424.82 666.087 1462.87 C 649.609 1452.6 628.321 1441.62 610.88 1432.12 L 500.871 1372.76 C 476.603 1359.56 440.159 1342.09 421.535 1323.57 C 404.11 1306.02 392.433 1283.59 388.055 1259.25 C 384.254 1237.81 385.323 1203.28 385.354 1180.66 L 385.478 1064.48 L 385.312 618.209 C 414.868 615.376 445.833 609.518 475.437 605.863 C 545.54 597.208 617.46 584.737 687.515 577.4 z"
      />
      <path
        fill="currentColor"
        d="M 1348.89 577.369 C 1360.73 575.936 1415.83 584.528 1431.77 586.589 C 1508.75 596.536 1585.62 608.685 1662.67 618.335 L 1662.73 1028.87 L 1662.69 1154.09 C 1662.67 1223.3 1674.33 1293.75 1609.64 1337.92 C 1596.01 1347.22 1581.75 1354.57 1567.33 1362.44 L 1512.89 1391.87 L 1382 1462.6 C 1383.76 1427.96 1382.35 1382.83 1382.21 1347.24 C 1420 1324.81 1467.93 1301.58 1507.58 1279.5 C 1524.53 1270.36 1558.74 1256.3 1560.1 1235.39 C 1561.42 1215.18 1560.95 1193.69 1560.9 1173.32 L 1560.87 1066.29 L 1560.68 705.345 C 1543.39 703.65 1521.51 700.068 1504.1 697.576 C 1473.23 693.054 1442.33 688.801 1411.39 684.819 C 1399.03 683.204 1369.09 678.563 1357.99 678.482 C 1343.65 678.377 1310.02 683.839 1294.14 685.904 C 1246.36 692.092 1198.63 698.627 1150.95 705.51 C 1151.37 734.567 1151.1 764.255 1151.14 793.361 C 1118.48 789.558 1083.43 784.206 1050.79 779.597 L 1050.69 617.847 L 1348.89 577.369 z"
      />
      <path
        fill="currentColor"
        d="M 1017.32 323.354 C 1027.15 321.591 1105.66 333.344 1122.51 335.603 C 1166.74 341.267 1210.92 347.328 1255.05 353.786 C 1279.68 357.183 1305.51 360.23 1329.92 364.192 L 1329.98 526.684 C 1296.55 530.372 1261.73 535.721 1228.25 540.29 C 1228.4 510.591 1228.39 480.892 1228.23 451.193 C 1219.27 449.729 1209.61 448.427 1200.57 447.329 C 1144.13 440.467 1086.78 429.864 1030.24 424.572 C 1018.71 422.967 967.642 430.978 952.027 433.125 L 819.579 450.968 C 820.252 479.945 819.726 511.22 819.879 540.382 C 785.991 535.397 752.051 530.778 718.064 526.526 L 717.99 364.358 C 745.543 359.872 774.642 356.332 802.417 352.399 L 1017.32 323.354 z"
      />
    </svg>
  );
}

/* ── Scan (detection) — target/radar with checkmark ────────────── */
export function ScanIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
      <path d="M9 12L11 14L15 10" />
    </svg>
  );
}

/* ── Lock (secured) — padlock ──────────────────────────────────── */
export function LockIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 018 0v4" />
      <circle cx="12" cy="16" r="1.5" fill="currentColor" />
    </svg>
  );
}

/* ── Alert (warning) — triangle with exclamation ───────────────── */
export function AlertIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M12 2L2 20h20L12 2z" />
      <path d="M12 9v4" />
      <circle cx="12" cy="16" r="0.5" fill="currentColor" />
    </svg>
  );
}

/* ── Terminal (CLI) — prompt bracket >_ ────────────────────────── */
export function TerminalIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="M6 9l3 3-3 3" />
      <path d="M12 15h5" />
    </svg>
  );
}

/* ── Network (endpoints) — connected nodes ─────────────────────── */
export function NetworkIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="12" cy="12" r="2.5" />
      <circle cx="4" cy="6" r="2" />
      <circle cx="20" cy="6" r="2" />
      <circle cx="4" cy="18" r="2" />
      <circle cx="20" cy="18" r="2" />
      <path d="M10 10.5L5.5 7.5" />
      <path d="M14 10.5L18.5 7.5" />
      <path d="M10 13.5L5.5 16.5" />
      <path d="M14 13.5L18.5 16.5" />
    </svg>
  );
}

/* ── Analytics (insights) — chart lines ────────────────────────── */
export function AnalyticsIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M3 20L3 4" />
      <path d="M3 20L21 20" />
      <path d="M6 16L10 10L14 13L20 6" />
      <circle cx="6" cy="16" r="1" fill="currentColor" />
      <circle cx="10" cy="10" r="1" fill="currentColor" />
      <circle cx="14" cy="13" r="1" fill="currentColor" />
      <circle cx="20" cy="6" r="1" fill="currentColor" />
    </svg>
  );
}

/* ── Check (safe) — checkmark in circle ────────────────────────── */
export function CheckIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="12" cy="12" r="10" />
      <path d="M8 12L11 15L16 9" />
    </svg>
  );
}

/* ── Block (threat) — X in circle ──────────────────────────────── */
export function BlockIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="12" cy="12" r="10" />
      <path d="M9 9L15 15" />
      <path d="M15 9L9 15" />
    </svg>
  );
}

/* ── History (timeline) — clock ────────────────────────────────── */
export function HistoryIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </svg>
  );
}

/* ── Monitor (watching) — eye ──────────────────────────────────── */
export function MonitorIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

/* ── Response (instant) — lightning bolt ────────────────────────── */
export function ResponseIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" />
    </svg>
  );
}

/* ── Deploy (install) — download arrow ─────────────────────────── */
export function DeployIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M12 3v12" />
      <path d="M8 11l4 4 4-4" />
      <path d="M4 19h16" />
    </svg>
  );
}

/* ── Global (multilingual) — globe with lines ──────────────────── */
export function GlobalIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20" />
      <path d="M12 2a15 15 0 014 10 15 15 0 01-4 10" />
      <path d="M12 2a15 15 0 00-4 10 15 15 0 004 10" />
    </svg>
  );
}

/* ── Team (collaboration) — people group ───────────────────────── */
export function TeamIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="9" cy="7" r="3" />
      <path d="M3 21v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
      <circle cx="17" cy="9" r="2.5" />
      <path d="M21 21v-1.5a3 3 0 00-2.5-2.96" />
    </svg>
  );
}

/* ── Settings (config) — gear ──────────────────────────────────── */
export function SettingsIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09a1.65 1.65 0 00-1.08-1.51 1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09a1.65 1.65 0 001.51-1.08 1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001.08 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9c.26.604.852.997 1.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1.08z" />
    </svg>
  );
}

/* ── Support (24/7) — headset with badge ───────────────────────── */
export function SupportIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M4 13a8 8 0 1116 0" />
      <path d="M4 13v3a2 2 0 002 2h1" />
      <path d="M20 13v3a2 2 0 01-2 2h-1" />
      <rect x="2" y="11" width="4" height="6" rx="1" />
      <rect x="18" y="11" width="4" height="6" rx="1" />
      <path d="M9 21h6" />
      <path d="M12 18v3" />
    </svg>
  );
}

/* ── Enterprise — building ─────────────────────────────────────── */
export function EnterpriseIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <rect x="4" y="3" width="16" height="18" rx="1" />
      <path d="M9 21V16h6v5" />
      <path d="M8 7h2" />
      <path d="M14 7h2" />
      <path d="M8 11h2" />
      <path d="M14 11h2" />
    </svg>
  );
}

/* ── Chat (AI copilot) — speech bubble ───────────────────────── */
export function ChatIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
      <path d="M8 10h8" />
      <path d="M8 13h5" />
    </svg>
  );
}

/* ── Trap (honeypot) — honeypot jar ──────────────────────────── */
export function TrapIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M8 2h8l2 4H6l2-4z" />
      <path d="M6 6v2a6 6 0 006 6 6 6 0 006-6V6" />
      <path d="M9 14v4a3 3 0 003 3 3 3 0 003-3v-4" />
      <circle cx="12" cy="10" r="1" fill="currentColor" />
    </svg>
  );
}

/* ── Integration (connect) — puzzle piece ────────────────────── */
export function IntegrationIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M5 8h2a2 2 0 002-2 2 2 0 012-2 2 2 0 012 2 2 2 0 002 2h2v2a2 2 0 002 2 2 2 0 010 4 2 2 0 00-2 2v2H13a2 2 0 00-2-2 2 2 0 01-2 2H5v-4a2 2 0 010-4V8z" />
    </svg>
  );
}

/* ── Report (compliance) — clipboard with lines ──────────────── */
export function ReportIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <rect x="5" y="3" width="14" height="18" rx="2" />
      <path d="M9 1v4" />
      <path d="M15 1v4" />
      <path d="M9 10h6" />
      <path d="M9 14h4" />
      <path d="M9 18h2" />
    </svg>
  );
}

/* ── Compliance (certification) — badge with check ───────────── */
export function ComplianceIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M12 2l3 3h4v4l3 3-3 3v4h-4l-3 3-3-3H5v-4l-3-3 3-3V5h4l3-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

/* ── Automation (gears/workflow) — circular arrows ───────────── */
export function AutomationIcon({ size = 24, className = '' }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} {...defaults}>
      <path d="M12 2a10 10 0 017.07 2.93" />
      <path d="M19.07 4.93L16 5" />
      <path d="M19.07 4.93L19 8" />
      <path d="M22 12a10 10 0 01-2.93 7.07" />
      <path d="M19.07 19.07L20 16" />
      <path d="M19.07 19.07L16 19" />
      <path d="M12 22a10 10 0 01-7.07-2.93" />
      <path d="M4.93 19.07L8 19" />
      <path d="M4.93 19.07L5 16" />
      <path d="M2 12A10 10 0 014.93 4.93" />
      <path d="M4.93 4.93L4 8" />
      <path d="M4.93 4.93L8 5" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}
