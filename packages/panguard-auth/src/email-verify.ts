/**
 * Email sender with Resend API (preferred) and raw SMTP fallback.
 * @module @panguard-ai/panguard-auth/email-verify
 */

import * as net from 'node:net';
import * as tls from 'node:tls';

// ── Config Types ────────────────────────────────────────────────────

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  from: string;
  auth: { user: string; pass: string };
}

export interface ResendConfig {
  apiKey: string;
  from: string;
}

export type EmailConfig = SmtpConfig | ResendConfig;

function isResendConfig(config: EmailConfig): config is ResendConfig {
  return 'apiKey' in config && !('host' in config);
}

// ── Unified Send ────────────────────────────────────────────────────

async function sendEmail(
  config: EmailConfig,
  to: string,
  subject: string,
  html: string
): Promise<void> {
  if (isResendConfig(config)) {
    await sendViaResend(config, to, subject, html);
  } else {
    const mime = buildMime(config.from, to, subject, html);
    await sendSmtp(config, to, mime);
  }
}

// ── Resend HTTP API ─────────────────────────────────────────────────

async function sendViaResend(
  config: ResendConfig,
  to: string,
  subject: string,
  html: string
): Promise<void> {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: config.from,
      to: [to],
      subject,
      html,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Resend API error (${res.status}): ${body}`);
  }
}

// ── Raw SMTP (fallback) ─────────────────────────────────────────────

function buildMime(from: string, to: string, subject: string, bodyHtml: string): string {
  const boundary = `----MIMEBoundary${Date.now()}`;
  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(bodyHtml.replace(/<[^>]+>/g, '')).toString('base64'),
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(bodyHtml).toString('base64'),
    '',
    `--${boundary}--`,
  ];
  return lines.join('\r\n');
}

function sendSmtp(config: SmtpConfig, to: string, mime: string): Promise<void> {
  return new Promise((resolve, reject) => {
    let commandIndex = -1;
    let dataPhase = false;
    let starttlsUpgraded = false;
    let socket: net.Socket;

    const commands = [
      'AUTH LOGIN',
      Buffer.from(config.auth.user).toString('base64'),
      Buffer.from(config.auth.pass).toString('base64'),
      `MAIL FROM:<${config.from}>`,
      `RCPT TO:<${to}>`,
      'DATA',
    ];

    const onData = (data: Buffer) => {
      const response = data.toString();
      const code = parseInt(response.slice(0, 3), 10);

      if (dataPhase) {
        if (code === 354 || response.includes('354')) {
          socket.write(`${mime}\r\n.\r\n`);
          dataPhase = false;
        }
        return;
      }

      if (code >= 400) {
        socket.destroy();
        reject(new Error(`SMTP error: ${response.trim()}`));
        return;
      }

      if (!config.secure && !starttlsUpgraded && response.includes('STARTTLS')) {
        starttlsUpgraded = true;
        socket.write('STARTTLS\r\n');
        return;
      }

      if (starttlsUpgraded && code === 220 && response.includes('TLS')) {
        const tlsSocket = tls.connect({ socket, host: config.host }, () => {
          tlsSocket.write('EHLO localhost\r\n');
        });
        tlsSocket.on('data', onData);
        tlsSocket.on('error', reject);
        socket = tlsSocket;
        return;
      }

      commandIndex++;
      if (commandIndex < commands.length) {
        const cmd = commands[commandIndex]!;
        if (cmd === 'DATA') dataPhase = true;
        socket.write(`${cmd}\r\n`);
      } else {
        socket.write('QUIT\r\n');
        socket.end();
        resolve();
      }
    };

    if (config.secure) {
      socket = tls.connect({ host: config.host, port: config.port }, () => {});
    } else {
      socket = net.connect({ host: config.host, port: config.port }, () => {});
    }

    socket.once('data', (greeting: Buffer) => {
      const code = parseInt(greeting.toString().slice(0, 3), 10);
      if (code >= 400) {
        socket.destroy();
        reject(new Error(`SMTP greeting error: ${greeting.toString().trim()}`));
        return;
      }
      socket.write('EHLO localhost\r\n');
      socket.on('data', onData);
    });

    socket.on('error', reject);
    socket.setTimeout(30000, () => {
      socket.destroy();
      reject(new Error('SMTP connection timeout'));
    });
  });
}

// ── Locale Detection ─────────────────────────────────────────────────

export type EmailLocale = 'en' | 'zh';

/**
 * Detect locale from Accept-Language header or explicit parameter.
 * Returns 'zh' for any Chinese variant (zh, zh-TW, zh-CN, zh-Hant, etc.),
 * 'en' for everything else.
 */
export function detectLocale(
  acceptLanguage?: string | null,
  explicit?: string | null
): EmailLocale {
  if (explicit) {
    return explicit.startsWith('zh') ? 'zh' : 'en';
  }
  if (!acceptLanguage) return 'en';
  const primary = acceptLanguage.split(',')[0]?.trim().split(';')[0]?.trim().toLowerCase() ?? '';
  return primary.startsWith('zh') ? 'zh' : 'en';
}

// ── i18n Dictionary ──────────────────────────────────────────────────

interface EmailStrings {
  // Shell
  footerTagline: string;
  footerRights: string;
  // Verification
  verifySubject: string;
  verifyHeading: string;
  verifyOverline: string;
  verifyBody: string;
  verifyButton: string;
  verifyIgnore: string;
  verifyCantClick: string;
  // Welcome
  welcomeSubject: string;
  welcomeGreeting: (name: string) => string;
  welcomeOverline: string;
  welcomeBody: string;
  welcomeIncluded: string;
  welcomeButton: string;
  welcomeDocs: string;
  welcomeHelp: string;
  featureScan: string;
  featureScanDesc: string;
  featureGuard: string;
  featureGuardDesc: string;
  featureAI: string;
  featureAIDesc: string;
  featureFix: string;
  featureFixDesc: string;
  // Reset
  resetSubject: string;
  resetHeading: string;
  resetOverline: string;
  resetBody: string;
  resetButton: string;
  resetNotice: string;
  resetCantClick: string;
  // Expiration
  expirationSubject: (tier: string, days: number) => string;
  expirationHeading: string;
  expirationOverline: string;
  expirationHi: (name: string) => string;
  expirationBody: (tier: string, date: string, days: number) => string;
  expirationPlanLabel: string;
  expirationExpiresLabel: string;
  expirationDowngrade: string;
  expirationButton: string;
  expirationHelp: string;
}

const i18n: Record<EmailLocale, EmailStrings> = {
  en: {
    footerTagline: 'Panguard AI &mdash; AI-Powered Endpoint Security',
    footerRights: `&copy; ${new Date().getFullYear()} Panguard AI. All rights reserved.`,
    verifySubject: 'Verify your email | Panguard AI',
    verifyHeading: 'Verify your email',
    verifyOverline: 'PANGUARD AI WAITLIST',
    verifyBody:
      'Thank you for joining the Panguard AI early access waitlist. To confirm your spot, please verify your email address.',
    verifyButton: 'Verify Email Address',
    verifyIgnore:
      'If you did not sign up for Panguard AI, you can safely ignore this email. This link expires in 24 hours.',
    verifyCantClick: "Can't click the button? Copy this link:",
    welcomeSubject: "You're in | Panguard AI",
    welcomeGreeting: (name) => (name ? `${name}, you're in` : "You're in"),
    welcomeOverline: 'EARLY ACCESS APPROVED',
    welcomeBody:
      'Your spot on the Panguard AI waitlist has been approved. Welcome to the next generation of endpoint security.',
    welcomeIncluded: "WHAT'S INCLUDED",
    welcomeButton: 'Create Your Account',
    welcomeDocs: 'Read the Getting Started guide',
    welcomeHelp:
      'Questions? Reply to this email or reach us at support@panguard.ai. We typically respond within 24 hours.',
    featureScan: 'Panguard Scan',
    featureScanDesc: 'Deep vulnerability scanning for your servers',
    featureGuard: 'Panguard Guard',
    featureGuardDesc: 'Real-time threat detection and auto-response',
    featureAI: 'AI Analysis',
    featureAIDesc: 'Multi-agent pipeline for intelligent threat assessment',
    featureFix: 'Auto-fix',
    featureFixDesc: 'One-click remediation for known vulnerabilities',
    resetSubject: 'Reset your password | Panguard AI',
    resetHeading: 'Reset your password',
    resetOverline: 'SECURITY REQUEST',
    resetBody:
      'We received a request to reset the password for your Panguard AI account. Click the button below to choose a new password.',
    resetButton: 'Reset Password',
    resetNotice:
      'This link expires in <strong style="color:#A09890;">1 hour</strong>. If you did not request a password reset, no action is needed &mdash; your password will remain unchanged. If you\'re concerned about your account security, please contact support@panguard.ai.',
    resetCantClick: "Can't click the button? Copy this link:",
    expirationSubject: (tier, days) => `Your ${tier} plan expires in ${days} day(s) | Panguard AI`,
    expirationHeading: 'Plan expiring soon',
    expirationOverline: 'SUBSCRIPTION NOTICE',
    expirationHi: (name) => `Hi ${name || 'there'},`,
    expirationBody: (tier, date, days) =>
      `Your <strong style="color:#F5F1E8;">${tier}</strong> plan will expire on <strong style="color:#F5F1E8;">${date}</strong>. That's <span style="color:#FBBF24;font-weight:600;">${days} day(s)</span> from now.`,
    expirationPlanLabel: 'CURRENT PLAN',
    expirationExpiresLabel: 'EXPIRES',
    expirationDowngrade:
      'After expiration, your account will be automatically downgraded to the Community (free) tier. You will lose access to paid features including AI analysis, advanced alerts, and reports.',
    expirationButton: 'Renew Subscription',
    expirationHelp: 'Questions? Reply to this email or contact support@panguard.ai.',
  },
  zh: {
    footerTagline: 'Panguard AI &mdash; AI 驅動的端點安全防護',
    footerRights: `&copy; ${new Date().getFullYear()} Panguard AI. 保留所有權利。`,
    verifySubject: '驗證您的信箱 | Panguard AI',
    verifyHeading: '驗證您的電子信箱',
    verifyOverline: 'PANGUARD AI 候補名單',
    verifyBody:
      '感謝您加入 Panguard AI 搶先體驗候補名單。請點擊下方按鈕驗證您的電子信箱，以確認您的名額。',
    verifyButton: '驗證電子信箱',
    verifyIgnore: '如果您並未註冊 Panguard AI，請忽略此信。此連結將於 24 小時後失效。',
    verifyCantClick: '無法點擊按鈕？請複製以下連結：',
    welcomeSubject: '您已通過審核 | Panguard AI',
    welcomeGreeting: (name) => (name ? `${name}，歡迎加入` : '歡迎加入'),
    welcomeOverline: '搶先體驗資格已通過',
    welcomeBody: '您在 Panguard AI 候補名單上的名額已獲核准。歡迎體驗新一代的端點安全防護。',
    welcomeIncluded: '包含功能',
    welcomeButton: '建立您的帳號',
    welcomeDocs: '閱讀快速入門指南',
    welcomeHelp:
      '有任何問題？請直接回覆此信或聯繫 support@panguard.ai，我們通常會在 24 小時內回覆。',
    featureScan: 'Panguard Scan',
    featureScanDesc: '深度弱點掃描，全面檢測伺服器漏洞',
    featureGuard: 'Panguard Guard',
    featureGuardDesc: '即時威脅偵測與自動回應',
    featureAI: 'AI 分析',
    featureAIDesc: '多代理 AI 管線智慧威脅評估',
    featureFix: '自動修復',
    featureFixDesc: '一鍵修復已知弱點',
    resetSubject: '重設您的密碼 | Panguard AI',
    resetHeading: '重設您的密碼',
    resetOverline: '安全性請求',
    resetBody: '我們收到了重設您 Panguard AI 帳號密碼的請求。請點擊下方按鈕設定新密碼。',
    resetButton: '重設密碼',
    resetNotice:
      '此連結將於 <strong style="color:#A09890;">1 小時</strong>後失效。如果您並未要求重設密碼，無需採取任何行動，您的密碼不會被更改。如果您擔心帳號安全，請聯繫 support@panguard.ai。',
    resetCantClick: '無法點擊按鈕？請複製以下連結：',
    expirationSubject: (tier, days) => `您的 ${tier} 方案將在 ${days} 天後到期 | Panguard AI`,
    expirationHeading: '方案即將到期',
    expirationOverline: '訂閱通知',
    expirationHi: (name) => `${name || '您'}好，`,
    expirationBody: (tier, date, days) =>
      `您的 <strong style="color:#F5F1E8;">${tier}</strong> 方案將於 <strong style="color:#F5F1E8;">${date}</strong> 到期，距今僅剩 <span style="color:#FBBF24;font-weight:600;">${days} 天</span>。`,
    expirationPlanLabel: '目前方案',
    expirationExpiresLabel: '到期日',
    expirationDowngrade:
      '到期後，您的帳號將自動降級為 Community（免費）方案。您將失去 AI 分析、進階警報及報告等付費功能的使用權限。',
    expirationButton: '續訂方案',
    expirationHelp: '有任何問題？請回覆此信或聯繫 support@panguard.ai。',
  },
};

function t(locale: EmailLocale): EmailStrings {
  return i18n[locale];
}

// ── Brand Email Layout ───────────────────────────────────────────────
//
// Dark theme matching panguard.ai visual identity:
//   Surface-0: #1A1614  |  Surface-1: #1F1C19  |  Surface-2: #272320
//   Sage:      #8B9A8E  |  Text:      #F5F1E8  |  Muted:    #706860
//   Border:    #2E2A27
//
// Uses table layout for max email client compatibility.

const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
const FONT_ZH = `"Noto Sans TC", "PingFang TC", "Microsoft JhengHei", ${FONT}`;

function fontFor(locale: EmailLocale): string {
  return locale === 'zh' ? FONT_ZH : FONT;
}

function emailShell(locale: EmailLocale, content: string): string {
  const s = t(locale);
  const f = fontFor(locale);
  const langAttr = locale === 'zh' ? 'zh-TW' : 'en';
  return `<!DOCTYPE html>
<html lang="${langAttr}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark">
<style>body,table,td{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}table{border-collapse:collapse!important}img{-ms-interpolation-mode:bicubic}a{color:#8B9A8E}</style>
</head>
<body style="margin:0;padding:0;background-color:#111110;font-family:${f};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#111110;">
<tr><td align="center" style="padding:40px 16px;">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;">

  <!-- Logo -->
  <tr><td align="center" style="padding-bottom:32px;">
    <table role="presentation" cellpadding="0" cellspacing="0"><tr>
      <td style="font-family:${FONT};font-size:13px;font-weight:700;letter-spacing:3px;color:#F5F1E8;">PANGUARD</td>
      <td style="padding:0 6px;">
        <div style="width:18px;height:18px;border:2px solid #8B9A8E;border-radius:3px;transform:rotate(0deg);display:inline-block;vertical-align:middle;position:relative;">
          <div style="width:8px;height:8px;background:#8B9A8E;border-radius:1px;position:absolute;top:3px;left:3px;"></div>
        </div>
      </td>
      <td style="font-family:${FONT};font-size:13px;font-weight:700;letter-spacing:3px;color:#F5F1E8;">AI</td>
    </tr></table>
  </td></tr>

  <!-- Card -->
  <tr><td>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#1A1614;border:1px solid #2E2A27;border-radius:12px;">
      <tr><td style="padding:40px 36px;">
        ${content}
      </td></tr>
    </table>
  </td></tr>

  <!-- Footer -->
  <tr><td style="padding-top:28px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
      <tr><td align="center" style="padding-bottom:16px;">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="padding:0 8px;"><a href="https://panguard.ai" style="color:#706860;font-family:${FONT};font-size:12px;text-decoration:none;">Website</a></td>
          <td style="color:#2E2A27;font-size:12px;">|</td>
          <td style="padding:0 8px;"><a href="https://github.com/panguard-ai/panguard-ai" style="color:#706860;font-family:${FONT};font-size:12px;text-decoration:none;">GitHub</a></td>
          <td style="color:#2E2A27;font-size:12px;">|</td>
          <td style="padding:0 8px;"><a href="https://x.com/panguard_ai" style="color:#706860;font-family:${FONT};font-size:12px;text-decoration:none;">Twitter</a></td>
        </tr></table>
      </td></tr>
      <tr><td align="center" style="font-family:${f};font-size:11px;color:#4A4540;line-height:1.5;">
        ${s.footerTagline}<br>
        ${s.footerRights}
      </td></tr>
    </table>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

function sageButton(locale: EmailLocale, href: string, label: string): string {
  const f = fontFor(locale);
  return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
  <tr><td align="center" style="border-radius:24px;background-color:#8B9A8E;">
    <a href="${href}" target="_blank" style="display:inline-block;padding:14px 32px;font-family:${f};font-size:14px;font-weight:600;color:#1A1614;text-decoration:none;border-radius:24px;letter-spacing:0.3px;">${label}</a>
  </td></tr>
</table>`;
}

function sageDivider(): string {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
  <tr><td style="height:1px;background:linear-gradient(90deg,transparent,#2E2A27 20%,#2E2A27 80%,transparent);font-size:0;line-height:0;">&nbsp;</td></tr>
</table>`;
}

function heading(locale: EmailLocale, text: string): string {
  const f = fontFor(locale);
  return `<h1 style="margin:0 0 6px;font-family:${f};font-size:22px;font-weight:700;color:#F5F1E8;letter-spacing:-0.3px;">${text}</h1>`;
}

function subheading(locale: EmailLocale, text: string): string {
  const f = fontFor(locale);
  return `<p style="margin:0 0 24px;font-family:${f};font-size:13px;color:#706860;letter-spacing:0.5px;">${text}</p>`;
}

function paragraph(locale: EmailLocale, text: string): string {
  const f = fontFor(locale);
  const lh = locale === 'zh' ? '1.85' : '1.7';
  return `<p style="margin:0 0 16px;font-family:${f};font-size:14px;color:#A09890;line-height:${lh};">${text}</p>`;
}

function muted(locale: EmailLocale, text: string): string {
  const f = fontFor(locale);
  return `<p style="margin:16px 0 0;font-family:${f};font-size:12px;color:#4A4540;line-height:1.6;">${text}</p>`;
}

function featureRow(locale: EmailLocale, label: string, desc: string): string {
  const f = fontFor(locale);
  return `<tr>
  <td style="padding:8px 12px 8px 0;vertical-align:top;width:20px;">
    <div style="width:6px;height:6px;background:#8B9A8E;border-radius:50%;margin-top:6px;"></div>
  </td>
  <td style="padding:8px 0;">
    <span style="font-family:${f};font-size:13px;font-weight:600;color:#F5F1E8;">${label}</span>
    <span style="font-family:${f};font-size:13px;color:#706860;"> &mdash; ${desc}</span>
  </td>
</tr>`;
}

// ── Email Templates ─────────────────────────────────────────────────

export async function sendVerificationEmail(
  config: EmailConfig,
  to: string,
  verifyToken: string,
  baseUrl: string,
  locale: EmailLocale = 'en'
): Promise<void> {
  const s = t(locale);
  const verifyLink = `${baseUrl}/api/waitlist/verify/${verifyToken}`;
  const html = emailShell(
    locale,
    `
    ${heading(locale, s.verifyHeading)}
    ${subheading(locale, s.verifyOverline)}
    ${paragraph(locale, s.verifyBody)}
    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(locale, verifyLink, s.verifyButton)}
    </div>
    ${sageDivider()}
    ${muted(locale, s.verifyIgnore)}
    ${muted(locale, `<span style="color:#706860;word-break:break-all;">${s.verifyCantClick}<br><a href="${verifyLink}" style="color:#8B9A8E;text-decoration:underline;">${verifyLink}</a></span>`)}
  `
  );
  await sendEmail(config, to, s.verifySubject, html);
}

export async function sendExpirationWarningEmail(
  config: EmailConfig,
  to: string,
  name: string,
  tier: string,
  expiresAt: string,
  baseUrl: string,
  locale: EmailLocale = 'en'
): Promise<void> {
  const s = t(locale);
  const f = fontFor(locale);
  const renewLink = `${baseUrl}/pricing`;
  const daysLeft = Math.max(
    0,
    Math.ceil((new Date(expiresAt).getTime() - Date.now()) / (24 * 60 * 60 * 1000))
  );
  const dateLocale = locale === 'zh' ? 'zh-TW' : 'en-US';
  const expiryDate = new Date(expiresAt).toLocaleDateString(dateLocale, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  const tierUpper = tier.charAt(0).toUpperCase() + tier.slice(1);
  const html = emailShell(
    locale,
    `
    ${heading(locale, s.expirationHeading)}
    ${subheading(locale, s.expirationOverline)}
    ${paragraph(locale, s.expirationHi(name))}
    ${paragraph(locale, s.expirationBody(tierUpper, expiryDate, daysLeft))}

    <!-- Status box -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:20px 0;background-color:#272320;border:1px solid #2E2A27;border-radius:8px;">
      <tr><td style="padding:16px 20px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-family:${f};font-size:12px;color:#706860;letter-spacing:0.5px;">${s.expirationPlanLabel}</td>
            <td align="right" style="font-family:${f};font-size:12px;color:#706860;letter-spacing:0.5px;">${s.expirationExpiresLabel}</td>
          </tr>
          <tr>
            <td style="font-family:${f};font-size:16px;font-weight:700;color:#8B9A8E;padding-top:4px;">${tierUpper}</td>
            <td align="right" style="font-family:${f};font-size:16px;font-weight:700;color:#FBBF24;padding-top:4px;">${expiryDate}</td>
          </tr>
        </table>
      </td></tr>
    </table>

    ${paragraph(locale, s.expirationDowngrade)}
    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(locale, renewLink, s.expirationButton)}
    </div>
    ${sageDivider()}
    ${muted(locale, s.expirationHelp)}
  `
  );
  await sendEmail(config, to, s.expirationSubject(tierUpper, daysLeft), html);
}

export async function sendResetEmail(
  config: EmailConfig,
  to: string,
  resetToken: string,
  baseUrl: string,
  locale: EmailLocale = 'en'
): Promise<void> {
  const s = t(locale);
  const f = fontFor(locale);
  const resetLink = `${baseUrl}/reset-password?token=${resetToken}`;
  const html = emailShell(
    locale,
    `
    ${heading(locale, s.resetHeading)}
    ${subheading(locale, s.resetOverline)}
    ${paragraph(locale, s.resetBody)}
    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(locale, resetLink, s.resetButton)}
    </div>
    ${sageDivider()}

    <!-- Security notice -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 0;background-color:#272320;border:1px solid #2E2A27;border-radius:8px;">
      <tr><td style="padding:14px 18px;">
        <p style="margin:0;font-family:${f};font-size:12px;color:#706860;line-height:1.6;">
          ${s.resetNotice}
        </p>
      </td></tr>
    </table>

    ${muted(locale, `<span style="color:#706860;word-break:break-all;">${s.resetCantClick}<br><a href="${resetLink}" style="color:#8B9A8E;text-decoration:underline;">${resetLink}</a></span>`)}
  `
  );
  await sendEmail(config, to, s.resetSubject, html);
}

export async function sendWelcomeEmail(
  config: EmailConfig,
  to: string,
  name: string,
  baseUrl: string,
  locale: EmailLocale = 'en'
): Promise<void> {
  const s = t(locale);
  const f = fontFor(locale);
  const registerLink = `${baseUrl}/register`;
  const docsLink = 'https://panguard.ai/docs/getting-started';
  const html = emailShell(
    locale,
    `
    ${heading(locale, s.welcomeGreeting(name))}
    ${subheading(locale, s.welcomeOverline)}
    ${paragraph(locale, s.welcomeBody)}
    ${sageDivider()}

    <!-- What you get -->
    <p style="margin:0 0 12px;font-family:${f};font-size:11px;font-weight:600;color:#706860;letter-spacing:1.5px;">${s.welcomeIncluded}</p>
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
      ${featureRow(locale, s.featureScan, s.featureScanDesc)}
      ${featureRow(locale, s.featureGuard, s.featureGuardDesc)}
      ${featureRow(locale, s.featureAI, s.featureAIDesc)}
      ${featureRow(locale, s.featureFix, s.featureFixDesc)}
    </table>

    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(locale, registerLink, s.welcomeButton)}
    </div>

    <!-- Quick links -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;">
      <tr><td align="center">
        <a href="${docsLink}" style="font-family:${f};font-size:12px;color:#8B9A8E;text-decoration:underline;">${s.welcomeDocs}</a>
      </td></tr>
    </table>

    ${sageDivider()}
    ${muted(locale, s.welcomeHelp)}
  `
  );
  await sendEmail(config, to, s.welcomeSubject, html);
}
