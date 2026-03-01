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

// ── Brand Email Layout ───────────────────────────────────────────────
//
// Dark theme matching panguard.ai visual identity:
//   Surface-0: #1A1614  |  Surface-1: #1F1C19  |  Surface-2: #272320
//   Sage:      #8B9A8E  |  Text:      #F5F1E8  |  Muted:    #706860
//   Border:    #2E2A27
//
// Uses table layout for max email client compatibility.

const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';

function emailShell(content: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark">
<style>body,table,td{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}table{border-collapse:collapse!important}img{-ms-interpolation-mode:bicubic}a{color:#8B9A8E}</style>
</head>
<body style="margin:0;padding:0;background-color:#111110;font-family:${FONT};">
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
      <tr><td align="center" style="font-family:${FONT};font-size:11px;color:#4A4540;line-height:1.5;">
        Panguard AI &mdash; AI-Powered Endpoint Security<br>
        &copy; ${new Date().getFullYear()} Panguard AI. All rights reserved.
      </td></tr>
    </table>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

function sageButton(href: string, label: string): string {
  return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
  <tr><td align="center" style="border-radius:24px;background-color:#8B9A8E;">
    <a href="${href}" target="_blank" style="display:inline-block;padding:14px 32px;font-family:${FONT};font-size:14px;font-weight:600;color:#1A1614;text-decoration:none;border-radius:24px;letter-spacing:0.3px;">${label}</a>
  </td></tr>
</table>`;
}

function sageDivider(): string {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
  <tr><td style="height:1px;background:linear-gradient(90deg,transparent,#2E2A27 20%,#2E2A27 80%,transparent);font-size:0;line-height:0;">&nbsp;</td></tr>
</table>`;
}

function heading(text: string): string {
  return `<h1 style="margin:0 0 6px;font-family:${FONT};font-size:22px;font-weight:700;color:#F5F1E8;letter-spacing:-0.3px;">${text}</h1>`;
}

function subheading(text: string): string {
  return `<p style="margin:0 0 24px;font-family:${FONT};font-size:13px;color:#706860;letter-spacing:0.5px;">${text}</p>`;
}

function paragraph(text: string): string {
  return `<p style="margin:0 0 16px;font-family:${FONT};font-size:14px;color:#A09890;line-height:1.7;">${text}</p>`;
}

function muted(text: string): string {
  return `<p style="margin:16px 0 0;font-family:${FONT};font-size:12px;color:#4A4540;line-height:1.6;">${text}</p>`;
}

function featureRow(label: string, desc: string): string {
  return `<tr>
  <td style="padding:8px 12px 8px 0;vertical-align:top;width:20px;">
    <div style="width:6px;height:6px;background:#8B9A8E;border-radius:50%;margin-top:6px;"></div>
  </td>
  <td style="padding:8px 0;">
    <span style="font-family:${FONT};font-size:13px;font-weight:600;color:#F5F1E8;">${label}</span>
    <span style="font-family:${FONT};font-size:13px;color:#706860;"> &mdash; ${desc}</span>
  </td>
</tr>`;
}

// ── Email Templates ─────────────────────────────────────────────────

export async function sendVerificationEmail(
  config: EmailConfig,
  to: string,
  verifyToken: string,
  baseUrl: string
): Promise<void> {
  const verifyLink = `${baseUrl}/api/waitlist/verify/${verifyToken}`;
  const subject = 'Verify your email | Panguard AI';
  const html = emailShell(`
    ${heading('Verify your email')}
    ${subheading('PANGUARD AI WAITLIST')}
    ${paragraph('Thank you for joining the Panguard AI early access waitlist. To confirm your spot, please verify your email address.')}
    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(verifyLink, 'Verify Email Address')}
    </div>
    ${sageDivider()}
    ${muted('If you did not sign up for Panguard AI, you can safely ignore this email. This link expires in 24 hours.')}
    ${muted(`<span style="color:#706860;word-break:break-all;">Can't click the button? Copy this link:<br><a href="${verifyLink}" style="color:#8B9A8E;text-decoration:underline;">${verifyLink}</a></span>`)}
  `);
  await sendEmail(config, to, subject, html);
}

export async function sendExpirationWarningEmail(
  config: EmailConfig,
  to: string,
  name: string,
  tier: string,
  expiresAt: string,
  baseUrl: string
): Promise<void> {
  const renewLink = `${baseUrl}/pricing`;
  const daysLeft = Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / (24 * 60 * 60 * 1000)));
  const expiryDate = new Date(expiresAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const subject = `Your ${tier} plan expires in ${daysLeft} day(s) | Panguard AI`;
  const tierUpper = tier.charAt(0).toUpperCase() + tier.slice(1);
  const html = emailShell(`
    ${heading('Plan expiring soon')}
    ${subheading('SUBSCRIPTION NOTICE')}
    ${paragraph(`Hi ${name || 'there'},`)}
    ${paragraph(`Your <strong style="color:#F5F1E8;">${tierUpper}</strong> plan will expire on <strong style="color:#F5F1E8;">${expiryDate}</strong>. That's <span style="color:#FBBF24;font-weight:600;">${daysLeft} day(s)</span> from now.`)}

    <!-- Status box -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:20px 0;background-color:#272320;border:1px solid #2E2A27;border-radius:8px;">
      <tr><td style="padding:16px 20px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-family:${FONT};font-size:12px;color:#706860;letter-spacing:0.5px;">CURRENT PLAN</td>
            <td align="right" style="font-family:${FONT};font-size:12px;color:#706860;letter-spacing:0.5px;">EXPIRES</td>
          </tr>
          <tr>
            <td style="font-family:${FONT};font-size:16px;font-weight:700;color:#8B9A8E;padding-top:4px;">${tierUpper}</td>
            <td align="right" style="font-family:${FONT};font-size:16px;font-weight:700;color:#FBBF24;padding-top:4px;">${expiryDate}</td>
          </tr>
        </table>
      </td></tr>
    </table>

    ${paragraph('After expiration, your account will be automatically downgraded to the Community (free) tier. You will lose access to paid features including AI analysis, advanced alerts, and reports.')}
    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(renewLink, 'Renew Subscription')}
    </div>
    ${sageDivider()}
    ${muted('Questions? Reply to this email or contact support@panguard.ai.')}
  `);
  await sendEmail(config, to, subject, html);
}

export async function sendResetEmail(
  config: EmailConfig,
  to: string,
  resetToken: string,
  baseUrl: string
): Promise<void> {
  const resetLink = `${baseUrl}/reset-password?token=${resetToken}`;
  const subject = 'Reset your password | Panguard AI';
  const html = emailShell(`
    ${heading('Reset your password')}
    ${subheading('SECURITY REQUEST')}
    ${paragraph('We received a request to reset the password for your Panguard AI account. Click the button below to choose a new password.')}
    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(resetLink, 'Reset Password')}
    </div>
    ${sageDivider()}

    <!-- Security notice -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 0;background-color:#272320;border:1px solid #2E2A27;border-radius:8px;">
      <tr><td style="padding:14px 18px;">
        <p style="margin:0;font-family:${FONT};font-size:12px;color:#706860;line-height:1.6;">
          This link expires in <strong style="color:#A09890;">1 hour</strong>. If you did not request a password reset, no action is needed &mdash; your password will remain unchanged. If you're concerned about your account security, please contact support@panguard.ai.
        </p>
      </td></tr>
    </table>

    ${muted(`<span style="color:#706860;word-break:break-all;">Can't click the button? Copy this link:<br><a href="${resetLink}" style="color:#8B9A8E;text-decoration:underline;">${resetLink}</a></span>`)}
  `);
  await sendEmail(config, to, subject, html);
}

export async function sendWelcomeEmail(
  config: EmailConfig,
  to: string,
  name: string,
  baseUrl: string
): Promise<void> {
  const registerLink = `${baseUrl}/register`;
  const docsLink = 'https://panguard.ai/docs/getting-started';
  const subject = "You're in | Panguard AI";
  const greeting = name ? `${name}, you're in` : "You're in";
  const html = emailShell(`
    ${heading(greeting)}
    ${subheading('EARLY ACCESS APPROVED')}
    ${paragraph('Your spot on the Panguard AI waitlist has been approved. Welcome to the next generation of endpoint security.')}
    ${sageDivider()}

    <!-- What you get -->
    <p style="margin:0 0 12px;font-family:${FONT};font-size:11px;font-weight:600;color:#706860;letter-spacing:1.5px;">WHAT'S INCLUDED</p>
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
      ${featureRow('Panguard Scan', 'Deep vulnerability scanning for your servers')}
      ${featureRow('Panguard Guard', 'Real-time threat detection and auto-response')}
      ${featureRow('AI Analysis', 'Multi-agent pipeline for intelligent threat assessment')}
      ${featureRow('Auto-fix', 'One-click remediation for known vulnerabilities')}
    </table>

    ${sageDivider()}
    <div style="text-align:center;padding:8px 0 8px;">
      ${sageButton(registerLink, 'Create Your Account')}
    </div>

    <!-- Quick links -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;">
      <tr><td align="center">
        <a href="${docsLink}" style="font-family:${FONT};font-size:12px;color:#8B9A8E;text-decoration:underline;">Read the Getting Started guide</a>
      </td></tr>
    </table>

    ${sageDivider()}
    ${muted('Questions? Reply to this email or reach us at support@panguard.ai. We typically respond within 24 hours.')}
  `);
  await sendEmail(config, to, subject, html);
}
