/**
 * Verification email sender using raw SMTP (node:net / node:tls).
 * Follows the same pattern as panguard-chat email channel.
 * @module @panguard-ai/panguard-auth/email-verify
 */

import * as net from 'node:net';
import * as tls from 'node:tls';

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  from: string;
  auth: { user: string; pass: string };
}

/**
 * Build a simple MIME message for verification emails.
 */
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

/**
 * Send an email via raw SMTP.
 */
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

      // After EHLO, attempt STARTTLS if not already secure and server supports it
      if (!config.secure && !starttlsUpgraded && response.includes('STARTTLS')) {
        starttlsUpgraded = true;
        socket.write('STARTTLS\r\n');
        return;
      }

      // Handle STARTTLS 220 response: upgrade to TLS
      if (starttlsUpgraded && code === 220 && response.includes('TLS')) {
        const tlsSocket = tls.connect({ socket, host: config.host }, () => {
          // Re-EHLO after TLS upgrade
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
      // Direct TLS connection (port 465)
      socket = tls.connect({ host: config.host, port: config.port }, () => {});
    } else {
      // Plain connection (port 587) with STARTTLS upgrade
      socket = net.connect({ host: config.host, port: config.port }, () => {});
    }

    // Send initial EHLO after connection greeting
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

/**
 * Send a waitlist verification email.
 */
export async function sendVerificationEmail(
  config: SmtpConfig,
  to: string,
  verifyToken: string,
  baseUrl: string
): Promise<void> {
  const verifyLink = `${baseUrl}/api/waitlist/verify/${verifyToken}`;
  const subject = 'Panguard AI - Verify your email';
  const html = `
    <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
      <h2 style="color: #1A1614;">Welcome to Panguard AI</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        Thank you for joining the Panguard AI waitlist. Please verify your email address
        by clicking the link below:
      </p>
      <p style="text-align: center; margin: 24px 0;">
        <a href="${verifyLink}"
           style="background: #8B9A8E; color: #fff; padding: 12px 24px;
                  text-decoration: none; border-radius: 6px; display: inline-block;">
          Verify Email
        </a>
      </p>
      <p style="color: #999; font-size: 12px;">
        If you did not sign up, you can safely ignore this email.
      </p>
    </div>
  `;

  const mime = buildMime(config.from, to, subject, html);
  await sendSmtp(config, to, mime);
}

/**
 * Send a welcome email after waitlist approval.
 */
export async function sendWelcomeEmail(
  config: SmtpConfig,
  to: string,
  name: string,
  baseUrl: string
): Promise<void> {
  const registerLink = `${baseUrl}/register`;
  const subject = "Panguard AI - You're in!";
  const html = `
    <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
      <h2 style="color: #1A1614;">You're in, ${name || 'there'}!</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        Your spot on the Panguard AI waitlist has been approved. You can now create
        your account and start using the platform.
      </p>
      <p style="text-align: center; margin: 24px 0;">
        <a href="${registerLink}"
           style="background: #8B9A8E; color: #fff; padding: 12px 24px;
                  text-decoration: none; border-radius: 6px; display: inline-block;">
          Create Account
        </a>
      </p>
    </div>
  `;

  const mime = buildMime(config.from, to, subject, html);
  await sendSmtp(config, to, mime);
}
