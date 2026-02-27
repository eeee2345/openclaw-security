/**
 * Email SMTP notification integration
 * Email SMTP 通知整合
 *
 * Sends threat alerts via raw SMTP without external dependencies.
 * Uses Node.js net/tls modules for direct SMTP communication.
 * 透過原始 SMTP 發送威脅警報，不使用外部相依套件。
 * 使用 Node.js net/tls 模組進行直接 SMTP 通訊。
 *
 * @module @panguard-ai/panguard-guard/notify/email
 */

import * as net from 'node:net';
import * as tls from 'node:tls';
import { createLogger } from '@panguard-ai/core';
import type { EmailConfig, NotificationResult, ThreatVerdict } from '../types.js';

const logger = createLogger('panguard-guard:notify:email');

/**
 * Send a threat alert via Email (raw SMTP)
 * 透過 Email (原始 SMTP) 發送威脅警報
 *
 * @param config - Email SMTP configuration / Email SMTP 配置
 * @param verdict - The threat verdict / 威脅判決
 * @param eventDescription - Event description / 事件描述
 * @returns Notification result / 通知結果
 */
export async function sendEmailNotify(
  config: EmailConfig,
  verdict: ThreatVerdict,
  eventDescription: string
): Promise<NotificationResult> {
  const subject = `[PanguardGuard] ${verdict.conclusion.toUpperCase()} Alert - Confidence ${verdict.confidence}%`;

  const body =
    `PanguardGuard Security Alert\n` +
    `========================\n\n` +
    `Conclusion: ${verdict.conclusion}\n` +
    `Confidence: ${verdict.confidence}%\n` +
    `Recommended Action: ${verdict.recommendedAction}\n` +
    `${verdict.mitreTechnique ? `MITRE ATT&CK: ${verdict.mitreTechnique}\n` : ''}` +
    `\nEvent Description:\n${eventDescription}\n` +
    `\nEvidence:\n${verdict.evidence.map((e) => `  - [${e.source}] ${e.description} (${e.confidence}%)`).join('\n')}\n` +
    `\nReasoning:\n${verdict.reasoning}\n` +
    `\nTimestamp: ${new Date().toISOString()}\n`;

  try {
    for (const recipient of config.to) {
      await sendSMTP(config, recipient, subject, body);
    }
    logger.info(`Email notification sent to ${config.to.length} recipients / Email 通知已發送`);
    return { channel: 'email', success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Email notification failed: ${msg} / Email 通知失敗: ${msg}`);
    return { channel: 'email', success: false, error: msg };
  }
}

/**
 * Send email via raw SMTP protocol / 透過原始 SMTP 協定發送電子郵件
 */
function sendSMTP(config: EmailConfig, to: string, subject: string, body: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const commands = [
      `EHLO panguard-guard`,
      `AUTH LOGIN`,
      Buffer.from(config.auth.user).toString('base64'),
      Buffer.from(config.auth.pass).toString('base64'),
      `MAIL FROM:<${config.from}>`,
      `RCPT TO:<${to}>`,
      `DATA`,
      `From: ${config.from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}\r\n.`,
      `QUIT`,
    ];

    let commandIndex = 0;
    let resolved = false;

    const onConnect = (socket: net.Socket | tls.TLSSocket) => {
      let buffer = '';

      socket.on('data', (data: Buffer) => {
        buffer += data.toString();

        // Process complete SMTP responses (ending with \r\n)
        // 處理完整的 SMTP 回應（以 \r\n 結尾）
        while (buffer.includes('\r\n')) {
          const lineEnd = buffer.indexOf('\r\n');
          const line = buffer.slice(0, lineEnd);
          buffer = buffer.slice(lineEnd + 2);

          const code = parseInt(line.slice(0, 3), 10);

          // Multi-line responses (code followed by dash) / 多行回應
          if (line[3] === '-') continue;

          // Check for errors / 檢查錯誤
          if (code >= 400) {
            if (!resolved) {
              resolved = true;
              socket.destroy();
              reject(new Error(`SMTP error ${code}: ${line}`));
            }
            return;
          }

          // Send next command / 發送下一個命令
          if (commandIndex < commands.length) {
            socket.write(commands[commandIndex] + '\r\n');
            commandIndex++;
          } else if (!resolved) {
            resolved = true;
            socket.destroy();
            resolve();
          }
        }
      });

      socket.on('error', (err: Error) => {
        if (!resolved) {
          resolved = true;
          reject(err);
        }
      });

      socket.on('close', () => {
        if (!resolved) {
          resolved = true;
          resolve();
        }
      });
    };

    if (config.secure) {
      const socket = tls.connect({ host: config.host, port: config.port }, () => onConnect(socket));
    } else {
      const socket = net.connect({ host: config.host, port: config.port }, () => onConnect(socket));
    }
  });
}
