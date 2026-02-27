/**
 * Message Formatter
 * 訊息格式化器
 *
 * Adapts technical security verdicts into human-readable messages
 * based on user type (developer / boss / IT admin).
 * 根據用戶類型（開發者/老闆/IT管理者）將技術安全判決
 * 轉換為人類可讀的訊息。
 *
 * @module @panguard-ai/panguard-chat/agent/formatter
 */

import type {
  UserType,
  MessageLanguage,
  ThreatAlert,
  SummaryReport,
  LearningProgress,
  FormattedMessage,
  AlertSeverity,
  ConfirmationRequest,
} from '../types.js';

// ---------------------------------------------------------------------------
// Severity Mapping
// 嚴重等級對應
// ---------------------------------------------------------------------------

const SEVERITY_LABELS: Record<string, Record<MessageLanguage, string>> = {
  critical: { 'zh-TW': '[嚴重]', en: '[Critical]' },
  high: { 'zh-TW': '[嚴重]', en: '[Critical]' },
  medium: { 'zh-TW': '[注意]', en: '[Warning]' },
  warning: { 'zh-TW': '[注意]', en: '[Warning]' },
  low: { 'zh-TW': '[資訊]', en: '[Info]' },
  info: { 'zh-TW': '[資訊]', en: '[Info]' },
};

function mapSeverity(severity: string): AlertSeverity {
  if (severity === 'critical' || severity === 'high') return 'critical';
  if (severity === 'medium') return 'warning';
  return 'info';
}

function getSeverityLabel(severity: string, language: MessageLanguage): string {
  return SEVERITY_LABELS[severity]?.[language] ?? SEVERITY_LABELS['info']![language];
}

// ---------------------------------------------------------------------------
// Developer Format
// 開發者格式
// ---------------------------------------------------------------------------

function formatAlertForDeveloper(alert: ThreatAlert, language: MessageLanguage): string {
  const label = getSeverityLabel(alert.severity, language);

  if (language === 'zh-TW') {
    const lines = [
      `${label} ${alert.humanSummary}`,
      '',
      `結論: ${alert.conclusion} (信心 ${Math.round(alert.confidence * 100)}%)`,
      `事件: ${alert.eventDescription}`,
    ];
    if (alert.mitreTechnique) {
      lines.push(`MITRE ATT&CK: ${alert.mitreTechnique}`);
    }
    lines.push(`推理: ${alert.reasoning}`);
    lines.push(`建議: ${alert.recommendedAction}`);
    if (alert.actionsTaken && alert.actionsTaken.length > 0) {
      lines.push(`已執行: ${alert.actionsTaken.join(', ')}`);
    }
    lines.push(`時間: ${alert.timestamp}`);
    return lines.join('\n');
  }

  const lines = [
    `${label} ${alert.humanSummary}`,
    '',
    `Conclusion: ${alert.conclusion} (confidence ${Math.round(alert.confidence * 100)}%)`,
    `Event: ${alert.eventDescription}`,
  ];
  if (alert.mitreTechnique) {
    lines.push(`MITRE ATT&CK: ${alert.mitreTechnique}`);
  }
  lines.push(`Reasoning: ${alert.reasoning}`);
  lines.push(`Recommendation: ${alert.recommendedAction}`);
  if (alert.actionsTaken && alert.actionsTaken.length > 0) {
    lines.push(`Actions taken: ${alert.actionsTaken.join(', ')}`);
  }
  lines.push(`Time: ${alert.timestamp}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Boss Format (no jargon)
// 老闆格式（無技術術語）
// ---------------------------------------------------------------------------

function formatAlertForBoss(alert: ThreatAlert, language: MessageLanguage): string {
  const label = getSeverityLabel(alert.severity, language);

  if (language === 'zh-TW') {
    const lines = [`${label} ${alert.humanSummary}`, '', `${alert.recommendedAction}`];
    if (alert.actionsTaken && alert.actionsTaken.length > 0) {
      lines.push(`我已經: ${alert.actionsTaken.join('、')}`);
    }
    return lines.join('\n');
  }

  const lines = [`${label} ${alert.humanSummary}`, '', `${alert.recommendedAction}`];
  if (alert.actionsTaken && alert.actionsTaken.length > 0) {
    lines.push(`I've already: ${alert.actionsTaken.join(', ')}`);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// IT Admin Format
// IT 管理者格式
// ---------------------------------------------------------------------------

function formatAlertForITAdmin(alert: ThreatAlert, language: MessageLanguage): string {
  const label = getSeverityLabel(alert.severity, language);

  if (language === 'zh-TW') {
    const lines = [
      `${label} ${alert.humanSummary}`,
      '',
      `事件: ${alert.eventDescription}`,
      `結論: ${alert.conclusion} (信心 ${Math.round(alert.confidence * 100)}%)`,
    ];
    if (alert.mitreTechnique) {
      lines.push(`MITRE: ${alert.mitreTechnique}`);
    }
    lines.push(`建議: ${alert.recommendedAction}`);
    if (alert.actionsTaken && alert.actionsTaken.length > 0) {
      lines.push(`已執行動作: ${alert.actionsTaken.join('、')}`);
    }
    lines.push('', '此事件可能需要記錄於資安事件通報。');
    return lines.join('\n');
  }

  const lines = [
    `${label} ${alert.humanSummary}`,
    '',
    `Event: ${alert.eventDescription}`,
    `Conclusion: ${alert.conclusion} (confidence ${Math.round(alert.confidence * 100)}%)`,
  ];
  if (alert.mitreTechnique) {
    lines.push(`MITRE: ${alert.mitreTechnique}`);
  }
  lines.push(`Recommendation: ${alert.recommendedAction}`);
  if (alert.actionsTaken && alert.actionsTaken.length > 0) {
    lines.push(`Actions taken: ${alert.actionsTaken.join(', ')}`);
  }
  lines.push('', 'This incident may need to be included in your security event report.');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Public API - Alert Formatting
// 公開 API - 告警格式化
// ---------------------------------------------------------------------------

/**
 * Format a threat alert message for the given user type
 * 為指定的用戶類型格式化威脅告警訊息
 *
 * @param alert - The threat alert / 威脅告警
 * @param userType - User type for tone adaptation / 用戶類型（語氣適配）
 * @param language - Target language / 目標語言
 * @returns Formatted message / 格式化後的訊息
 */
export function formatAlert(
  alert: ThreatAlert,
  userType: UserType,
  language: MessageLanguage
): FormattedMessage {
  let text: string;
  switch (userType) {
    case 'developer':
      text = formatAlertForDeveloper(alert, language);
      break;
    case 'boss':
      text = formatAlertForBoss(alert, language);
      break;
    case 'it_admin':
      text = formatAlertForITAdmin(alert, language);
      break;
  }

  const quickReplies =
    language === 'zh-TW'
      ? [
          { label: '查看詳情', action: 'details' },
          { label: '忽略', action: 'dismiss' },
          { label: '封鎖來源', action: 'block_source' },
        ]
      : [
          { label: 'View details', action: 'details' },
          { label: 'Dismiss', action: 'dismiss' },
          { label: 'Block source', action: 'block_source' },
        ];

  return {
    text,
    severity: mapSeverity(alert.severity),
    quickReplies,
  };
}

// ---------------------------------------------------------------------------
// Summary Report Formatting
// 摘要報告格式化
// ---------------------------------------------------------------------------

/**
 * Format a summary report (daily / weekly)
 * 格式化摘要報告（日報/週報）
 *
 * @param report - Summary report data / 摘要報告資料
 * @param userType - User type / 用戶類型
 * @param language - Target language / 目標語言
 * @returns Formatted message / 格式化後的訊息
 */
export function formatSummary(
  report: SummaryReport,
  userType: UserType,
  language: MessageLanguage
): FormattedMessage {
  const periodLabel =
    language === 'zh-TW'
      ? report.period === 'daily'
        ? '今日'
        : '本週'
      : report.period === 'daily'
        ? 'Today'
        : 'This Week';

  if (language === 'zh-TW') {
    const lines = [
      `[${periodLabel}] 安全摘要`,
      `${report.startDate} ~ ${report.endDate}`,
      '',
      `阻擋攻擊: ${report.threatsBlocked} 次`,
      `可疑事件: ${report.suspiciousEvents} 件`,
      `總事件數: ${report.totalEvents} 件`,
    ];

    if (report.estimatedDamageAvoided !== undefined) {
      lines.push(`估計避免損失: $${report.estimatedDamageAvoided.toLocaleString()}`);
    }

    if (report.trendComparison) {
      const trend = report.trendComparison;
      const direction = trend.changePercent >= 0 ? '增加' : '減少';
      lines.push(`趨勢: 較上期${direction} ${Math.abs(trend.changePercent)}%`);
    }

    if (report.topAttackSources.length > 0 && userType !== 'boss') {
      lines.push('', '主要攻擊來源:');
      for (const source of report.topAttackSources.slice(0, 3)) {
        const country = source.country ? ` (${source.country})` : '';
        lines.push(`  ${source.ip}${country} - ${source.count} 次`);
      }
    }

    if (report.recommendations && report.recommendations.length > 0) {
      lines.push('', '建議:');
      for (const rec of report.recommendations) {
        lines.push(`  - ${rec}`);
      }
    }

    return { text: lines.join('\n'), severity: 'info' };
  }

  // English
  const lines = [
    `[${periodLabel}] Security Summary`,
    `${report.startDate} ~ ${report.endDate}`,
    '',
    `Attacks blocked: ${report.threatsBlocked}`,
    `Suspicious events: ${report.suspiciousEvents}`,
    `Total events: ${report.totalEvents}`,
  ];

  if (report.estimatedDamageAvoided !== undefined) {
    lines.push(`Estimated damage avoided: $${report.estimatedDamageAvoided.toLocaleString()}`);
  }

  if (report.trendComparison) {
    const trend = report.trendComparison;
    const direction = trend.changePercent >= 0 ? 'increased' : 'decreased';
    lines.push(
      `Trend: ${direction} by ${Math.abs(trend.changePercent)}% compared to previous period`
    );
  }

  if (report.topAttackSources.length > 0 && userType !== 'boss') {
    lines.push('', 'Top attack sources:');
    for (const source of report.topAttackSources.slice(0, 3)) {
      const country = source.country ? ` (${source.country})` : '';
      lines.push(`  ${source.ip}${country} - ${source.count} hits`);
    }
  }

  if (report.recommendations && report.recommendations.length > 0) {
    lines.push('', 'Recommendations:');
    for (const rec of report.recommendations) {
      lines.push(`  - ${rec}`);
    }
  }

  return { text: lines.join('\n'), severity: 'info' };
}

// ---------------------------------------------------------------------------
// Learning Progress Formatting
// 學習期進度格式化
// ---------------------------------------------------------------------------

/**
 * Format a learning progress notification
 * 格式化學習期進度通知
 *
 * @param progress - Learning progress data / 學習期進度資料
 * @param language - Target language / 目標語言
 * @returns Formatted message / 格式化後的訊息
 */
export function formatLearningProgress(
  progress: LearningProgress,
  language: MessageLanguage
): FormattedMessage {
  const percent = Math.round((progress.day / progress.totalDays) * 100);

  if (language === 'zh-TW') {
    const lines = [
      `[學習期進度] 第 ${progress.day} 天 / 共 ${progress.totalDays} 天 (${percent}%)`,
      '',
      `已記錄行為模式: ${progress.patternsRecorded} 個`,
      `已分析事件: ${progress.eventsAnalyzed} 件`,
    ];
    if (progress.notableFindings > 0) {
      lines.push(`值得關注的發現: ${progress.notableFindings} 項`);
    }
    if (progress.day >= progress.totalDays) {
      lines.push('', '學習期已完成! 系統已切換為保護模式。');
    } else {
      lines.push('', `學習期間只會在日報中彙報，不會推送即時告警（已知攻擊模式除外）。`);
    }
    return { text: lines.join('\n'), severity: 'info' };
  }

  const lines = [
    `[Learning Progress] Day ${progress.day} / ${progress.totalDays} (${percent}%)`,
    '',
    `Behavior patterns recorded: ${progress.patternsRecorded}`,
    `Events analyzed: ${progress.eventsAnalyzed}`,
  ];
  if (progress.notableFindings > 0) {
    lines.push(`Notable findings: ${progress.notableFindings}`);
  }
  if (progress.day >= progress.totalDays) {
    lines.push('', 'Learning period complete! System has switched to protection mode.');
  } else {
    lines.push(
      '',
      'During the learning period, alerts are included in daily summaries only (except known attack patterns).'
    );
  }
  return { text: lines.join('\n'), severity: 'info' };
}

// ---------------------------------------------------------------------------
// Confirmation Request Formatting
// 確認請求格式化
// ---------------------------------------------------------------------------

/**
 * Format a confirmation request for user approval
 * 格式化用戶確認請求
 *
 * @param request - Confirmation request / 確認請求
 * @param language - Target language / 目標語言
 * @returns Formatted message with quick replies / 附帶快速回覆的格式化訊息
 */
export function formatConfirmation(
  request: ConfirmationRequest,
  language: MessageLanguage
): FormattedMessage {
  if (language === 'zh-TW') {
    const lines = [
      `[需要您的確認]`,
      '',
      request.humanSummary,
      '',
      `建議動作: ${request.proposedAction}`,
      `信心度: ${Math.round(request.confidence * 100)}%`,
      '',
      `請在 ${new Date(request.expiresAt).toLocaleString('zh-TW')} 之前回覆。`,
      `若未回覆，系統將不會執行此動作。`,
    ];
    return {
      text: lines.join('\n'),
      severity: request.conclusion === 'malicious' ? 'critical' : 'warning',
      quickReplies: [
        { label: '確認執行', action: `confirm:${request.verdictId}` },
        { label: '取消', action: `reject:${request.verdictId}` },
        { label: '查看詳情', action: `details:${request.verdictId}` },
      ],
    };
  }

  const lines = [
    `[Your Confirmation Needed]`,
    '',
    request.humanSummary,
    '',
    `Proposed action: ${request.proposedAction}`,
    `Confidence: ${Math.round(request.confidence * 100)}%`,
    '',
    `Please respond before ${new Date(request.expiresAt).toLocaleString('en-US')}.`,
    `If no response, the action will NOT be taken.`,
  ];
  return {
    text: lines.join('\n'),
    severity: request.conclusion === 'malicious' ? 'critical' : 'warning',
    quickReplies: [
      { label: 'Confirm', action: `confirm:${request.verdictId}` },
      { label: 'Cancel', action: `reject:${request.verdictId}` },
      { label: 'View details', action: `details:${request.verdictId}` },
    ],
  };
}

// ---------------------------------------------------------------------------
// Peaceful Report (All-Clear)
// 平安報告
// ---------------------------------------------------------------------------

/**
 * Format a peaceful "all clear" report
 * 格式化平安報告（無事報平安）
 *
 * @param language - Target language / 目標語言
 * @returns Formatted message / 格式化後的訊息
 */
export function formatPeacefulReport(language: MessageLanguage): FormattedMessage {
  if (language === 'zh-TW') {
    return {
      text: [
        '[平安] 一切正常',
        '',
        '目前沒有任何安全威脅或異常事件。',
        '您的系統運行正常，我會繼續守護。',
      ].join('\n'),
      severity: 'info',
    };
  }

  return {
    text: [
      '[All Clear] Everything is normal',
      '',
      'No security threats or anomalies detected.',
      'Your systems are running normally. I will continue monitoring.',
    ].join('\n'),
    severity: 'info',
  };
}
