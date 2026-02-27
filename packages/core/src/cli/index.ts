/**
 * CLI Rendering Utilities - On-brand terminal output for Panguard AI
 * CLI 渲染工具 - Panguard AI 品牌終端輸出
 *
 * Zero external dependencies. Uses 24-bit ANSI colors matching brand tokens.
 * Brand colors: Sage Green #8B9A8E, Cream #F5F1E8, Charcoal #1A1614
 * Status: Safe #2ED573, Caution #FBBF24, Alert #FF6B35, Critical #EF4444
 *
 * @module @panguard-ai/core/cli
 */

// ============================================================
// Color System — Brand Tokens
// ============================================================

const isColorSupported = (): boolean => {
  if (process.env['NO_COLOR'] !== undefined) return false;
  if (process.env['FORCE_COLOR'] !== undefined) return true;
  return process.stdout.isTTY === true;
};

const ESC = '\x1b[';
const RESET = `${ESC}0m`;

/** 24-bit RGB color */
function rgb(r: number, g: number, b: number): string {
  return `${ESC}38;2;${r};${g};${b}m`;
}

/** 24-bit RGB background */
function bgRgb(r: number, g: number, b: number): string {
  return `${ESC}48;2;${r};${g};${b}m`;
}

// Brand palette
const palette = {
  sage: rgb(139, 154, 142), // #8B9A8E — primary brand
  charcoal: rgb(26, 22, 20), // #1A1614 — backgrounds
  cream: rgb(245, 241, 232), // #F5F1E8 — primary text
  safe: rgb(46, 213, 115), // #2ED573 — safe/protected
  caution: rgb(251, 191, 36), // #FBBF24 — warning
  alert: rgb(255, 107, 53), // #FF6B35 — alert
  critical: rgb(239, 68, 68), // #EF4444 — critical/danger
  dim: rgb(120, 120, 120), // muted text
  white: rgb(255, 255, 255), // bright white
  bgSafe: bgRgb(46, 213, 115),
  bgCaution: bgRgb(251, 191, 36),
  bgAlert: bgRgb(255, 107, 53),
  bgCritical: bgRgb(239, 68, 68),
};

const BOLD = `${ESC}1m`;
const DIM = `${ESC}2m`;
const ITALIC = `${ESC}3m`;
const UNDERLINE = `${ESC}4m`;

type StyleFn = (text: string) => string;

function wrap(code: string): StyleFn {
  return (text: string) => (isColorSupported() ? `${code}${text}${RESET}` : text);
}

/** Brand-matched ANSI color/style helpers */
export const c = {
  // Brand colors
  sage: wrap(palette.sage),
  cream: wrap(palette.cream),
  safe: wrap(palette.safe),
  caution: wrap(palette.caution),
  alert: wrap(palette.alert),
  critical: wrap(palette.critical),
  dim: wrap(palette.dim),

  // Basic styles
  bold: wrap(BOLD),
  italic: wrap(ITALIC),
  underline: wrap(UNDERLINE),
  muted: wrap(DIM),

  // Semantic styles
  brand: (text: string) => wrap(BOLD + palette.sage)(text),
  heading: (text: string) => wrap(BOLD + palette.cream)(text),
  success: (text: string) => wrap(BOLD + palette.safe)(text),
  error: (text: string) => wrap(BOLD + palette.critical)(text),
  warn: (text: string) => wrap(BOLD + palette.caution)(text),
  info: (text: string) => wrap(BOLD + palette.sage)(text),

  // Fallback for standard terminal colors
  red: wrap(`${ESC}31m`),
  green: wrap(`${ESC}32m`),
  yellow: wrap(`${ESC}33m`),
  blue: wrap(`${ESC}34m`),
  magenta: wrap(`${ESC}35m`),
  cyan: wrap(`${ESC}36m`),
  white: wrap(`${ESC}37m`),
  gray: wrap(`${ESC}90m`),

  brightRed: wrap(palette.critical),
  brightGreen: wrap(palette.safe),
  brightYellow: wrap(palette.caution),
  brightBlue: wrap(`${ESC}94m`),
  brightMagenta: wrap(`${ESC}95m`),
  brightCyan: wrap(palette.sage),
  bgRed: wrap(palette.bgCritical),
  bgGreen: wrap(palette.bgSafe),
  bgYellow: wrap(palette.bgCaution),
  bgBlue: wrap(`${ESC}44m`),
};

// ============================================================
// Status Indicators — matching brand mockups
// ============================================================

/** Brand status indicators (matching CLI mockup v1) */
export const symbols = {
  pass: isColorSupported() ? `${palette.safe}${BOLD}[✓]${RESET}` : '[OK]',
  fail: isColorSupported() ? `${palette.critical}${BOLD}[✗]${RESET}` : '[!!]',
  warn: isColorSupported() ? `${palette.caution}${BOLD}[!]${RESET}` : '[!]',
  info: isColorSupported() ? `${palette.sage}${BOLD}[i]${RESET}` : '[i]',
  arrow: isColorSupported() ? `${palette.sage}[→]${RESET}` : '[->]',
  scan: isColorSupported() ? `${palette.sage}${BOLD}[⚡]${RESET}` : '[~]',
  shield: isColorSupported() ? `${palette.sage}${BOLD}[▣]${RESET}` : '[#]',
  bullet: isColorSupported() ? `${palette.dim}  ·${RESET}` : '  -',
  dot: isColorSupported() ? `${palette.dim}  ·${RESET}` : '  .',
};

// ============================================================
// Severity & Score Colors
// ============================================================

/** Map severity to brand status colors */
export function colorSeverity(severity: string): string {
  const s = severity.toLowerCase();
  switch (s) {
    case 'critical':
      return wrap(BOLD + palette.bgCritical + rgb(255, 255, 255))(` ${severity.toUpperCase()} `);
    case 'high':
      return c.critical(severity.toUpperCase());
    case 'medium':
      return c.caution(severity.toUpperCase());
    case 'low':
      return c.sage(severity.toUpperCase());
    case 'info':
      return c.dim(severity.toUpperCase());
    default:
      return severity;
  }
}

/** Map score to brand color */
export function colorScore(score: number): string {
  const text = String(score);
  if (score >= 80) return c.safe(text);
  if (score >= 60) return c.caution(text);
  if (score >= 40) return c.alert(text);
  return c.critical(text);
}

/** Map grade to brand color */
export function colorGrade(grade: string): string {
  switch (grade) {
    case 'A':
      return c.success(grade);
    case 'B':
      return c.safe(grade);
    case 'C':
      return c.caution(grade);
    case 'D':
      return c.alert(grade);
    case 'F':
      return c.critical(grade);
    default:
      return grade;
  }
}

// ============================================================
// Banner & Header — Brand Logo
// ============================================================

/**
 * Panguard AI CLI banner — matching brand mockup v1
 * Logo format: PANGUARD [shield] AI (per brand spec)
 */
export function banner(): string {
  if (!isColorSupported()) {
    return ['', '  PANGUARD [#] AI  v0.5.0', '  AI-Powered Security Platform', ''].join('\n');
  }

  const shieldArt = [
    `${palette.sage}       _____`,
    `      /     \\`,
    `     /  ___  \\`,
    `    |  /   \\  |`,
    `    | | ${palette.safe}${BOLD}[${RESET}${palette.safe}${BOLD}✓${RESET}${palette.sage}| | |`,
    `    |  \\___/  |`,
    `     \\       /`,
    `      \\_____/${RESET}`,
  ];

  const titleLines = [
    '',
    `  ${BOLD}${palette.cream}PANGUARD ${palette.sage}[▣]${palette.cream} AI${RESET}  ${palette.dim}v0.5.0${RESET}`,
    `  ${palette.dim}AI-Powered Security Platform${RESET}`,
    '',
  ];

  // Combine shield art (right) with title (left)
  const combined: string[] = [];
  const maxLines = Math.max(shieldArt.length, titleLines.length);
  for (let i = 0; i < maxLines; i++) {
    const title = titleLines[i] ?? '';
    const shield = shieldArt[i] ?? '';
    if (i < titleLines.length && i < shieldArt.length) {
      const titleWidth = stripAnsi(title).length;
      const pad = Math.max(0, 35 - titleWidth);
      combined.push(title + ' '.repeat(pad) + shield);
    } else if (i < titleLines.length) {
      combined.push(title);
    } else {
      combined.push(' '.repeat(35) + shield);
    }
  }

  return combined.join('\n');
}

/** Compact header line */
export function header(subtitle: string = ''): string {
  const lines: string[] = [];
  if (isColorSupported()) {
    lines.push(`  ${BOLD}${palette.cream}PANGUARD ${palette.sage}[▣]${palette.cream} AI${RESET}`);
  } else {
    lines.push('  PANGUARD [#] AI');
  }
  if (subtitle) {
    lines.push(`  ${c.dim(subtitle)}`);
  }
  lines.push('');
  return lines.join('\n');
}

// ============================================================
// Divider — Double-line style (matching mockup)
// ============================================================

/** Section divider with optional centered label */
export function divider(label?: string): string {
  const width = Math.min(process.stdout.columns ?? 60, 70);
  if (label) {
    const remaining = width - stripAnsi(label).length - 4;
    const left = Math.max(1, Math.floor(remaining / 2));
    const right = Math.max(1, remaining - left);
    return c.dim('='.repeat(left) + '[ ') + c.bold(label) + c.dim(' ]' + '='.repeat(right));
  }
  return c.dim('='.repeat(width));
}

// ============================================================
// Spinner — matching brand loading animation style
// ============================================================

const SPINNER_FRAMES = isColorSupported()
  ? ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
  : ['|', '/', '-', '\\'];

export class Spinner {
  private frameIndex = 0;
  private timer: ReturnType<typeof setInterval> | null = null;
  private message: string;

  constructor(message: string) {
    this.message = message;
  }

  start(): this {
    if (!isColorSupported()) {
      process.stdout.write(`  ${this.message}...\n`);
      return this;
    }
    process.stdout.write('\x1b[?25l'); // Hide cursor
    this.timer = setInterval(() => {
      const frame = SPINNER_FRAMES[this.frameIndex % SPINNER_FRAMES.length];
      process.stdout.write(`\r  ${palette.sage}${frame}${RESET} ${this.message}`);
      this.frameIndex++;
    }, 80);
    this.timer.unref();
    return this;
  }

  update(message: string): void {
    this.message = message;
    if (!isColorSupported()) {
      process.stdout.write(`  ${message}\n`);
    }
  }

  succeed(message?: string): void {
    this.stop();
    const text = message ?? this.message;
    process.stdout.write(`\r  ${symbols.pass} ${text}\n`);
  }

  fail(message?: string): void {
    this.stop();
    const text = message ?? this.message;
    process.stdout.write(`\r  ${symbols.fail} ${text}\n`);
  }

  warn(message?: string): void {
    this.stop();
    const text = message ?? this.message;
    process.stdout.write(`\r  ${symbols.warn} ${text}\n`);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (isColorSupported()) {
      process.stdout.write('\r\x1b[K');
      process.stdout.write('\x1b[?25h'); // Show cursor
    }
  }
}

/** Create and start a spinner */
export function spinner(message: string): Spinner {
  return new Spinner(message).start();
}

// ============================================================
// Progress Bar — matching mockup: [=========================>          ] 75%
// ============================================================

export interface ProgressBarOptions {
  total: number;
  width?: number;
  label?: string;
}

export class ProgressBar {
  private current = 0;
  private total: number;
  private width: number;
  private label: string;
  private startTime: number;

  constructor(options: ProgressBarOptions) {
    this.total = options.total;
    this.width = options.width ?? 40;
    this.label = options.label ?? 'Progress';
    this.startTime = Date.now();
  }

  update(current: number, label?: string): void {
    this.current = Math.min(current, this.total);
    if (label !== undefined) this.label = label;
    this.render();
  }

  increment(label?: string): void {
    this.update(this.current + 1, label);
  }

  complete(label?: string): void {
    this.update(this.total, label);
    process.stdout.write('\n');
  }

  private render(): void {
    const ratio = this.total > 0 ? this.current / this.total : 0;
    const percent = Math.round(ratio * 100);
    const filled = Math.round(this.width * ratio);
    const empty = this.width - filled;

    // Mockup style: [=========================>          ] 75%
    const barFill = filled > 0 ? c.safe('='.repeat(Math.max(0, filled - 1)) + '>') : '';
    const barEmpty = c.dim(' '.repeat(empty));
    const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);

    const percentStr = percent === 100 ? c.success(`${percent}%`) : c.cream(`${percent}%`);

    const line = `  ${this.label}: ${c.dim('[')}${barFill}${barEmpty}${c.dim(']')}  ${percentStr}  ${c.dim(`${elapsed}s`)}`;
    process.stdout.write(`\r\x1b[K${line}`);
  }
}

/** Create a progress bar */
export function progressBar(options: ProgressBarOptions): ProgressBar {
  return new ProgressBar(options);
}

// ============================================================
// Table — clean bordered style
// ============================================================

export interface TableColumn {
  header: string;
  key: string;
  width?: number;
  align?: 'left' | 'right' | 'center';
  color?: (value: string) => string;
}

/** Render a formatted table */
export function table(columns: TableColumn[], rows: Record<string, string>[]): string {
  const widths = columns.map((col) => {
    const headerLen = stripAnsi(col.header).length;
    const maxDataLen = rows.reduce((max, row) => {
      const val = row[col.key] ?? '';
      return Math.max(max, stripAnsi(val).length);
    }, 0);
    return col.width ?? Math.max(headerLen, maxDataLen) + 2;
  });

  const lines: string[] = [];

  // Top border
  const hLine = (ch: string) => c.dim('  +' + widths.map((w) => ch.repeat(w + 2)).join('+') + '+');

  lines.push(hLine('-'));

  // Header
  const headerCells = columns.map((col, i) => {
    return ' ' + pad(c.brand(col.header), widths[i] ?? 10, 'left') + ' ';
  });
  lines.push(c.dim('  |') + headerCells.join(c.dim('|')) + c.dim('|'));

  // Header separator (double line)
  lines.push(c.dim('  +' + widths.map((w) => '='.repeat(w + 2)).join('+') + '+'));

  // Rows
  for (const row of rows) {
    const cells = columns.map((col, i) => {
      let val = row[col.key] ?? '';
      if (col.color) val = col.color(val);
      return ' ' + pad(val, widths[i] ?? 10, col.align ?? 'left') + ' ';
    });
    lines.push(c.dim('  |') + cells.join(c.dim('|')) + c.dim('|'));
  }

  // Bottom border
  lines.push(hLine('-'));

  return lines.join('\n');
}

// ============================================================
// Box — bordered panel
// ============================================================

export interface BoxOptions {
  title?: string;
  padding?: number;
  borderColor?: (text: string) => string;
  width?: number;
}

/** Draw a bordered box around text */
export function box(content: string, options: BoxOptions = {}): string {
  const { title, padding = 1, borderColor = c.sage, width: forceWidth } = options;
  const contentLines = content.split('\n');

  const maxContentWidth = Math.max(
    ...contentLines.map((l) => stripAnsi(l).length),
    title ? stripAnsi(title).length + 4 : 0
  );
  const innerWidth = forceWidth ?? maxContentWidth + padding * 2;

  const lines: string[] = [];

  // Top border
  if (title) {
    const titleStr = ` ${title} `;
    const remaining = innerWidth - stripAnsi(titleStr).length;
    const left = Math.max(1, Math.floor(remaining / 2));
    const right = Math.max(1, remaining - left);
    lines.push('  ' + borderColor('+' + '-'.repeat(left) + titleStr + '-'.repeat(right) + '+'));
  } else {
    lines.push('  ' + borderColor('+' + '-'.repeat(innerWidth) + '+'));
  }

  // Padding top
  for (let i = 0; i < Math.max(0, padding - 1); i++) {
    lines.push('  ' + borderColor('|') + ' '.repeat(innerWidth) + borderColor('|'));
  }

  // Content
  for (const line of contentLines) {
    const stripped = stripAnsi(line);
    const padRight = innerWidth - padding - stripped.length;
    lines.push(
      '  ' +
        borderColor('|') +
        ' '.repeat(padding) +
        line +
        ' '.repeat(Math.max(0, padRight)) +
        borderColor('|')
    );
  }

  // Padding bottom
  for (let i = 0; i < Math.max(0, padding - 1); i++) {
    lines.push('  ' + borderColor('|') + ' '.repeat(innerWidth) + borderColor('|'));
  }

  // Bottom border
  lines.push('  ' + borderColor('+' + '-'.repeat(innerWidth) + '+'));

  return lines.join('\n');
}

// ============================================================
// Score Display — matching brand status panel style
// ============================================================

/** Render security score display (matching mockup status panel) */
export function scoreDisplay(score: number, grade: string, trend?: string): string {
  const trendIcon =
    trend === 'improving'
      ? c.safe(' [+] Improving')
      : trend === 'declining'
        ? c.critical(' [-] Declining')
        : c.dim(' [=] Stable');

  const scoreStr = colorScore(score);
  const gradeStr = colorGrade(grade);

  // Score bar matching mockup: [=========================>          ]
  const barWidth = 30;
  const filled = Math.round((score / 100) * barWidth);
  const empty = barWidth - filled;
  const barColor =
    score >= 80 ? c.safe : score >= 60 ? c.caution : score >= 40 ? c.alert : c.critical;
  const bar =
    c.dim('[') +
    barColor('='.repeat(Math.max(0, filled - 1)) + (filled > 0 ? '>' : '')) +
    c.dim(' '.repeat(empty) + ']');

  return [
    '',
    `  ${c.heading('Security Score:')} ${c.bold(scoreStr)}${c.dim('/100')}  ${c.heading('Grade:')} ${gradeStr}${trendIcon}`,
    `  ${bar}`,
    '',
  ].join('\n');
}

// ============================================================
// Status Panel — matching mockup "PANGUARD AI Security Status"
// ============================================================

export interface StatusItem {
  label: string;
  value: string;
  status?: 'safe' | 'caution' | 'alert' | 'critical';
}

/** Render a status panel like the mockup */
export function statusPanel(title: string, items: StatusItem[]): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(divider(title));
  lines.push('');

  for (const item of items) {
    const dot =
      item.status === 'safe'
        ? c.safe('●')
        : item.status === 'caution'
          ? c.caution('●')
          : item.status === 'alert'
            ? c.alert('●')
            : item.status === 'critical'
              ? c.critical('●')
              : c.dim('●');

    lines.push(`  ${dot} ${c.bold(item.label + ':')} ${item.value}`);
  }

  lines.push('');
  return lines.join('\n');
}

// ============================================================
// Utility Helpers
// ============================================================

/** Strip ANSI escape codes from a string */
export function stripAnsi(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;]*m/g, '');
}

/** Pad a string (accounting for ANSI codes) */
function pad(text: string, width: number, align: 'left' | 'right' | 'center'): string {
  const visibleLen = stripAnsi(text).length;
  const needed = Math.max(0, width - visibleLen);

  if (align === 'right') return ' '.repeat(needed) + text;
  if (align === 'center') {
    const left = Math.floor(needed / 2);
    const right = needed - left;
    return ' '.repeat(left) + text + ' '.repeat(right);
  }
  return text + ' '.repeat(needed);
}

/** Format milliseconds as human-readable duration */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60000);
  const secs = Math.round((ms % 60000) / 1000);
  return `${mins}m ${secs}s`;
}

/** Format a timestamp as relative time */
export function timeAgo(date: Date | string): string {
  const now = Date.now();
  const then = typeof date === 'string' ? new Date(date).getTime() : date.getTime();
  const diff = now - then;

  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

// ============================================================
// Re-exports from prompt and wizard modules
// ============================================================

export { visLen, promptSelect, promptText, promptConfirm } from './prompts.js';
export type { SelectOption, SelectConfig, TextConfig, ConfirmConfig } from './prompts.js';
export { WizardEngine } from './wizard.js';
export type { WizardStep, WizardAnswers } from './wizard.js';
