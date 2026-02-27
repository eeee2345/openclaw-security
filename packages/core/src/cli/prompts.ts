/**
 * Interactive Prompt System - Zero-dependency terminal prompts
 * 互動式提示系統 - 零依賴終端機提示工具
 *
 * Provides promptSelect, promptText, and promptConfirm for building
 * interactive CLI wizards. Uses raw mode stdin for keypresses and
 * readline for text input. Brand-styled with Panguard AI colors.
 *
 * @module @panguard-ai/core/cli/prompts
 */

import * as readline from 'node:readline';
import { c, symbols, stripAnsi } from './index.js';

type Lang = 'en' | 'zh-TW';

// ============================================================
// CJK Width Calculation (moved from menu.ts for sharing)
// ============================================================

/**
 * Calculate visible width of a string, accounting for ANSI codes and CJK double-width chars.
 */
export function visLen(s: string): number {
  const plain = stripAnsi(s);
  let len = 0;
  for (const ch of plain) {
    const code = ch.codePointAt(0) ?? 0;
    if (
      (code >= 0x2E80 && code <= 0x9FFF) ||
      (code >= 0xF900 && code <= 0xFAFF) ||
      (code >= 0xFE30 && code <= 0xFE4F) ||
      (code >= 0xFF01 && code <= 0xFF60) ||
      (code >= 0xFFE0 && code <= 0xFFE6) ||
      (code >= 0x20000 && code <= 0x2FA1F) ||
      (code >= 0x3000 && code <= 0x303F) ||
      (code >= 0x3040 && code <= 0x30FF)
    ) {
      len += 2;
    } else {
      len += 1;
    }
  }
  return len;
}

// ============================================================
// Shared Types
// ============================================================

export interface SelectOption<T = string> {
  readonly value: T;
  readonly label: Record<Lang, string>;
  readonly description?: Record<Lang, string>;
}

export interface SelectConfig<T = string> {
  readonly title: Record<Lang, string>;
  readonly description?: Record<Lang, string>;
  readonly options: readonly SelectOption<T>[];
  readonly lang: Lang;
  readonly allowBack?: boolean;
}

export interface TextConfig {
  readonly title: Record<Lang, string>;
  readonly description?: Record<Lang, string>;
  readonly placeholder?: string;
  readonly defaultValue?: string;
  readonly validate?: (value: string) => string | null;
  readonly sensitive?: boolean;
  readonly lang: Lang;
  readonly allowBack?: boolean;
}

export interface ConfirmConfig {
  readonly message: Record<Lang, string>;
  readonly defaultValue?: boolean;
  readonly lang: Lang;
}

// ============================================================
// Utility: Wait for a single keypress in raw mode
// ============================================================

function waitForKey(): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    if (stdin.isTTY) {
      stdin.setRawMode(true);
    }
    stdin.resume();
    stdin.setEncoding('utf-8');

    const onData = (data: string) => {
      stdin.removeListener('data', onData);
      if (stdin.isTTY) {
        stdin.setRawMode(wasRaw ?? false);
      }
      stdin.pause();

      if (data === '\x03') { resolve('ctrl-c'); return; }
      if (data === '\r' || data === '\n') { resolve('enter'); return; }
      if (data === '\x1b' && data.length === 1) { resolve('escape'); return; }
      if (data === '\x7f' || data === '\b') { resolve('backspace'); return; }

      resolve(data.trim().toLowerCase());
    };

    stdin.on('data', onData);
  });
}

// ============================================================
// promptSelect — Single-key selection from numbered options
// ============================================================

/**
 * Display numbered options and wait for the user to select one.
 * Returns the selected option's value, or null if the user pressed [b] for back.
 */
export async function promptSelect<T = string>(config: SelectConfig<T>): Promise<T | null> {
  const { title, description, options, lang, allowBack = true } = config;
  const isTTY = process.stdin.isTTY;

  // Non-TTY fallback: return first option
  if (!isTTY) {
    return options[0]?.value ?? null;
  }

  // Render title
  const titleText = title[lang];
  console.log('');
  console.log(`  ${c.heading(titleText)}`);
  if (description) {
    console.log(`  ${c.dim(description[lang])}`);
  }
  console.log('');

  // Render options
  for (let i = 0; i < options.length; i++) {
    const opt = options[i]!;
    const num = String(i + 1);
    const label = opt.label[lang];
    const desc = opt.description?.[lang];
    console.log(`    ${c.sage(`[${num}]`)}  ${c.bold(label)}`);
    if (desc) {
      console.log(`          ${c.dim(desc)}`);
    }
  }

  // Footer
  console.log('');
  const footerParts: string[] = [];
  if (allowBack) {
    footerParts.push(`${c.dim('[b]')} ${lang === 'zh-TW' ? '\u8FD4\u56DE' : 'Back'}`);
  }
  footerParts.push(`${c.dim('[q]')} ${lang === 'zh-TW' ? '\u9000\u51FA' : 'Quit'}`);
  console.log(`  ${footerParts.join('   ')}`);
  console.log('');

  process.stdout.write(`  ${c.sage('panguard')} ${c.dim('\u203A')} `);

  // Wait for valid input
  while (true) {
    const key = await waitForKey();

    if (key === 'q' || key === 'ctrl-c') {
      console.log('');
      process.exit(0);
    }
    if (key === 'b' && allowBack) {
      console.log('');
      return null;
    }

    const idx = parseInt(key, 10) - 1;
    if (idx >= 0 && idx < options.length) {
      const selected = options[idx]!;
      // Echo the selection
      process.stdout.write(`${selected.label[lang]}\n`);
      return selected.value;
    }
  }
}

// ============================================================
// promptText — Readline text input with validation
// ============================================================

/**
 * Prompt the user for text input.
 * Returns the entered text, or null if the user cancelled.
 */
export async function promptText(config: TextConfig): Promise<string | null> {
  const { title, description, placeholder, defaultValue, validate, sensitive, lang, allowBack = true } = config;
  const isTTY = process.stdin.isTTY;

  // Non-TTY fallback: return default
  if (!isTTY) {
    return defaultValue ?? '';
  }

  // Render title
  console.log('');
  console.log(`  ${c.heading(title[lang])}`);
  if (description) {
    console.log(`  ${c.dim(description[lang])}`);
  }
  if (defaultValue) {
    console.log(`  ${c.dim(`(${lang === 'zh-TW' ? '\u9810\u8A2D' : 'default'}: ${defaultValue})`)}`);
  }
  if (placeholder) {
    console.log(`  ${c.dim(placeholder)}`);
  }

  if (allowBack) {
    console.log(`  ${c.dim(`[Esc] ${lang === 'zh-TW' ? '\u8FD4\u56DE' : 'Back'}`)}`);
  }
  console.log('');

  // Sensitive input: handle manually with raw mode
  if (sensitive) {
    return promptSensitiveText(config);
  }

  // Normal text input using readline
  while (true) {
    const result = await readLine(`  ${c.sage('panguard')} ${c.dim('\u203A')} `);

    if (result === null) {
      // User pressed Ctrl+C or escaped
      return allowBack ? null : '';
    }

    const value = result.trim() || defaultValue || '';

    if (!value && validate) {
      const err = validate(value);
      if (err) {
        console.log(`  ${symbols.fail} ${c.critical(err)}`);
        continue;
      }
    }

    if (validate && value) {
      const err = validate(value);
      if (err) {
        console.log(`  ${symbols.fail} ${c.critical(err)}`);
        continue;
      }
    }

    return value;
  }
}

function readLine(prompt: string): Promise<string | null> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });

    rl.on('close', () => {
      resolve(null);
    });
  });
}

async function promptSensitiveText(config: TextConfig): Promise<string | null> {
  const { validate, defaultValue, allowBack = true } = config;

  process.stdout.write(`  ${c.sage('panguard')} ${c.dim('\u203A')} `);

  let buffer = '';
  const stdin = process.stdin;
  const wasRaw = stdin.isRaw;

  if (stdin.isTTY) {
    stdin.setRawMode(true);
  }
  stdin.resume();
  stdin.setEncoding('utf-8');

  return new Promise((resolve) => {
    const onData = (data: string) => {
      // Ctrl+C
      if (data === '\x03') {
        stdin.removeListener('data', onData);
        if (stdin.isTTY) stdin.setRawMode(wasRaw ?? false);
        stdin.pause();
        console.log('');
        process.exit(0);
      }

      // Escape
      if (data === '\x1b') {
        stdin.removeListener('data', onData);
        if (stdin.isTTY) stdin.setRawMode(wasRaw ?? false);
        stdin.pause();
        console.log('');
        if (allowBack) {
          resolve(null);
        } else {
          resolve(defaultValue ?? '');
        }
        return;
      }

      // Enter
      if (data === '\r' || data === '\n') {
        stdin.removeListener('data', onData);
        if (stdin.isTTY) stdin.setRawMode(wasRaw ?? false);
        stdin.pause();
        console.log('');

        const value = buffer.trim() || defaultValue || '';
        if (validate) {
          const err = validate(value);
          if (err) {
            console.log(`  ${symbols.fail} ${c.critical(err)}`);
            buffer = '';
            // Re-prompt
            promptSensitiveText(config).then(resolve);
            return;
          }
        }
        resolve(value);
        return;
      }

      // Backspace
      if (data === '\x7f' || data === '\b') {
        if (buffer.length > 0) {
          buffer = buffer.slice(0, -1);
          process.stdout.write('\b \b');
        }
        return;
      }

      // Normal character
      buffer += data;
      process.stdout.write('*');
    };

    stdin.on('data', onData);
  });
}

// ============================================================
// promptConfirm — Y/N confirmation
// ============================================================

/**
 * Ask a yes/no question. Returns true for yes, false for no.
 */
export async function promptConfirm(config: ConfirmConfig): Promise<boolean> {
  const { message, defaultValue = true, lang } = config;
  const isTTY = process.stdin.isTTY;

  // Non-TTY fallback: return default
  if (!isTTY) {
    return defaultValue;
  }

  const hint = defaultValue ? 'Y/n' : 'y/N';
  console.log('');
  process.stdout.write(`  ${c.sage('?')} ${message[lang]} ${c.dim(`[${hint}]`)} `);

  const key = await waitForKey();

  if (key === 'y') {
    console.log(c.safe('Yes'));
    return true;
  }
  if (key === 'n') {
    console.log(c.dim('No'));
    return false;
  }
  if (key === 'enter') {
    console.log(defaultValue ? c.safe('Yes') : c.dim('No'));
    return defaultValue;
  }
  if (key === 'ctrl-c') {
    console.log('');
    process.exit(0);
  }

  // Unknown key: treat as default
  console.log(defaultValue ? c.safe('Yes') : c.dim('No'));
  return defaultValue;
}
