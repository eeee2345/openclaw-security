/**
 * Panguard CLI Menu System
 *
 * Number-key instant select + text prompt input.
 * Sub-menus use compact numbered selection.
 *
 * @module @panguard-ai/panguard/cli/menu
 */

import { c } from '@panguard-ai/core';
import type { Tier } from './credentials.js';

export type Lang = 'en' | 'zh-TW';

export interface MenuItem {
  key: string;
  label: string;
  description?: string;
  tier?: Tier | string;
  separator?: boolean;
}

// ── Main Input Types ────────────────────────────────────────────────

export type MainInputResult =
  | { type: 'number'; index: number }
  | { type: 'quit' }
  | { type: 'help' }
  | { type: 'lang_toggle' }
  | { type: 'command'; text: string };

// ── ANSI helpers ────────────────────────────────────────────────────

function showCursor(): void {
  process.stdout.write('\x1b[?25h');
}

// ── Key input ───────────────────────────────────────────────────────

/**
 * Wait for a single keypress. Handles arrow keys, enter, and special keys.
 */
export function waitForKey(): Promise<string> {
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

      if (data === '\x03') {
        resolve('ctrl-c');
        return;
      }
      if (data === '\r' || data === '\n') {
        resolve('enter');
        return;
      }
      if (data === '\x1b' && data.length === 1) {
        resolve('escape');
        return;
      }
      if (data === '\x1b[A') {
        resolve('up');
        return;
      }
      if (data === '\x1b[B') {
        resolve('down');
        return;
      }
      if (data === '\x1b[C') {
        resolve('right');
        return;
      }
      if (data === '\x1b[D') {
        resolve('left');
        return;
      }

      resolve(data.trim().toLowerCase());
    };

    stdin.on('data', onData);
  });
}

// ── Main menu input ─────────────────────────────────────────────────

/**
 * Wait for main menu input.
 *
 * In raw mode:
 * - '0'-'7' triggers corresponding menu item instantly (no Enter)
 * - 'q' quits
 * - 'h' shows help
 * - 'b' toggles language
 * - Other printable chars enter command mode: user types text + Enter
 */
export function waitForMainInput(): Promise<MainInputResult> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    if (stdin.isTTY) {
      stdin.setRawMode(true);
    }
    stdin.resume();
    stdin.setEncoding('utf-8');

    let buffer = '';
    let inCommandMode = false;

    function cleanup(): void {
      stdin.removeListener('data', onData);
      if (stdin.isTTY) {
        stdin.setRawMode(wasRaw ?? false);
      }
      stdin.pause();
    }

    function onData(data: string): void {
      // Ctrl+C always quits
      if (data === '\x03') {
        cleanup();
        resolve({ type: 'quit' });
        return;
      }

      if (!inCommandMode) {
        const ch = data[0];
        if (!ch) return;

        // Number keys 0-7 — instant trigger
        if (ch >= '0' && ch <= '7') {
          cleanup();
          process.stdout.write(ch + '\n');
          resolve({ type: 'number', index: parseInt(ch, 10) });
          return;
        }

        // Quit
        if (ch === 'q') {
          cleanup();
          resolve({ type: 'quit' });
          return;
        }

        // Help
        if (ch === 'h') {
          cleanup();
          resolve({ type: 'help' });
          return;
        }

        // Language toggle
        if (ch === 'b') {
          cleanup();
          resolve({ type: 'lang_toggle' });
          return;
        }

        // Enter with no input — ignore
        if (data === '\r' || data === '\n') return;

        // Any other printable char — enter command mode
        if (ch.charCodeAt(0) >= 32) {
          inCommandMode = true;
          buffer = ch;
          process.stdout.write(ch);
        }
      } else {
        // Command mode — collecting text
        for (const ch of data) {
          // Enter — process command
          if (ch === '\r' || ch === '\n') {
            process.stdout.write('\n');
            cleanup();
            resolve({ type: 'command', text: buffer.trim() });
            return;
          }

          // Backspace
          if (ch === '\x7f' || ch === '\b') {
            if (buffer.length > 0) {
              buffer = buffer.slice(0, -1);
              process.stdout.write('\b \b');
            }
            continue;
          }

          // Ctrl+C
          if (ch === '\x03') {
            cleanup();
            resolve({ type: 'quit' });
            return;
          }

          // Escape — cancel command, back to single-char mode
          if (ch === '\x1b') {
            for (let i = 0; i < buffer.length; i++) {
              process.stdout.write('\b \b');
            }
            buffer = '';
            inCommandMode = false;
            continue;
          }

          // Printable char — accumulate
          if (ch.charCodeAt(0) >= 32) {
            buffer += ch;
            process.stdout.write(ch);
          }
        }
      }
    }

    stdin.on('data', onData);
  });
}

// ── Compact submenu ─────────────────────────────────────────────────

/**
 * Render a compact submenu with number-key selection.
 * Used for secondary choices (scan depth, frameworks, languages).
 */
export function renderCompactMenu(title: string, items: MenuItem[]): void {
  console.log(`  ${c.dim(title)}`);
  console.log('');

  for (const item of items) {
    console.log(`    ${c.sage(`[${item.key}]`)}  ${item.label}`);
    if (item.description) {
      console.log(`          ${c.dim(item.description)}`);
    }
  }
  console.log('');
}

/**
 * Wait for user to select from a compact submenu.
 * Returns selected MenuItem or null for back/quit.
 */
export async function waitForCompactChoice(
  items: MenuItem[],
  lang: Lang
): Promise<MenuItem | null> {
  const validKeys = new Set(items.map((i) => i.key));
  const backText = lang === 'zh-TW' ? '\u8FD4\u56DE' : 'Back';

  console.log(`  ${c.dim(`[b] ${backText}`)}`);
  console.log('');
  const promptLabel = lang === 'zh-TW' ? '\u9078\u64C7' : 'Select';
  process.stdout.write(`  ${c.sage(promptLabel + ' >')} `);

  while (true) {
    const key = await waitForKey();

    if (key === 'q' || key === 'ctrl-c' || key === 'b' || key === 'escape') {
      console.log('');
      return null;
    }

    if (validKeys.has(key)) {
      console.log('');
      return items.find((i) => i.key === key) ?? null;
    }
  }
}

// ── Utilities ───────────────────────────────────────────────────────

/**
 * "Press any key to continue..."
 */
export async function pressAnyKey(lang: Lang): Promise<void> {
  const msg =
    lang === 'zh-TW' ? '\u6309\u4EFB\u610F\u9375\u7E7C\u7E8C...' : 'Press any key to continue...';
  console.log('');
  process.stdout.write(`  ${c.dim(msg)} `);
  await waitForKey();
  console.log('');
}

/**
 * Cleanup terminal state on exit.
 */
export function cleanupTerminal(): void {
  showCursor();
  if (process.stdin.isTTY && process.stdin.isRaw) {
    process.stdin.setRawMode(false);
  }
}
