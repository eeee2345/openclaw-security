/**
 * Arrow-key interactive menu system for Panguard CLI.
 * Minimalist design — no box-drawing borders, single language.
 *
 * Uses ANSI cursor control for flicker-free re-rendering.
 *
 * @module @panguard-ai/panguard/cli/menu
 */

import { c, visLen } from '@panguard-ai/core';
import { tierLabel } from './theme.js';
import type { Tier } from './credentials.js';
import { getLicense } from './auth-guard.js';

export type Lang = 'en' | 'zh-TW';

export interface MenuItem {
  key: string;
  label: string;
  description?: string;
  tier?: Tier | string;
  separator?: boolean;
}

// ── Constants ─────────────────────────────────────────────────────────

const POINTER = '\u25B6'; // ►
const SEP_LINE = '\u2500'.repeat(5); // ─────
const MENU_WIDTH = 60;

// ── ANSI helpers ──────────────────────────────────────────────────────

/** Move cursor up N lines */
function cursorUp(n: number): void {
  if (n > 0) process.stdout.write(`\x1b[${n}A`);
}

/** Clear from cursor to end of line */
function clearLine(): void {
  process.stdout.write('\x1b[2K');
}

/** Hide cursor */
function hideCursor(): void {
  process.stdout.write('\x1b[?25l');
}

/** Show cursor */
function showCursor(): void {
  process.stdout.write('\x1b[?25h');
}

// ── Key input ─────────────────────────────────────────────────────────

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

      // Ctrl+C
      if (data === '\x03') { resolve('ctrl-c'); return; }
      // Enter
      if (data === '\r' || data === '\n') { resolve('enter'); return; }
      // Escape (standalone)
      if (data === '\x1b' && data.length === 1) { resolve('escape'); return; }
      // Arrow keys: \x1b[A (up), \x1b[B (down), \x1b[C (right), \x1b[D (left)
      if (data === '\x1b[A') { resolve('up'); return; }
      if (data === '\x1b[B') { resolve('down'); return; }
      if (data === '\x1b[C') { resolve('right'); return; }
      if (data === '\x1b[D') { resolve('left'); return; }

      resolve(data.trim().toLowerCase());
    };

    stdin.on('data', onData);
  });
}

// ── Menu rendering ────────────────────────────────────────────────────

function renderMenuLine(item: MenuItem, selected: boolean, userTier?: Tier | string): string {
  if (item.separator) {
    return `    ${c.dim(SEP_LINE)}`;
  }

  const pointer = selected ? c.sage(POINTER) : ' ';
  const label = selected ? c.sage(item.label) : c.dim(item.label);

  // Build right-aligned tier badge
  let badge = '';
  if (item.tier) {
    badge = tierLabel(item.tier as Tier, userTier);
  }

  // Calculate padding for right-alignment
  const leftPart = `  ${pointer} ${item.key.padEnd(15)} ${label}`;
  const leftLen = visLen(leftPart);
  const badgeLen = visLen(badge);
  const gap = Math.max(1, MENU_WIDTH - leftLen - badgeLen);

  return `${leftPart}${' '.repeat(gap)}${badge}`;
}

/** Render the full menu to stdout */
function drawMenu(items: MenuItem[], selectedIndex: number, footer: string, userTier?: Tier | string): void {
  for (let i = 0; i < items.length; i++) {
    clearLine();
    console.log(renderMenuLine(items[i]!, i === selectedIndex, userTier));
  }
  // Footer
  clearLine();
  console.log('');
  clearLine();
  console.log(c.dim(`  ${footer}`));
}

/** Total lines rendered by drawMenu (items + 2 for blank + footer) */
function menuLineCount(items: MenuItem[]): number {
  return items.length + 2;
}

// ── Arrow-key menu ────────────────────────────────────────────────────

export interface ArrowMenuResult {
  key: string;
  label: string;
  tier?: Tier | string;
}

/**
 * Run an interactive arrow-key menu.
 * Returns the selected item, or null for quit.
 * Returns { key: '__lang__' } for language toggle.
 */
export async function runArrowMenu(
  items: MenuItem[],
  opts: { lang: Lang; initialIndex?: number },
): Promise<ArrowMenuResult | null> {
  const selectableIndices = items
    .map((item, i) => ({ item, i }))
    .filter(({ item }) => !item.separator)
    .map(({ i }) => i);

  if (selectableIndices.length === 0) return null;

  let selectedIndex = opts.initialIndex ?? selectableIndices[0]!;

  // Ensure selectedIndex is valid
  if (!selectableIndices.includes(selectedIndex)) {
    selectedIndex = selectableIndices[0]!;
  }

  const { tier: userTier } = getLicense();

  const footerText = opts.lang === 'zh-TW'
    ? '\u2191\u2193 \u5C0E\u822A  \u23CE \u9078\u64C7  q \u9000\u51FA  l \u4E2D/EN'
    : '\u2191\u2193 Navigate  \u23CE Select  q Quit  l \u4E2D/EN';

  hideCursor();

  // Initial draw
  drawMenu(items, selectedIndex, footerText, userTier);

  try {
    while (true) {
      const key = await waitForKey();

      if (key === 'q' || key === 'ctrl-c') {
        showCursor();
        return null;
      }

      if (key === 'l') {
        showCursor();
        return { key: '__lang__', label: '' };
      }

      if (key === 'enter') {
        showCursor();
        const item = items[selectedIndex];
        if (!item || item.separator) continue;
        return { key: item.key, label: item.label, tier: item.tier };
      }

      let moved = false;

      if (key === 'up') {
        const currentPos = selectableIndices.indexOf(selectedIndex);
        if (currentPos > 0) {
          selectedIndex = selectableIndices[currentPos - 1]!;
          moved = true;
        }
      }

      if (key === 'down') {
        const currentPos = selectableIndices.indexOf(selectedIndex);
        if (currentPos < selectableIndices.length - 1) {
          selectedIndex = selectableIndices[currentPos + 1]!;
          moved = true;
        }
      }

      if (moved) {
        // Move cursor back up and redraw
        const totalLines = menuLineCount(items);
        cursorUp(totalLines);
        drawMenu(items, selectedIndex, footerText, userTier);
      }
    }
  } catch {
    showCursor();
    return null;
  }
}

// ── Compact submenu (for scan depth, frameworks, etc.) ────────────────

/**
 * Render a compact submenu with number-key selection.
 * Used for secondary choices (scan depth, frameworks, languages).
 */
export function renderCompactMenu(
  title: string,
  items: MenuItem[],
): void {
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
  lang: Lang,
): Promise<MenuItem | null> {
  const validKeys = new Set(items.map(i => i.key));
  const backText = lang === 'zh-TW' ? '\u8FD4\u56DE' : 'Back';

  console.log(`  ${c.dim(`[b] ${backText}`)}`);
  console.log('');
  process.stdout.write(`  ${c.sage('>')} `);

  while (true) {
    const key = await waitForKey();

    if (key === 'q' || key === 'ctrl-c' || key === 'b' || key === 'escape') {
      console.log('');
      return null;
    }

    if (validKeys.has(key)) {
      console.log('');
      return items.find(i => i.key === key) ?? null;
    }
  }
}

// ── Utilities ─────────────────────────────────────────────────────────

/**
 * "Press any key to continue..."
 */
export async function pressAnyKey(lang: Lang): Promise<void> {
  const msg = lang === 'zh-TW'
    ? '\u6309\u4EFB\u610F\u9375\u7E7C\u7E8C...'
    : 'Press any key to continue...';
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
