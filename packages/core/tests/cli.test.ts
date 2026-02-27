import { describe, it, expect } from 'vitest';
import {
  c,
  colorSeverity,
  colorScore,
  colorGrade,
  table,
  box,
  banner,
  header,
  divider,
  scoreDisplay,
  statusPanel,
  stripAnsi,
  formatDuration,
  timeAgo,
  symbols,
} from '../src/cli/index.js';

describe('CLI Colors (Brand Tokens)', () => {
  it('should apply brand sage green', () => {
    const sage = c.sage('text');
    expect(sage).toContain('text');
  });

  it('should apply brand status colors', () => {
    expect(stripAnsi(c.safe('ok'))).toBe('ok');
    expect(stripAnsi(c.caution('warn'))).toBe('warn');
    expect(stripAnsi(c.alert('alert'))).toBe('alert');
    expect(stripAnsi(c.critical('bad'))).toBe('bad');
  });

  it('should apply semantic styles', () => {
    expect(stripAnsi(c.brand('brand'))).toBe('brand');
    expect(stripAnsi(c.heading('title'))).toBe('title');
    expect(stripAnsi(c.success('done'))).toBe('done');
    expect(stripAnsi(c.error('err'))).toBe('err');
  });

  it('should apply bold', () => {
    expect(stripAnsi(c.bold('title'))).toBe('title');
  });
});

describe('colorSeverity (Brand Status Colors)', () => {
  it('should color critical with background', () => {
    const result = colorSeverity('critical');
    expect(stripAnsi(result)).toContain('CRITICAL');
  });

  it('should color high', () => {
    expect(stripAnsi(colorSeverity('high'))).toBe('HIGH');
  });

  it('should color medium', () => {
    expect(stripAnsi(colorSeverity('medium'))).toBe('MEDIUM');
  });

  it('should color low', () => {
    expect(stripAnsi(colorSeverity('low'))).toBe('LOW');
  });

  it('should return unknown severity unchanged', () => {
    expect(colorSeverity('unknown')).toBe('unknown');
  });
});

describe('colorScore', () => {
  it('should color high scores safe green', () => {
    expect(stripAnsi(colorScore(95))).toBe('95');
  });

  it('should color low scores critical red', () => {
    expect(stripAnsi(colorScore(20))).toBe('20');
  });
});

describe('colorGrade', () => {
  it('should color all grades with brand colors', () => {
    for (const grade of ['A', 'B', 'C', 'D', 'F']) {
      expect(stripAnsi(colorGrade(grade))).toBe(grade);
    }
  });
});

describe('table', () => {
  it('should render a table with headers and rows', () => {
    const result = table(
      [
        { header: 'Name', key: 'name', width: 10 },
        { header: 'Value', key: 'value', width: 10 },
      ],
      [
        { name: 'cpu', value: '50%' },
        { name: 'ram', value: '30%' },
      ]
    );
    const lines = result.split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(5);
    const plain = stripAnsi(result);
    expect(plain).toContain('Name');
    expect(plain).toContain('cpu');
    expect(plain).toContain('30%');
  });

  it('should handle empty rows', () => {
    const result = table([{ header: 'Col', key: 'col', width: 5 }], []);
    expect(stripAnsi(result)).toContain('Col');
  });
});

describe('box', () => {
  it('should draw a box around content', () => {
    const result = box('Hello');
    const lines = result.split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(3);
    const plain = stripAnsi(result);
    expect(plain).toContain('Hello');
    expect(plain).toContain('+');
  });

  it('should include title', () => {
    const result = box('Content', { title: 'Title' });
    const plain = stripAnsi(result);
    expect(plain).toContain('Title');
    expect(plain).toContain('Content');
  });

  it('should accept brand borderColor', () => {
    const result = box('Safe', { borderColor: c.safe, title: 'OK' });
    expect(stripAnsi(result)).toContain('Safe');
  });
});

describe('banner (Brand Logo)', () => {
  it('should include PANGUARD AI text', () => {
    const result = banner();
    const plain = stripAnsi(result);
    expect(plain).toContain('PANGUARD');
    expect(plain).toContain('AI');
  });

  it('should include version', () => {
    const plain = stripAnsi(banner());
    expect(plain).toContain('v0.5.0');
  });

  it('should have multiple lines', () => {
    expect(banner().split('\n').length).toBeGreaterThanOrEqual(4);
  });
});

describe('header', () => {
  it('should return PANGUARD AI text', () => {
    const plain = stripAnsi(header('subtitle'));
    expect(plain).toContain('PANGUARD');
    expect(plain).toContain('AI');
    expect(plain).toContain('subtitle');
  });

  it('should work without subtitle', () => {
    const plain = stripAnsi(header());
    expect(plain).toContain('PANGUARD');
  });
});

describe('divider', () => {
  it('should return a divider line', () => {
    const plain = stripAnsi(divider());
    expect(plain.length).toBeGreaterThan(10);
    expect(plain).toMatch(/^=+$/);
  });

  it('should include label', () => {
    const plain = stripAnsi(divider('Section'));
    expect(plain).toContain('Section');
    expect(plain).toContain('=');
  });
});

describe('scoreDisplay', () => {
  it('should show score and grade', () => {
    const plain = stripAnsi(scoreDisplay(85, 'B'));
    expect(plain).toContain('85');
    expect(plain).toContain('/100');
    expect(plain).toContain('B');
  });

  it('should show trend indicators', () => {
    const improving = stripAnsi(scoreDisplay(90, 'A', 'improving'));
    expect(improving).toContain('[+]');

    const declining = stripAnsi(scoreDisplay(30, 'F', 'declining'));
    expect(declining).toContain('[-]');

    const stable = stripAnsi(scoreDisplay(70, 'C', 'stable'));
    expect(stable).toContain('[=]');
  });

  it('should include progress bar', () => {
    const plain = stripAnsi(scoreDisplay(75, 'B'));
    expect(plain).toContain('[');
    expect(plain).toContain(']');
  });
});

describe('statusPanel', () => {
  it('should show title and items', () => {
    const result = statusPanel('Test Panel', [
      { label: 'Status', value: 'OK', status: 'safe' },
      { label: 'Count', value: '42' },
    ]);
    const plain = stripAnsi(result);
    expect(plain).toContain('Test Panel');
    expect(plain).toContain('Status');
    expect(plain).toContain('OK');
    expect(plain).toContain('Count');
    expect(plain).toContain('42');
  });

  it('should support all status types', () => {
    const result = statusPanel('Statuses', [
      { label: 'Safe', value: 'ok', status: 'safe' },
      { label: 'Caution', value: 'warn', status: 'caution' },
      { label: 'Alert', value: 'alert', status: 'alert' },
      { label: 'Critical', value: 'bad', status: 'critical' },
    ]);
    const plain = stripAnsi(result);
    expect(plain).toContain('Safe');
    expect(plain).toContain('Critical');
  });
});

describe('stripAnsi', () => {
  it('should strip ANSI codes', () => {
    expect(stripAnsi('\x1b[31mred\x1b[0m')).toBe('red');
    expect(stripAnsi('plain')).toBe('plain');
  });

  it('should strip 24-bit color codes', () => {
    expect(stripAnsi('\x1b[38;2;139;154;142msage\x1b[0m')).toBe('sage');
  });
});

describe('formatDuration', () => {
  it('should format milliseconds', () => {
    expect(formatDuration(500)).toBe('500ms');
    expect(formatDuration(1500)).toBe('1.5s');
    expect(formatDuration(65000)).toBe('1m 5s');
    expect(formatDuration(0)).toBe('0ms');
  });
});

describe('timeAgo', () => {
  it('should format recent times', () => {
    expect(timeAgo(new Date())).toBe('just now');
  });

  it('should format older times', () => {
    expect(timeAgo(new Date(Date.now() - 3600000))).toBe('1h ago');
  });

  it('should accept ISO string dates', () => {
    expect(timeAgo(new Date(Date.now() - 120000).toISOString())).toBe('2m ago');
  });
});

describe('symbols (Brand Indicators)', () => {
  it('should have all brand status symbols', () => {
    const pass = stripAnsi(symbols.pass);
    const fail = stripAnsi(symbols.fail);
    const warn = stripAnsi(symbols.warn);
    const info = stripAnsi(symbols.info);
    // Non-color terminals get ASCII fallback
    expect(pass.length).toBeGreaterThan(0);
    expect(fail.length).toBeGreaterThan(0);
    expect(warn.length).toBeGreaterThan(0);
    expect(info.length).toBeGreaterThan(0);
  });
});
