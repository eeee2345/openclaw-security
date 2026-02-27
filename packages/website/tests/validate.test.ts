import { describe, it, expect } from 'vitest';
import {
  escapeHtml,
  validateEmail,
  validateWaitlist,
  validateContact,
  validateDemo,
} from '../src/lib/validate';

/* ─── escapeHtml ─── */

describe('escapeHtml', () => {
  it('escapes HTML entities', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    );
  });

  it('escapes ampersands', () => {
    expect(escapeHtml('foo & bar')).toBe('foo &amp; bar');
  });

  it('escapes single quotes', () => {
    expect(escapeHtml("it's")).toBe('it&#x27;s');
  });

  it('returns empty string unchanged', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('leaves safe strings untouched', () => {
    expect(escapeHtml('hello world')).toBe('hello world');
  });
});

/* ─── validateEmail ─── */

describe('validateEmail', () => {
  it('accepts a valid email', () => {
    expect(validateEmail('test@example.com')).toBe('test@example.com');
  });

  it('normalizes to lowercase', () => {
    expect(validateEmail('User@Example.COM')).toBe('user@example.com');
  });

  it('trims whitespace', () => {
    expect(validateEmail('  user@example.com  ')).toBe('user@example.com');
  });

  it('rejects non-string input', () => {
    expect(validateEmail(42)).toBeNull();
    expect(validateEmail(null)).toBeNull();
    expect(validateEmail(undefined)).toBeNull();
  });

  it('rejects empty string', () => {
    expect(validateEmail('')).toBeNull();
  });

  it('rejects email without @', () => {
    expect(validateEmail('notanemail')).toBeNull();
  });

  it('rejects email without domain', () => {
    expect(validateEmail('user@')).toBeNull();
  });

  it('rejects email without TLD', () => {
    expect(validateEmail('user@example')).toBeNull();
  });

  it('rejects email exceeding 254 chars', () => {
    const long = 'a'.repeat(246) + '@test.com'; // 255 chars total
    expect(validateEmail(long)).toBeNull();
  });
});

/* ─── validateWaitlist ─── */

describe('validateWaitlist', () => {
  it('returns email for valid input', () => {
    expect(validateWaitlist({ email: 'a@b.com' })).toEqual({ email: 'a@b.com' });
  });

  it('returns null for missing email', () => {
    expect(validateWaitlist({ email: '' })).toBeNull();
  });

  it('returns null for non-object input', () => {
    expect(validateWaitlist(null)).toBeNull();
    expect(validateWaitlist('string')).toBeNull();
  });
});

/* ─── validateContact ─── */

describe('validateContact', () => {
  const valid = {
    name: 'Alice',
    email: 'alice@example.com',
    company: 'ACME',
    type: 'General',
    message: 'Hello there',
  };

  it('accepts valid contact form', () => {
    const result = validateContact(valid);
    expect(result).not.toBeNull();
    expect(result!.email).toBe('alice@example.com');
  });

  it('allows empty company', () => {
    const result = validateContact({ ...valid, company: '' });
    expect(result).not.toBeNull();
    expect(result!.company).toBe('');
  });

  it('rejects missing name', () => {
    expect(validateContact({ ...valid, name: '' })).toBeNull();
  });

  it('rejects invalid email', () => {
    expect(validateContact({ ...valid, email: 'bad' })).toBeNull();
  });

  it('rejects missing type', () => {
    expect(validateContact({ ...valid, type: '' })).toBeNull();
  });

  it('rejects missing message', () => {
    expect(validateContact({ ...valid, message: '' })).toBeNull();
  });

  it('escapes XSS in name', () => {
    const result = validateContact({ ...valid, name: '<img onerror="alert(1)">' });
    expect(result).not.toBeNull();
    expect(result!.name).not.toContain('<img');
  });

  it('rejects name exceeding 100 chars', () => {
    expect(validateContact({ ...valid, name: 'x'.repeat(101) })).toBeNull();
  });

  it('rejects message exceeding 5000 chars', () => {
    expect(validateContact({ ...valid, message: 'x'.repeat(5001) })).toBeNull();
  });

  it('rejects non-object input', () => {
    expect(validateContact(null)).toBeNull();
    expect(validateContact(undefined)).toBeNull();
  });
});

/* ─── validateDemo ─── */

describe('validateDemo', () => {
  const valid = {
    name: 'Bob',
    email: 'bob@corp.io',
    company: 'Corp Inc',
    teamSize: '11-50',
    stack: 'Node, React',
    message: 'Interested',
  };

  it('accepts valid demo form', () => {
    const result = validateDemo(valid);
    expect(result).not.toBeNull();
    expect(result!.email).toBe('bob@corp.io');
  });

  it('allows optional fields to be empty', () => {
    const result = validateDemo({
      ...valid,
      teamSize: '',
      stack: '',
      message: '',
    });
    expect(result).not.toBeNull();
    expect(result!.teamSize).toBe('');
  });

  it('rejects missing company', () => {
    expect(validateDemo({ ...valid, company: '' })).toBeNull();
  });

  it('rejects non-object input', () => {
    expect(validateDemo(42)).toBeNull();
  });
});
