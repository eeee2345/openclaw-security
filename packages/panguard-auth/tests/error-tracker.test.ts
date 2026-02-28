import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { captureException, captureRequestError } from '../src/error-tracker.js';

describe('Error Tracker', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  describe('captureException', () => {
    it('should log Error instances as JSON', () => {
      const err = new Error('test error');
      captureException(err);
      expect(errorSpy).toHaveBeenCalledOnce();
      const logStr = errorSpy.mock.calls[0]![0] as string;
      const parsed = JSON.parse(logStr);
      expect(parsed.level).toBe('error');
      expect(parsed.message).toBe('test error');
      expect(parsed.stack).toBeDefined();
      expect(parsed.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('should log string errors', () => {
      captureException('string error');
      const logStr = errorSpy.mock.calls[0]![0] as string;
      const parsed = JSON.parse(logStr);
      expect(parsed.message).toBe('string error');
      expect(parsed.stack).toBeUndefined();
    });

    it('should include extra context', () => {
      captureException(new Error('ctx test'), { source: 'test', foo: 'bar' });
      const logStr = errorSpy.mock.calls[0]![0] as string;
      const parsed = JSON.parse(logStr);
      expect(parsed.source).toBe('test');
      expect(parsed.foo).toBe('bar');
    });

    it('should handle non-Error objects', () => {
      captureException({ code: 42 });
      const logStr = errorSpy.mock.calls[0]![0] as string;
      const parsed = JSON.parse(logStr);
      expect(parsed.message).toBe('[object Object]');
    });

    it('should handle null/undefined', () => {
      captureException(null);
      captureException(undefined);
      expect(errorSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe('captureRequestError', () => {
    it('should include method and path in context', () => {
      captureRequestError(new Error('req fail'), 'POST', '/api/auth/login');
      const logStr = errorSpy.mock.calls[0]![0] as string;
      const parsed = JSON.parse(logStr);
      expect(parsed.source).toBe('request');
      expect(parsed.method).toBe('POST');
      expect(parsed.path).toBe('/api/auth/login');
      expect(parsed.message).toBe('req fail');
    });
  });
});
