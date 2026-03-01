import { describe, it, expect, vi, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

describe('useOS', () => {
  const originalNavigator = globalThis.navigator;

  function mockUserAgent(ua: string) {
    Object.defineProperty(globalThis, 'navigator', {
      value: { userAgent: ua },
      writable: true,
      configurable: true,
    });
  }

  afterEach(() => {
    Object.defineProperty(globalThis, 'navigator', {
      value: originalNavigator,
      writable: true,
      configurable: true,
    });
    vi.resetModules();
  });

  it('detects macOS', async () => {
    mockUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)');
    const { useOS } = await import('../../src/hooks/useOS');
    const { result } = renderHook(() => useOS());
    expect(result.current.os).toBe('mac');
    expect(result.current.prompt).toBe('$');
    expect(result.current.installCmd).toContain('curl');
  });

  it('detects Windows', async () => {
    mockUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
    const { useOS } = await import('../../src/hooks/useOS');
    const { result } = renderHook(() => useOS());
    expect(result.current.os).toBe('windows');
    expect(result.current.prompt).toBe('>');
    expect(result.current.installCmd).toContain('irm');
  });

  it('defaults to linux for unknown UA', async () => {
    mockUserAgent('Mozilla/5.0 (X11; Linux x86_64)');
    const { useOS } = await import('../../src/hooks/useOS');
    const { result } = renderHook(() => useOS());
    expect(result.current.os).toBe('linux');
    expect(result.current.prompt).toBe('$');
  });
});
