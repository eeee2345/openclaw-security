'use client';

import { useState, useEffect } from 'react';

type OS = 'mac' | 'linux' | 'windows';

const INSTALL_COMMANDS: Record<OS, string> = {
  mac: 'curl -fsSL https://get.panguard.ai | bash',
  linux: 'curl -fsSL https://get.panguard.ai | bash',
  windows: 'irm https://get.panguard.ai/windows | iex',
};

const PROMPTS: Record<OS, string> = {
  mac: '$',
  linux: '$',
  windows: '>',
};

export function useOS() {
  const [os, setOS] = useState<OS>('mac');

  useEffect(() => {
    const ua = navigator.userAgent;
    if (/Win/.test(ua)) setOS('windows');
    else if (/Mac/.test(ua)) setOS('mac');
    else setOS('linux');
  }, []);

  return {
    os,
    installCmd: INSTALL_COMMANDS[os],
    prompt: PROMPTS[os],
  };
}
