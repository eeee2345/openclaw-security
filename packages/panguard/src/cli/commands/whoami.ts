/**
 * `panguard whoami` - Show current user info
 * `panguard whoami` - 顯示目前用戶資訊
 *
 * @module @openclaw/panguard/cli/commands/whoami
 */

import { Command } from 'commander';
import { c, symbols, statusPanel, timeAgo } from '@openclaw/core';
import type { StatusItem } from '@openclaw/core';
import { loadCredentials, isTokenExpired, tierDisplayName } from '../credentials.js';

export function whoamiCommand(): Command {
  return new Command('whoami')
    .description('Show current user info / \u986F\u793A\u76EE\u524D\u7528\u6236\u8CC7\u8A0A')
    .option('--json', 'Output as JSON')
    .option('--lang <language>', 'Language override')
    .action(async (opts: { json?: boolean; lang?: string }) => {
      const lang = opts.lang === 'en' ? 'en' : 'zh-TW';
      const creds = loadCredentials();

      if (!creds) {
        if (opts.json) {
          console.log(JSON.stringify({ authenticated: false }));
          return;
        }
        console.log('');
        console.log(`  ${symbols.warn} ${lang === 'zh-TW'
          ? '\u672A\u767B\u5165\u3002\u57F7\u884C \u300Cpanguard login\u300D\u4F86\u9A57\u8B49\u3002'
          : 'Not logged in. Run "panguard login" to authenticate.'}`);
        console.log('');
        process.exitCode = 1;
        return;
      }

      const expired = isTokenExpired(creds);

      if (opts.json) {
        console.log(JSON.stringify({
          authenticated: !expired,
          email: creds.email,
          name: creds.name,
          tier: creds.tier,
          expiresAt: creds.expiresAt,
          expired,
          apiUrl: creds.apiUrl,
        }, null, 2));
        return;
      }

      if (expired) {
        console.log('');
        console.log(`  ${symbols.warn} ${lang === 'zh-TW'
          ? `\u5E33\u865F ${c.sage(creds.email)} \u7684 session \u5DF2\u904E\u671F\u3002\u8ACB\u91CD\u65B0\u57F7\u884C ${c.sage('panguard login')}\u3002`
          : `Session for ${c.sage(creds.email)} has expired. Run ${c.sage('panguard login')} to re-authenticate.`}`);
        console.log('');
        process.exitCode = 1;
        return;
      }

      // Build status display
      const items: StatusItem[] = [
        { label: lang === 'zh-TW' ? '\u4FE1\u7BB1' : 'Email', value: creds.email, status: 'safe' },
        { label: lang === 'zh-TW' ? '\u540D\u7A31' : 'Name', value: creds.name },
        {
          label: lang === 'zh-TW' ? '\u8A02\u95B1\u7B49\u7D1A' : 'Tier',
          value: tierDisplayName(creds.tier),
          status: creds.tier === 'enterprise' || creds.tier === 'business' || creds.tier === 'team' ? 'safe' : undefined,
        },
        {
          label: lang === 'zh-TW' ? '\u5230\u671F\u6642\u9593' : 'Expires',
          value: timeAgo(creds.expiresAt),
        },
        {
          label: lang === 'zh-TW' ? '\u4F3A\u670D\u5668' : 'Server',
          value: creds.apiUrl,
        },
      ];

      console.log('');
      console.log(statusPanel(
        lang === 'zh-TW' ? 'Panguard AI \u5E33\u6236\u8CC7\u8A0A' : 'Panguard AI Account',
        items,
      ));
      console.log('');
    });
}
