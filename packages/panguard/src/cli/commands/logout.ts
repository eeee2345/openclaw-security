/**
 * `panguard logout` - Log out from Panguard AI
 * `panguard logout` - 登出 Panguard AI
 *
 * Deletes local credentials and optionally invalidates the server session.
 *
 * @module @panguard-ai/panguard/cli/commands/logout
 */

import { Command } from 'commander';
import { c, symbols } from '@panguard-ai/core';
import { loadCredentials, deleteCredentials } from '../credentials.js';

export function logoutCommand(): Command {
  return new Command('logout')
    .description('Log out of Panguard AI / \u767B\u51FA Panguard AI')
    .option('--lang <language>', 'Language override')
    .action(async (opts: { lang?: string }) => {
      const lang = opts.lang === 'en' ? 'en' : 'zh-TW';
      const creds = loadCredentials();

      if (!creds) {
        console.log('');
        console.log(`  ${symbols.info} ${lang === 'zh-TW'
          ? '\u76EE\u524D\u672A\u767B\u5165\u3002'
          : 'Not currently logged in.'}`);
        console.log('');
        return;
      }

      // Best-effort server-side logout
      try {
        await fetch(`${creds.apiUrl}/api/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${creds.token}`,
            'Content-Type': 'application/json',
          },
        });
        // Ignore response - best-effort
      } catch {
        // Server may be unreachable - that's fine
      }

      // Delete local credentials
      deleteCredentials();

      console.log('');
      console.log(`  ${symbols.pass} ${lang === 'zh-TW'
        ? `\u5DF2\u767B\u51FA ${c.sage(creds.email)}\u3002\u672C\u5730\u6191\u8B49\u5DF2\u522A\u9664\u3002`
        : `Logged out ${c.sage(creds.email)}. Local credentials deleted.`}`);
      console.log('');
    });
}
