/**
 * panguard admin - Admin management commands
 *
 * panguard admin init           Create initial admin account
 * panguard admin create-user    Create a user with specified tier
 */

import { Command } from 'commander';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { c, banner } from '@openclaw/core';
import { AuthDB, hashPassword } from '@openclaw/panguard-auth';

function prompt(rl: ReturnType<typeof createInterface>, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => resolve(answer.trim()));
  });
}

export function adminCommand(): Command {
  const cmd = new Command('admin')
    .description('Admin management commands / 管理員指令');

  cmd
    .command('init')
    .description('Create initial admin account / 建立初始管理員帳號')
    .option('--db <path>', 'Database path', join(homedir(), '.panguard', 'auth.db'))
    .action(async (options: { db: string }) => {
      console.log(banner());
      console.log(`  ${c.sage('Admin Init')} - Create admin account`);
      console.log('');

      // Ensure db directory exists
      mkdirSync(join(homedir(), '.panguard'), { recursive: true });

      const db = new AuthDB(options.db);
      const rl = createInterface({ input: process.stdin, output: process.stdout });

      try {
        const email = await prompt(rl, `  ${c.dim('Email:')} `);
        if (!email || !email.includes('@')) {
          console.log(`  ${c.critical('Invalid email')}`);
          return;
        }

        const existing = db.getUserByEmail(email);
        if (existing) {
          console.log(`  ${c.caution('User already exists.')} Updating role to admin...`);
          db.updateUserRole(existing.id, 'admin');
          console.log(`  ${c.safe('Done.')} ${email} is now an admin.`);
          return;
        }

        const name = await prompt(rl, `  ${c.dim('Name:')} `);
        const password = await prompt(rl, `  ${c.dim('Password (min 8 chars):')} `);
        if (password.length < 8) {
          console.log(`  ${c.critical('Password must be at least 8 characters')}`);
          return;
        }

        const pwHash = await hashPassword(password);
        const user = db.createUser({ email, name: name || email, password }, pwHash);
        db.updateUserRole(user.id, 'admin');

        console.log('');
        console.log(`  ${c.safe('Admin account created:')}`);
        console.log(`    Email: ${c.sage(email)}`);
        console.log(`    Role:  ${c.sage('admin')}`);
        console.log(`    Tier:  ${c.sage('free')} (change via admin panel)`);
        console.log('');
        console.log(`  Start the server: ${c.sage('panguard serve')}`);
        console.log(`  Admin panel:      ${c.sage('http://localhost:3000/admin')}`);
        console.log('');
      } finally {
        rl.close();
        db.close();
      }
    });

  cmd
    .command('create-user')
    .description('Create a user with specified tier / 建立指定等級的用戶')
    .option('--db <path>', 'Database path', join(homedir(), '.panguard', 'auth.db'))
    .option('--email <email>', 'User email')
    .option('--name <name>', 'User name')
    .option('--password <password>', 'User password')
    .option('--tier <tier>', 'User tier (free/solo/pro/enterprise)', 'free')
    .option('--role <role>', 'User role (user/admin)', 'user')
    .action(async (options: { db: string; email?: string; name?: string; password?: string; tier: string; role: string }) => {
      mkdirSync(join(homedir(), '.panguard'), { recursive: true });
      const db = new AuthDB(options.db);

      let email = options.email;
      let name = options.name;
      let password = options.password;

      // Interactive mode if options not provided
      if (!email || !password) {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        try {
          if (!email) email = await prompt(rl, `  ${c.dim('Email:')} `);
          if (!name) name = await prompt(rl, `  ${c.dim('Name:')} `);
          if (!password) password = await prompt(rl, `  ${c.dim('Password:')} `);
        } finally {
          rl.close();
        }
      }

      if (!email || !email.includes('@')) {
        console.log(`  ${c.critical('Invalid email')}`);
        db.close();
        return;
      }
      if (!password || password.length < 8) {
        console.log(`  ${c.critical('Password must be at least 8 characters')}`);
        db.close();
        return;
      }

      const existing = db.getUserByEmail(email);
      if (existing) {
        console.log(`  ${c.caution('User already exists with this email')}`);
        db.close();
        return;
      }

      const pwHash = await hashPassword(password);
      const user = db.createUser({ email, name: name || email, password }, pwHash);
      db.updateUserTier(user.id, options.tier);
      db.updateUserRole(user.id, options.role);

      console.log(`  ${c.safe('User created:')}`);
      console.log(`    Email: ${email}`);
      console.log(`    Tier:  ${options.tier}`);
      console.log(`    Role:  ${options.role}`);
      console.log('');

      db.close();
    });

  return cmd;
}
