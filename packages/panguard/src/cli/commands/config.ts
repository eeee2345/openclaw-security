/**
 * panguard config - Manage local configuration
 *
 * Subcommands:
 *   panguard config llm --provider claude --api-key sk-xxx
 *   panguard config llm --provider ollama --endpoint http://localhost:11434
 *   panguard config llm --show
 *   panguard config llm --clear
 */

import { Command } from 'commander';
import { c, banner } from '@panguard-ai/core';
import { saveLlmConfig, loadLlmConfig, deleteLlmConfig } from '../credentials.js';

export function configCommand(): Command {
  const cmd = new Command('config').description('Manage local configuration / 管理本地設定');

  cmd
    .command('llm')
    .description('Configure LLM provider for AI analysis / 設定 AI 分析的 LLM 提供者')
    .option('--provider <provider>', 'LLM provider: claude, openai, ollama')
    .option('--api-key <key>', 'API key (for claude/openai)')
    .option('--model <model>', 'Model override (e.g., claude-haiku-4-5-20251001, gpt-4o)')
    .option('--endpoint <url>', 'Endpoint URL (for ollama, default: http://localhost:11434)')
    .option('--show', 'Show current LLM configuration')
    .option('--clear', 'Remove stored LLM configuration')
    .action(
      (options: {
        provider?: string;
        apiKey?: string;
        model?: string;
        endpoint?: string;
        show?: boolean;
        clear?: boolean;
      }) => {
        console.log(banner());

        if (options.show) {
          const config = loadLlmConfig();
          if (!config) {
            console.log(`  ${c.dim('No LLM configuration found.')}`);
            console.log(
              `  ${c.dim('Set one with:')} panguard config llm --provider claude --api-key sk-...`
            );
            return;
          }
          console.log(`  ${c.sage('LLM Configuration')}`);
          console.log(`  Provider:  ${c.bold(config.provider)}`);
          console.log(
            `  API Key:   ${config.apiKey ? c.safe(config.apiKey.slice(0, 8) + '...' + config.apiKey.slice(-4)) : c.dim('none')}`
          );
          console.log(`  Model:     ${config.model ? c.bold(config.model) : c.dim('default')}`);
          console.log(
            `  Endpoint:  ${config.endpoint ? c.bold(config.endpoint) : c.dim('default')}`
          );
          console.log(`  Saved:     ${c.dim(config.savedAt)}`);
          console.log('');
          console.log(`  ${c.dim('Stored encrypted at ~/.panguard/llm.enc')}`);
          return;
        }

        if (options.clear) {
          const removed = deleteLlmConfig();
          if (removed) {
            console.log(`  ${c.safe('LLM configuration removed.')}`);
          } else {
            console.log(`  ${c.dim('No LLM configuration to remove.')}`);
          }
          return;
        }

        if (!options.provider) {
          console.log(`  ${c.caution('--provider is required.')}`);
          console.log('');
          console.log('  Examples:');
          console.log(
            `    ${c.dim('$')} panguard config llm --provider claude --api-key sk-ant-xxx`
          );
          console.log(`    ${c.dim('$')} panguard config llm --provider openai --api-key sk-xxx`);
          console.log(`    ${c.dim('$')} panguard config llm --provider ollama`);
          console.log(`    ${c.dim('$')} panguard config llm --show`);
          console.log(`    ${c.dim('$')} panguard config llm --clear`);
          return;
        }

        const validProviders = ['claude', 'openai', 'ollama'];
        if (!validProviders.includes(options.provider)) {
          console.log(
            `  ${c.caution(`Invalid provider: ${options.provider}. Must be one of: ${validProviders.join(', ')}`)}`
          );
          return;
        }

        if (options.provider !== 'ollama' && !options.apiKey) {
          console.log(
            `  ${c.caution(`--api-key is required for provider '${options.provider}'.`)}`
          );
          return;
        }

        saveLlmConfig({
          provider: options.provider,
          apiKey: options.apiKey,
          model: options.model,
          endpoint: options.endpoint,
          savedAt: new Date().toISOString(),
        });

        console.log(`  ${c.safe('LLM configuration saved.')}`);
        console.log(`  Provider:  ${c.bold(options.provider)}`);
        if (options.apiKey) {
          console.log(
            `  API Key:   ${c.safe(options.apiKey.slice(0, 8) + '...' + options.apiKey.slice(-4))}`
          );
        }
        if (options.model) {
          console.log(`  Model:     ${c.bold(options.model)}`);
        }
        console.log('');
        console.log(`  ${c.dim('Encrypted and stored at ~/.panguard/llm.enc')}`);
        console.log(`  ${c.dim('The Guard engine will use this configuration automatically.')}`);
      }
    );

  return cmd;
}
