/**
 * Wizard Engine - Step-by-step interactive flow with navigation
 * 精靈引擎 - 逐步互動流程，支援前後導航
 *
 * Orchestrates a sequence of WizardSteps, rendering progress indicators,
 * handling back-navigation, conditional steps, and auto-detection.
 *
 * @module @panguard-ai/core/cli/wizard
 */

import { c, symbols } from './index.js';
import { promptSelect, promptText, promptConfirm } from './prompts.js';
import type { SelectOption } from './prompts.js';

type Lang = 'en' | 'zh-TW';

// ============================================================
// Types
// ============================================================

export interface WizardStep {
  readonly id: string;
  readonly title: Record<Lang, string>;
  readonly description: Record<Lang, string>;
  readonly inputType: 'select' | 'text' | 'confirm' | 'auto';
  readonly options?: readonly SelectOption[];
  readonly validate?: (value: string) => string | null;
  readonly sensitive?: boolean;
  readonly autoDetect?: () => Promise<string>;
  /** Only show this step if the dependency condition is met */
  readonly dependsOn?: {
    readonly stepId: string;
    /** If provided, step is shown only when the dependency's value is in this list */
    readonly values?: readonly string[];
  };
}

export type WizardAnswers = Record<string, string>;

// ============================================================
// Progress Rendering
// ============================================================

function renderProgress(current: number, total: number, lang: Lang): void {
  const barWidth = 24;
  const ratio = total > 0 ? current / total : 0;
  const filled = Math.round(barWidth * ratio);
  const empty = barWidth - filled;
  const percent = Math.round(ratio * 100);

  const bar = c.safe('\u2588'.repeat(filled)) + c.dim('\u2591'.repeat(empty));
  const stepLabel =
    lang === 'zh-TW' ? `\u6B65\u9A5F ${current}/${total}` : `Step ${current}/${total}`;

  console.log(`  ${c.dim(stepLabel)} ${bar} ${c.dim(`${percent}%`)}`);
  console.log('');
}

// ============================================================
// Wizard Engine
// ============================================================

export class WizardEngine {
  private steps: WizardStep[];
  private lang: Lang;
  private answers: WizardAnswers = {};

  constructor(steps: WizardStep[], lang: Lang) {
    this.steps = steps;
    this.lang = lang;
  }

  /** Get the current language (may be updated during the wizard) */
  getLang(): Lang {
    return this.lang;
  }

  /** Set language (useful after the language selection step) */
  setLang(lang: Lang): void {
    this.lang = lang;
  }

  /**
   * Run the wizard through all steps.
   * Returns collected answers, or null if the user cancelled.
   */
  async run(): Promise<WizardAnswers | null> {
    // Filter to applicable steps
    const applicableSteps = this.getApplicableSteps();
    const total = applicableSteps.length;
    let index = 0;

    while (index < total) {
      const step = applicableSteps[index]!;

      // Re-evaluate applicable steps in case answers changed
      const currentApplicable = this.getApplicableSteps();
      if (!currentApplicable.find((s) => s.id === step.id)) {
        // This step is no longer applicable, skip forward
        index++;
        continue;
      }

      // Recalculate position within current applicable steps
      const stepNum = currentApplicable.findIndex((s) => s.id === step.id) + 1;
      const stepTotal = currentApplicable.length;

      renderProgress(stepNum, stepTotal, this.lang);

      const result = await this.executeStep(step);

      if (result === null) {
        // User pressed back
        if (index > 0) {
          index--;
          // Clear previous answer
          const prevStep = applicableSteps[index]!;
          delete this.answers[prevStep.id];
        }
        continue;
      }

      this.answers[step.id] = result;

      // Special: if this is a language step, update the wizard language
      if (step.id === 'language' && (result === 'en' || result === 'zh-TW')) {
        this.lang = result;
      }

      index++;
    }

    return this.answers;
  }

  /**
   * Execute a single step based on its inputType.
   * Returns the answer string, or null for back-navigation.
   */
  private async executeStep(step: WizardStep): Promise<string | null> {
    switch (step.inputType) {
      case 'select':
        return this.executeSelect(step);
      case 'text':
        return this.executeText(step);
      case 'confirm':
        return this.executeConfirm(step);
      case 'auto':
        return this.executeAuto(step);
      default:
        return null;
    }
  }

  private async executeSelect(step: WizardStep): Promise<string | null> {
    if (!step.options || step.options.length === 0) return null;

    const result = await promptSelect({
      title: step.title,
      description: step.description,
      options: step.options,
      lang: this.lang,
      allowBack: true,
    });

    return result;
  }

  private async executeText(step: WizardStep): Promise<string | null> {
    const existing = this.answers[step.id];
    const result = await promptText({
      title: step.title,
      description: step.description,
      defaultValue: existing,
      validate: step.validate,
      sensitive: step.sensitive,
      lang: this.lang,
      allowBack: true,
    });

    return result;
  }

  private async executeConfirm(step: WizardStep): Promise<string | null> {
    const result = await promptConfirm({
      message: step.title,
      defaultValue: true,
      lang: this.lang,
    });

    return result ? 'yes' : 'no';
  }

  private async executeAuto(step: WizardStep): Promise<string | null> {
    if (!step.autoDetect) return '';

    console.log(`  ${c.heading(step.title[this.lang])}`);
    console.log(`  ${c.dim(step.description[this.lang])}`);
    console.log('');

    // Run auto-detection
    const detecting = this.lang === 'zh-TW' ? '\u5075\u6E2C\u4E2D...' : 'Detecting...';
    process.stdout.write(`  ${c.sage('\u2022')} ${detecting}`);

    try {
      const detected = await step.autoDetect();
      process.stdout.write(`\r\x1b[K`);
      console.log(`  ${symbols.pass} ${detected}`);
      console.log('');

      // Confirm the auto-detected value
      const ok = await promptConfirm({
        message: {
          en: 'Is this correct?',
          'zh-TW': '\u9019\u6B63\u78BA\u55CE\uFF1F',
        },
        defaultValue: true,
        lang: this.lang,
      });

      if (ok) return detected;

      // User said no — let them type it
      const manual = await promptText({
        title: step.title,
        lang: this.lang,
        allowBack: true,
      });
      return manual;
    } catch {
      process.stdout.write(`\r\x1b[K`);
      console.log(
        `  ${symbols.warn} ${this.lang === 'zh-TW' ? '\u5075\u6E2C\u5931\u6557' : 'Detection failed'}`
      );

      const manual = await promptText({
        title: step.title,
        lang: this.lang,
        allowBack: true,
      });
      return manual;
    }
  }

  /**
   * Filter steps based on their dependency conditions and current answers.
   */
  private getApplicableSteps(): WizardStep[] {
    return this.steps.filter((step) => {
      if (!step.dependsOn) return true;

      const depValue = this.answers[step.dependsOn.stepId];
      if (depValue === undefined) return true; // Dependency not yet answered, include step

      if (step.dependsOn.values) {
        return step.dependsOn.values.includes(depValue);
      }

      // If no specific values, just check if dependency has been answered
      return depValue !== undefined;
    });
  }
}
