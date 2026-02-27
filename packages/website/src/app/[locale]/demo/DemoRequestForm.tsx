'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Check } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const inputStyles =
  'w-full bg-surface-2 border border-border rounded-full px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors';

export default function DemoRequestForm() {
  const t = useTranslations('demoForm');

  const teamSizes = t.raw('teamSizes') as string[];

  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');
  const [form, setForm] = useState({
    name: '',
    email: '',
    company: '',
    teamSize: '',
    stack: '',
    message: '',
  });

  function update(field: string, value: string) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error('Submit failed');
      setSubmitted(true);
    } catch {
      setError(t('error'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AnimatePresence mode="wait">
      {!submitted ? (
        <motion.form
          key="form"
          onSubmit={handleSubmit}
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.3 }}
          className="space-y-4 flex-1 flex flex-col"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="demo-name" className="block text-xs text-text-tertiary mb-1.5">
                {t('labels.name')}
              </label>
              <input
                id="demo-name"
                type="text"
                required
                value={form.name}
                onChange={(e) => update('name', e.target.value)}
                placeholder={t('placeholders.name')}
                className={inputStyles}
              />
            </div>
            <div>
              <label htmlFor="demo-email" className="block text-xs text-text-tertiary mb-1.5">
                {t('labels.workEmail')}
              </label>
              <input
                id="demo-email"
                type="email"
                required
                value={form.email}
                onChange={(e) => update('email', e.target.value)}
                placeholder={t('placeholders.email')}
                className={inputStyles}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="demo-company" className="block text-xs text-text-tertiary mb-1.5">
                {t('labels.company')}
              </label>
              <input
                id="demo-company"
                type="text"
                required
                value={form.company}
                onChange={(e) => update('company', e.target.value)}
                placeholder={t('placeholders.company')}
                className={inputStyles}
              />
            </div>
            <div>
              <label htmlFor="demo-team-size" className="block text-xs text-text-tertiary mb-1.5">
                {t('labels.teamSize')}
              </label>
              <select
                id="demo-team-size"
                value={form.teamSize}
                onChange={(e) => update('teamSize', e.target.value)}
                className={`${inputStyles} appearance-none`}
              >
                <option value="">{t('placeholders.teamSize')}</option>
                {teamSizes.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="demo-stack" className="block text-xs text-text-tertiary mb-1.5">
              {t('labels.currentStack')}
            </label>
            <input
              id="demo-stack"
              type="text"
              value={form.stack}
              onChange={(e) => update('stack', e.target.value)}
              placeholder={t('placeholders.stack')}
              className={inputStyles}
            />
          </div>

          <div>
            <label htmlFor="demo-message" className="block text-xs text-text-tertiary mb-1.5">
              {t('labels.message')}
            </label>
            <textarea
              id="demo-message"
              value={form.message}
              onChange={(e) => update('message', e.target.value)}
              placeholder={t('placeholders.message')}
              rows={3}
              className={`${inputStyles} resize-none`}
            />
          </div>

          {error && <p className="text-sm text-status-alert">{error}</p>}

          <button
            type="submit"
            className="mt-auto bg-brand-sage text-surface-0 font-semibold rounded-full px-6 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] w-full text-sm"
          >
            {loading ? t('submitting') : t('submit')}
          </button>
        </motion.form>
      ) : (
        <motion.div
          key="success"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="flex-1 flex flex-col items-center justify-center text-center py-8"
        >
          <div className="w-12 h-12 rounded-full bg-status-safe/10 border border-status-safe/20 flex items-center justify-center mb-4">
            <Check className="w-6 h-6 text-status-safe" />
          </div>
          <h3 className="text-xl font-bold text-text-primary">{t('successTitle')}</h3>
          <p className="text-text-secondary mt-2 leading-relaxed text-sm max-w-sm">
            {t('successDesc')}
          </p>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
