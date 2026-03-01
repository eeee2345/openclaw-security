'use client';

import { RefreshCw, ArrowLeft } from 'lucide-react';

export default function BlogPostError({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="min-h-[60vh] flex items-center justify-center px-6">
      <div className="max-w-sm w-full text-center">
        <div className="w-10 h-10 rounded-full bg-status-alert/10 flex items-center justify-center mx-auto mb-4">
          <span className="text-status-alert text-lg font-bold">!</span>
        </div>
        <h2 className="text-xl font-bold text-text-primary mb-2">Post Not Found</h2>
        <p className="text-text-secondary text-sm mb-6">
          This blog post could not be loaded. It may have been removed.
        </p>
        <div className="flex gap-3 justify-center">
          <button
            onClick={reset}
            className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-2.5 hover:bg-brand-sage-light transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Retry
          </button>
          <a
            href="/blog"
            className="inline-flex items-center gap-2 border border-border text-text-secondary text-sm rounded-full px-5 py-2.5 hover:text-text-primary transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            All Posts
          </a>
        </div>
      </div>
    </div>
  );
}
