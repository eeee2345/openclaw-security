"use client";

import { useEffect } from "react";
import { RefreshCw, ArrowLeft } from "lucide-react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[page-error]", error);
  }, [error]);

  return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center px-6">
      <div className="max-w-md w-full text-center">
        <div className="w-12 h-12 rounded-full bg-status-alert/10 flex items-center justify-center mx-auto mb-6">
          <span className="text-status-alert text-xl font-bold">!</span>
        </div>

        <h1 className="text-2xl font-bold text-text-primary mb-3">
          Something went wrong
        </h1>
        <p className="text-text-secondary text-sm leading-relaxed mb-8">
          An unexpected error occurred. Please try again or go back to the homepage.
        </p>

        <div className="flex gap-3 justify-center">
          <button
            onClick={reset}
            className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-6 py-3 hover:bg-brand-sage-light transition-colors active:scale-[0.98]"
          >
            <RefreshCw className="w-4 h-4" />
            Try again
          </button>
          <a
            href="/"
            className="inline-flex items-center gap-2 border border-border text-text-secondary font-semibold text-sm rounded-full px-6 py-3 hover:text-text-primary hover:border-brand-sage transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Home
          </a>
        </div>
      </div>
    </div>
  );
}
