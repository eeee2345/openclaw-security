import BrandLogo from '@/components/ui/BrandLogo';

export default function BlogLoading() {
  return (
    <div className="min-h-[60vh] flex items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="animate-pulse">
          <BrandLogo size={32} className="text-brand-sage/50" />
        </div>
        <div className="w-20 h-0.5 bg-surface-2 rounded-full overflow-hidden">
          <div className="h-full bg-brand-sage/40 rounded-full animate-[loading-bar_1.5s_ease-in-out_infinite]" />
        </div>
      </div>
    </div>
  );
}
