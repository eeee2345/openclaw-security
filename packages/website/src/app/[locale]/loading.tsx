import BrandLogo from '@/components/ui/BrandLogo';

export default function Loading() {
  return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <div className="animate-pulse">
          <BrandLogo size={40} className="text-brand-sage/50" />
        </div>
        <div className="w-24 h-0.5 bg-surface-2 rounded-full overflow-hidden">
          <div className="h-full bg-brand-sage/40 rounded-full animate-[loading-bar_1.5s_ease-in-out_infinite]" />
        </div>
      </div>
    </div>
  );
}
