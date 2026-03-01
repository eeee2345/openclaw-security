import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import BrandLogo, { BRAND_LOGO_PATHS, BRAND_LOGO_VIEWBOX } from '../../src/components/ui/BrandLogo';

describe('BrandLogo', () => {
  it('renders an SVG element', () => {
    const { container } = render(<BrandLogo />);
    const svg = container.querySelector('svg');
    expect(svg).toBeTruthy();
  });

  it('applies the given size', () => {
    const { container } = render(<BrandLogo size={48} />);
    const svg = container.querySelector('svg')!;
    expect(svg.getAttribute('width')).toBe('48');
    expect(svg.getAttribute('height')).toBe('48');
  });

  it('uses the correct viewBox', () => {
    const { container } = render(<BrandLogo />);
    const svg = container.querySelector('svg')!;
    expect(svg.getAttribute('viewBox')).toBe(BRAND_LOGO_VIEWBOX);
  });

  it('renders the correct number of paths', () => {
    const { container } = render(<BrandLogo />);
    const paths = container.querySelectorAll('path');
    expect(paths.length).toBe(BRAND_LOGO_PATHS.length);
  });

  it('applies className', () => {
    const { container } = render(<BrandLogo className="text-brand-sage" />);
    const svg = container.querySelector('svg')!;
    expect(svg.classList.contains('text-brand-sage')).toBe(true);
  });

  it('exports BRAND_LOGO_PATHS with fg and bg roles', () => {
    expect(BRAND_LOGO_PATHS.length).toBe(5);
    const roles = BRAND_LOGO_PATHS.map((p) => p.role);
    expect(roles.filter((r) => r === 'fg').length).toBe(4);
    expect(roles.filter((r) => r === 'bg').length).toBe(1);
  });

  it('uses bg color for bg-role paths', () => {
    const { container } = render(<BrandLogo bg="#FF0000" />);
    const paths = container.querySelectorAll('path');
    const bgPathIndex = BRAND_LOGO_PATHS.findIndex((p) => p.role === 'bg');
    expect(paths[bgPathIndex].getAttribute('fill')).toBe('#FF0000');
  });
});
