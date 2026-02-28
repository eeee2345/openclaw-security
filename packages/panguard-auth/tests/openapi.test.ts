import { describe, it, expect } from 'vitest';
import { generateOpenApiSpec, generateSwaggerHtml } from '../src/openapi.js';

describe('OpenAPI', () => {
  describe('generateOpenApiSpec', () => {
    const spec = generateOpenApiSpec('https://api.panguard.ai');

    it('should return valid OpenAPI 3.0 structure', () => {
      expect(spec['openapi']).toBe('3.0.3');
      expect(spec['info']).toBeDefined();
      expect(spec['paths']).toBeDefined();
      expect(spec['components']).toBeDefined();
    });

    it('should include server URL', () => {
      const servers = spec['servers'] as Array<{ url: string }>;
      expect(servers[0]!.url).toBe('https://api.panguard.ai');
    });

    it('should use provided baseUrl', () => {
      const localSpec = generateOpenApiSpec('http://localhost:3000');
      const servers = localSpec['servers'] as Array<{ url: string }>;
      expect(servers[0]!.url).toBe('http://localhost:3000');
    });

    it('should include all required tags', () => {
      const tags = (spec['tags'] as Array<{ name: string }>).map((t) => t.name);
      expect(tags).toContain('Auth');
      expect(tags).toContain('Account');
      expect(tags).toContain('Billing');
      expect(tags).toContain('Usage');
      expect(tags).toContain('Admin');
      expect(tags).toContain('Threat Cloud');
    });

    it('should define bearer auth security scheme', () => {
      const components = spec['components'] as Record<string, unknown>;
      const schemes = components['securitySchemes'] as Record<
        string,
        { type: string; scheme: string }
      >;
      expect(schemes['bearerAuth']).toBeDefined();
      expect(schemes['bearerAuth']!.type).toBe('http');
      expect(schemes['bearerAuth']!.scheme).toBe('bearer');
    });

    it('should include core auth endpoints', () => {
      const paths = spec['paths'] as Record<string, unknown>;
      expect(paths['/api/auth/register']).toBeDefined();
      expect(paths['/api/auth/login']).toBeDefined();
      expect(paths['/api/auth/logout']).toBeDefined();
      expect(paths['/api/auth/me']).toBeDefined();
    });

    it('should include billing endpoints', () => {
      const paths = spec['paths'] as Record<string, unknown>;
      expect(paths['/api/billing/checkout']).toBeDefined();
      expect(paths['/api/billing/portal']).toBeDefined();
      expect(paths['/api/billing/status']).toBeDefined();
      expect(paths['/api/billing/webhook']).toBeDefined();
    });

    it('should include usage endpoints', () => {
      const paths = spec['paths'] as Record<string, unknown>;
      expect(paths['/api/usage']).toBeDefined();
      expect(paths['/api/usage/limits']).toBeDefined();
      expect(paths['/api/usage/check']).toBeDefined();
      expect(paths['/api/usage/record']).toBeDefined();
    });

    it('should include GDPR endpoints', () => {
      const paths = spec['paths'] as Record<string, unknown>;
      expect(paths['/api/auth/delete-account']).toBeDefined();
      expect(paths['/api/auth/export-data']).toBeDefined();
    });

    it('should include TOTP endpoints', () => {
      const paths = spec['paths'] as Record<string, unknown>;
      expect(paths['/api/auth/totp/setup']).toBeDefined();
      expect(paths['/api/auth/totp/verify']).toBeDefined();
      expect(paths['/api/auth/totp/disable']).toBeDefined();
      expect(paths['/api/auth/totp/status']).toBeDefined();
    });

    it('should include Threat Cloud endpoints', () => {
      const paths = spec['paths'] as Record<string, unknown>;
      expect(paths['/api/threats']).toBeDefined();
      expect(paths['/api/iocs']).toBeDefined();
      expect(paths['/api/stats']).toBeDefined();
      expect(paths['/api/rules']).toBeDefined();
      expect(paths['/api/feeds/ip-blocklist']).toBeDefined();
      expect(paths['/api/feeds/domain-blocklist']).toBeDefined();
    });

    it('should include health endpoint', () => {
      const paths = spec['paths'] as Record<string, unknown>;
      expect(paths['/health']).toBeDefined();
    });

    it('should define reusable schemas', () => {
      const components = spec['components'] as Record<string, unknown>;
      const schemas = components['schemas'] as Record<string, unknown>;
      expect(schemas['Error']).toBeDefined();
      expect(schemas['User']).toBeDefined();
      expect(schemas['UsageSummary']).toBeDefined();
      expect(schemas['QuotaCheck']).toBeDefined();
    });

    it('should be valid JSON', () => {
      const json = JSON.stringify(spec);
      expect(() => JSON.parse(json)).not.toThrow();
    });
  });

  describe('generateSwaggerHtml', () => {
    const html = generateSwaggerHtml('/openapi.json');

    it('should return valid HTML', () => {
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('</html>');
    });

    it('should include Swagger UI CDN scripts', () => {
      expect(html).toContain('swagger-ui-dist@5/swagger-ui.css');
      expect(html).toContain('swagger-ui-dist@5/swagger-ui-bundle.js');
    });

    it('should reference the spec URL', () => {
      expect(html).toContain("url: '/openapi.json'");
    });

    it('should include Panguard branding', () => {
      expect(html).toContain('PANGUARD');
      expect(html).toContain('API Documentation');
    });

    it('should use custom spec URL', () => {
      const customHtml = generateSwaggerHtml('https://api.panguard.ai/openapi.json');
      expect(customHtml).toContain("url: 'https://api.panguard.ai/openapi.json'");
    });
  });
});
