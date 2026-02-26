import { describe, it, expect } from 'vitest';
import { getGoogleAuthUrl } from '../src/google-oauth.js';

const mockConfig = {
  clientId: 'test-client-id.apps.googleusercontent.com',
  clientSecret: 'test-secret',
  redirectUri: 'http://localhost:3000/api/auth/google/callback',
};

describe('Google OAuth', () => {
  describe('getGoogleAuthUrl', () => {
    it('should generate a valid Google auth URL', () => {
      const url = getGoogleAuthUrl(mockConfig);
      expect(url).toContain('accounts.google.com/o/oauth2/v2/auth');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('redirect_uri=');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=openid+email+profile');
    });

    it('should include state parameter when provided', () => {
      const url = getGoogleAuthUrl(mockConfig, 'my-state');
      expect(url).toContain('state=my-state');
    });

    it('should not include state parameter when not provided', () => {
      const url = getGoogleAuthUrl(mockConfig);
      expect(url).not.toContain('state=');
    });
  });
});
