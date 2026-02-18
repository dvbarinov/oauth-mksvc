import { z } from 'zod';

// Для /oauth/authorize (GET)
export const authorizeQuerySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  response_type: z.literal('code'),
  scope: z.string().optional().default('profile'),
  state: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(['S256', 'plain']).optional(),
  nonce: z.string().optional() // <--- Добавлено для OIDC
});

// Для POST /oauth/authorize (согласие)
export const authorizeConsentBodySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().optional().default('profile'),
  state: z.string().optional(),
  approve: z.enum(['1']),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(['S256', 'plain']).optional(),
  nonce: z.string().optional() // <--- Добавлено для OIDC
});

// Для POST /oauth/token
export const tokenRequestBodySchema = z.object({
  grant_type: z.enum(['authorization_code', 'refresh_token']),
  // authorization_code flow
  code: z.string().optional(),
  redirect_uri: z.string().url().optional(),
  client_id: z.string().min(1),
  // refresh_token flow
  refresh_token: z.string().optional(),
  // PKCE
  code_verifier: z.string().optional()
  // nonce не передается в /token, он уже зашит в коде авторизации
}).refine(
  (data) => {
    if (data.grant_type === 'authorization_code') {
      return data.code && data.redirect_uri;
    }
    if (data.grant_type === 'refresh_token') {
      return data.refresh_token;
    }
    return true;
  },
  {
    message: 'Для authorization_code требуются code и redirect_uri; для refresh_token — refresh_token',
    path: ['grant_type']
  }
);

// POST /oauth/revoke
export const revokeTokenSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
  client_id: z.string().min(1),
  client_secret: z.string().min(1)
});

// POST /oauth/introspect
export const introspectTokenSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional()
});
