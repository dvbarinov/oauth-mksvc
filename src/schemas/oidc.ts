// src/schemas/oidc.ts
import { z } from 'zod';

export const openidConfigurationSchema = z.object({
  issuer: z.string().url(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  userinfo_endpoint: z.string().url(),
  jwks_uri: z.string().url(), // Пока заглушка, если нет JWKS
  response_types_supported: z.array(z.string()),
  subject_types_supported: z.array(z.string()),
  id_token_signing_alg_values_supported: z.array(z.string()),
  grant_types_supported: z.array(z.string()),
  token_endpoint_auth_methods_supported: z.array(z.string()),
  scopes_supported: z.array(z.string()).optional(),
  claims_supported: z.array(z.string()).optional()
});

export type OpenIDConfiguration = z.infer<typeof openidConfigurationSchema>;