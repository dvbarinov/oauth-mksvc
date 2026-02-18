import { Router, Request, Response } from 'express';
import { openidConfigurationSchema, OpenIDConfiguration } from '../schemas/oidc';

const router = Router();

// Helper to get base URL dynamically or from env
const getBaseUrl = (req: Request): string => {
  // В продакшене лучше использовать process.env.ISSUER_URL
  // Например: https://auth.myapp.com
  const protocol = req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
};

router.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
  const baseUrl = process.env.ISSUER_URL || getBaseUrl(req);

  const config: OpenIDConfiguration = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`, // Требуется для проверки подписи JWT
    response_types_supported: ['code'], // Поддерживаем только Authorization Code
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'], // Укажите те, что реально используете, убран 'HS256'
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    scopes_supported: ['openid', 'profile', 'email'], // Стандартные OIDC scope + ваши
    claims_supported: ['sub', 'name', 'email', 'email_verified'],
    revocation_endpoint: `${baseUrl}/oauth/revoke`, // <--- Добавлено
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
};

  // Валидация перед отправкой (защита от ошибок конфигурации)
  const parsed = openidConfigurationSchema.safeParse(config);
  if (!parsed.success) {
    console.error('OIDC Config validation failed:', parsed.error);
    return res.status(500).json({ error: 'Server configuration error' });
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600'); // Кэширование на 1 час
  res.json(parsed.data);
});

export default router;