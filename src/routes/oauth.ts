import { Router, Request, Response, urlencoded } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { User } from '../models/User';
import { OAuthClient } from '../models/OAuthClient';
import { AuthorizationCode } from '../models/AuthorizationCode';
import { AccessToken } from '../models/AccessToken';
import { RefreshToken } from '../models/RefreshToken';
import { generateCodeChallenge } from '../utils/crypto';
import { generateAccessToken, generateIdToken, generateRefreshToken } from '../utils/tokens';
import jwt from 'jsonwebtoken';
import { getUserId } from '../utils/session';
import { authorizeConsentBodySchema, authorizeQuerySchema, tokenRequestBodySchema } from '../schemas/oauth';

const router = Router();

// Authorization Endpoint
router.get('/authorize', async (req: Request, res: Response) => {
  const parsed = authorizeQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_request', details: parsed.error.format() });
  }

  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    code_challenge,
    code_challenge_method
  } = parsed.data;

  const client = await OAuthClient.findOne({ clientId: client_id });
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send('Invalid client or redirect URI');
  }

  if (!getUserId(req)) {
    const originalUrl = encodeURIComponent(req.originalUrl);
    return res.redirect(`/auth/login?redirect=${originalUrl}`);
  }

  res.send(`
    <h2>${client.name} запрашивает доступ к вашему аккаунту</h2>
    <p>Scope: ${scope}</p>
    <form method="POST">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="scope" value="${scope}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="nonce" value="${req.query.nonce || ''}"> 
      <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
      <button name="approve" value="1">Разрешить</button>
      <button type="button" onclick="window.close()">Отмена</button>
    </form>
  `);
});

// Consent form handler / Обработка согласия
router.post('/authorize', async (req: Request, res: Response) => {
  const parsed = authorizeConsentBodySchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_request', details: parsed.error.format() });
  }

  const {
    client_id,
    redirect_uri,
    scope,
    state,
    approve,
    code_challenge,
    code_challenge_method,
    nonce
  } = parsed.data;

  // ... логика согласия ...
  if (!approve) {
    const url = new URL(redirect_uri);
    url.searchParams.append('error', 'access_denied');
    if (state) url.searchParams.append('state', state);
    return res.redirect(url.toString());
  }

  const code = uuidv4();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  const authCode = new AuthorizationCode({
    code,
    clientId: client_id,
    userId: getUserId(req),
    redirectUri: redirect_uri,
    scope,
    expiresAt,
    challenge: code_challenge,
    challengeMethod: code_challenge_method,
    nonce: nonce || undefined // Сохраняем nonce (упрощенно берем из body)
    // Примечание: nonce приходит в query при GET и передается в hidden input при POST
  });

  await authCode.save();

  const url = new URL(redirect_uri);
  url.searchParams.append('code', code);
  if (state) url.searchParams.append('state', state);
  res.redirect(url.toString());
});

// Token Endpoint
router.post('/token', urlencoded({ extended: false }), async (req: Request, res: Response) => {
  const parsed = tokenRequestBodySchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Validation failed',
      details: parsed.error.format() //ТОЛЬКО ДЛЯ DEV MODE!!!
    });
  }

  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    refresh_token,
    code_verifier
  } = parsed.data;

  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri || !client_id) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    const authCode = await AuthorizationCode.findOne({ code });
    if (
      !authCode ||
      authCode.expiresAt < new Date() ||
      authCode.clientId !== client_id ||
      authCode.redirectUri !== redirect_uri
    ) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // PKCE
    if (authCode.challenge) {
      if (!code_verifier) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code_verifier' });
      }
      const expectedChallenge = generateCodeChallenge(code_verifier);
      if (expectedChallenge !== authCode.challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
    }

    await AuthorizationCode.deleteOne({ _id: authCode._id });

    const user = await User.findById(authCode.userId);
    if (!user) {
      return res.status(500).json({ error: 'server_error', error_description: 'User not found' });
    }

    const accessTokenStr = generateAccessToken({
      sub: authCode.userId.toString(),
      client_id: authCode.clientId,
      scope: authCode.scope
    });

    const refreshTokenStr = generateRefreshToken();
    const now = new Date();

    await new AccessToken({
      token: accessTokenStr,
      clientId: authCode.clientId,
      userId: authCode.userId,
      scope: authCode.scope,
      expiresAt: new Date(now.getTime() + 15 * 60 * 1000)
    }).save();

    await new RefreshToken({
      token: refreshTokenStr,
      clientId: authCode.clientId,
      userId: authCode.userId,
      scope: authCode.scope,
      expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)
    }).save();

    let idToken: string | undefined;

    const scopes = authCode.scope.split(' ');
    if (scopes.includes('openid')) {
      idToken = generateIdToken(user, authCode.clientId, authCode.nonce);
    }

    const responseBody: any = {
      access_token: accessTokenStr,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshTokenStr,
      scope: authCode.scope
    };

    if (idToken) {
      responseBody.id_token = idToken;
    }

    res.json(responseBody);

  } else if (grant_type === 'refresh_token') {
    if (!refresh_token || !client_id) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    const refreshTokenDoc = await RefreshToken.findOne({ token: refresh_token, clientId: client_id });
    if (!refreshTokenDoc || refreshTokenDoc.expiresAt < new Date()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    await RefreshToken.deleteOne({ _id: refreshTokenDoc._id });

    const newAccessToken = generateAccessToken({
      sub: refreshTokenDoc.userId.toString(),
      client_id: refreshTokenDoc.clientId,
      scope: refreshTokenDoc.scope
    });

    const newRefreshToken = generateRefreshToken();
    const now = new Date();

    await new AccessToken({
      token: newAccessToken,
      clientId: refreshTokenDoc.clientId,
      userId: refreshTokenDoc.userId,
      scope: refreshTokenDoc.scope,
      expiresAt: new Date(now.getTime() + 15 * 60 * 1000)
    }).save();

    await new RefreshToken({
      token: newRefreshToken,
      clientId: refreshTokenDoc.clientId,
      userId: refreshTokenDoc.userId,
      scope: refreshTokenDoc.scope,
      expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)
    }).save();

    res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: newRefreshToken,
      scope: refreshTokenDoc.scope
    });

  } else {
    res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

// UserInfo Endpoint
router.get('/userinfo', async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }

  const token = authHeader.substring(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as { sub: string };
    const user = await User.findById(payload.sub).select('name email');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ sub: payload.sub, name: user.name, email: user.email });
  } catch (e) {
    res.status(401).json({ error: 'invalid_token' });
  }
});

export default router;