const express = require('express');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const OAuthClient = require('../models/OAuthClient');
const AuthorizationCode = require('../models/AuthorizationCode');
const AccessToken = require('../models/AccessToken');
const RefreshToken = require('../models/RefreshToken');
const { generateCodeChallenge } = require('../utils/crypto');
const { generateAccessToken, generateRefreshToken } = require('../utils/tokens');
const router = express.Router();

// Authorization Endpoint
router.get('/authorize', async (req, res) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope = 'profile',
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  if (response_type !== 'code') {
    return res.status(400).send('Unsupported response type');
  }

  const client = await OAuthClient.findOne({ clientId: client_id });
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send('Invalid client or redirect URI');
  }

  if (!req.session.userId) {
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  // Показываем экран согласия
  res.send(`
    <h2>${client.name} запрашивает доступ к вашему аккаунту</h2>
    <p>Scope: ${scope}</p>
    <form method="POST">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="scope" value="${scope}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
      <button name="approve" value="1">Разрешить</button>
      <button type="button" onclick="window.close()">Отмена</button>
    </form>
  `);
});

// Обработка согласия
router.post('/authorize', async (req, res) => {
  const {
    client_id,
    redirect_uri,
    scope,
    state,
    approve,
    code_challenge,
    code_challenge_method
  } = req.body;

  if (!approve) {
    const url = new URL(redirect_uri);
    url.searchParams.append('error', 'access_denied');
    if (state) url.searchParams.append('state', state);
    return res.redirect(url.toString());
  }

  const code = uuidv4();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 мин

  const authCode = new AuthorizationCode({
    code,
    clientId: client_id,
    userId: req.session.userId,
    redirectUri: redirect_uri,
    scope,
    expiresAt,
    challenge: code_challenge,
    challengeMethod: code_challenge_method
  });

  await authCode.save();

  const url = new URL(redirect_uri);
  url.searchParams.append('code', code);
  if (state) url.searchParams.append('state', state);
  res.redirect(url.toString());
});

// Token Endpoint
router.post('/token', express.urlencoded({ extended: false }), async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token, code_verifier } = req.body;

  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri || !client_id) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    const authCode = await AuthorizationCode.findOne({ code });
    if (!authCode || authCode.expiresAt < new Date() || authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // PKCE проверка
    if (authCode.challenge) {
      if (!code_verifier) return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code_verifier' });
      const expectedChallenge = generateCodeChallenge(code_verifier);
      if (expectedChallenge !== authCode.challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
    }

    // Удаляем использованный код
    await AuthorizationCode.deleteOne({ _id: authCode._id });

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
      expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000) // 30 дней
    }).save();

    res.json({
      access_token: accessTokenStr,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshTokenStr,
      scope: authCode.scope
    });

  } else if (grant_type === 'refresh_token') {
    if (!refresh_token || !client_id) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    const refreshTokenDoc = await RefreshToken.findOne({ token: refresh_token, clientId: client_id });
    if (!refreshTokenDoc || refreshTokenDoc.expiresAt < new Date()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // Инвалидируем старый refresh token
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
router.get('/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }

  const token = authHeader.substring(7);
  const jwt = require('jsonwebtoken');
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub).select('name email');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ sub: payload.sub, name: user.name, email: user.email });
  } catch (e) {
    res.status(401).json({ error: 'invalid_token' });
  }
});

module.exports = router;