// src/routes/introspect.ts
import { Router, Request, Response, urlencoded } from 'express';
import { AccessToken } from '../models/AccessToken';
import { RefreshToken } from '../models/RefreshToken';
import { OAuthClient } from '../models/OAuthClient';
import { User } from '../models/User';
import { introspectTokenSchema } from '../schemas/oauth';
import jwt from 'jsonwebtoken';

const router = Router();

// Middleware для базовой аутентификации клиента (Client ID + Secret)
// Поддерживает передачу в Body (как требует RFC для этого эндпоинта часто) или Basic Auth header
const authenticateClient = async (req: Request, res: Response, next: Function) => {
  let clientId = req.body.client_id;
  let clientSecret = req.body.client_secret;

  // Проверка Basic Auth заголовка, если нет в body
  if (!clientId || !clientSecret) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
      const buff = Buffer.from(authHeader.split(' ')[1], 'base64');
      const text = buff.toString('utf-8');
      const [id, secret] = text.split(':');
      clientId = id;
      clientSecret = secret;
    }
  }

  if (!clientId || !clientSecret) {
    return res.status(401).json({ error: 'invalid_client', error_description: 'Missing credentials' });
  }

  const client = await OAuthClient.findOne({ clientId });
  if (!client || client.clientSecret !== clientSecret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // Сохраняем клиента в запросе для дальнейшего использования (опционально)
  (req as any).client = client;
  next();
};

router.post('/oauth/introspect', urlencoded({ extended: false }), authenticateClient, async (req: Request, res: Response) => {
  const parsed = introspectTokenSchema.safeParse(req.body);
  
  // Если валидация не прошла, возвращаем inactive (безопаснее, чем ошибка 400, чтобы не спамить логи при атаках)
  if (!parsed.success) {
    return res.json({ active: false });
  }

  const { token, token_type_hint } = parsed.data;
  let tokenDoc = null;
  let tokenType = '';
  let userId = null;
  let scope = '';
  let clientIdStr = '';
  let expiresAt: Date | null = null;

  // 1. Попытка найти Refresh Token
  if (!token_type_hint || token_type_hint === 'refresh_token') {
    tokenDoc = await RefreshToken.findOne({ token });
    if (tokenDoc) {
      tokenType = 'refresh_token';
      userId = tokenDoc.userId;
      scope = tokenDoc.scope || '';
      clientIdStr = tokenDoc.clientId;
      expiresAt = tokenDoc.expiresAt;
    }
  }

  // 2. Если не нашли Refresh, пробуем Access Token
  // Примечание: Для JWT access токенов мы можем сначала декодировать их, чтобы получить ID, 
  // но для строгой проверки "не отозван ли" нам всё равно нужно идти в БД.
  if (!tokenDoc && (!token_type_hint || token_type_hint === 'access_token')) {
    tokenDoc = await AccessToken.findOne({ token });
    if (tokenDoc) {
      tokenType = 'access_token';
      userId = tokenDoc.userId;
      scope = tokenDoc.scope || '';
      clientIdStr = tokenDoc.clientId;
      expiresAt = tokenDoc.expiresAt;
    }
  }

  // 3. Если токен вообще не найден в БД -> Неактивен
  if (!tokenDoc) {
    // Дополнительно: если это JWT access token, который мы не храним в БД (stateless), 
    // мы могли бы проверить подпись. Но в нашей архитектуре мы храним все токены в БД для возможности отзыва.
    // Поэтому отсутствие в БД = невалиден.
    return res.json({ active: false });
  }

  // 4. Проверка срока действия
  if (expiresAt && expiresAt < new Date()) {
    // Токен истек. Можно удалить его из БД asynchronously для чистоты, но пока просто вернем false.
    return res.json({ active: false });
  }

  // 5. Токен найден и валиден. Собираем ответ.
  const user = await User.findById(userId).select('email');
  
  const responseData: any = {
    active: true,
    scope: scope,
    client_id: clientIdStr,
    token_type: tokenType === 'access_token' ? 'Bearer' : 'refresh_token', // Упрощенно
    exp: expiresAt ? Math.floor(expiresAt.getTime() / 1000) : undefined,
    iat: expiresAt ? Math.floor((expiresAt.getTime() - 15 * 60 * 1000) / 1000) : undefined, // Примерное время выдачи
    sub: userId ? userId.toString() : undefined
  };

  if (user) {
    responseData.username = user.email;
  }

  res.json(responseData);
});

export default router;