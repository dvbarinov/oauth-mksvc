import { Router, Request, Response, urlencoded } from 'express';
import { AccessToken } from '../models/AccessToken';
import { RefreshToken } from '../models/RefreshToken';
import { OAuthClient } from '../models/OAuthClient';
import { revokeTokenSchema } from '../schemas/oauth';

const router = Router();

router.post('/oauth/revoke', urlencoded({ extended: false }), async (req: Request, res: Response) => {
  // 1. Валидация входных данных
  const parsed = revokeTokenSchema.safeParse(req.body);
  if (!parsed.success) {
    // RFC 7009: ошибки валидации могут возвращать 400
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid parameters' });
  }

  const { token, token_type_hint, client_id, client_secret } = parsed.data;

  // 2. Аутентификация клиента
  // Проверяем существование клиента и секрет
  const client = await OAuthClient.findOne({ clientId: client_id });
  if (!client || client.clientSecret !== client_secret) {
    // Важно: не раскрывать, что именно неверно (клиент или секрет)
    return res.status(401).json({ error: 'invalid_client' });
  }

  // 3. Попытка отзыва токена
  let revoked = false;

  // Если подсказка есть или мы проверяем refresh_token
  if (!token_type_hint || token_type_hint === 'refresh_token') {
    const result = await RefreshToken.deleteOne({ token, clientId: client_id });
    if (result.deletedCount > 0) revoked = true;
  }

  // Если еще не отозван и подсказка есть или мы проверяем access_token
  if (!revoked && (!token_type_hint || token_type_hint === 'access_token')) {
    const result = await AccessToken.deleteOne({ token, clientId: client_id });
    if (result.deletedCount > 0) revoked = true;
  }

  // 4. Ответ
  // RFC 7009: Если токен не найден, сервер все равно ДОЛЖЕН вернуть 200 OK.
  // Это предотвращает атаку перебором (enumeration attack), когда злоумышленник пытается угадать valid токены.
  res.status(200).send(''); // Пустое тело с статусом 200
});

export default router;