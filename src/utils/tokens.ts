import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import { IUser } from '../models/User';
import { getPrivateKey } from './keys';

dotenv.config();

interface IdTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  nonce?: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
}

export const generateAccessToken = (payload: object): string => {
  // Access token тоже можно подписывать RS256, но пока оставим HS256 для внутренней коммуникации,
  // либо тоже переведем на RS256 по желанию. Для OIDC критичен именно id_token.
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not defined');
  
  return jwt.sign(payload, secret, { expiresIn: '15m' });
};

export const generateRefreshToken = (): string => {
  return uuidv4();
};

export const generateIdToken = (
  user: IUser,
  clientId: string,
  nonce?: string
): string => {
  const now = Math.floor(Date.now() / 1000);
  const privateKeyPem = getPrivateKey();
  console.log("Key in PEM: ", privateKeyPem)

  if (!privateKeyPem) {
    throw new Error('Private key not initialized');
  }

  const payload: IdTokenPayload = {
    iss: process.env.ISSUER_URL || 'http://localhost:3001', // Issuer
    sub: user._id.toString(),                               // Subject (User ID)
    aud: clientId,                                          // Audience (Client ID)
    exp: now + 3600,                                        // Expires in 1 hour
    iat: now,                                               // Issued At
    nonce: nonce,                                           // Nonce (если был)
    // Стандартные claims (можно расширить в зависимости от scope)
    name: user.name,
    email: user.email,
    email_verified: false // Пока false, можно добавить поле в модель User
  };

  // Подписываем через RS256 с указанием kid (Key ID)
  // Явно указываем тип опций, чтобы TypeScript понял структуру
  const options: SignOptions = {
    algorithm: 'RS256',
    //expiresIn: '1h',
    header: {
      kid: 'oauth-server-key-1', // Должен совпадать с kid в JWKS
      alg: 'RS256' // <--- ОБЯЗАТЕЛЬНО: добавляем alg в заголовок
    }
  };

  // Передаем ключ как строку (PEM формат), typescript должен принять это через перегрузку
  // Если ошибка сохранится, обернем ключ в Buffer
  return jwt.sign(payload, privateKeyPem, options);
};