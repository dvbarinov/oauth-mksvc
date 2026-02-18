import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import { IUser } from '../models/User';

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
  return jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: '15m' });
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

  // Используем тот же секрет, что и для Access Token (для простоты)
  // В продакшене лучше использовать отдельный ключ или RS256
  return jwt.sign(payload, process.env.JWT_SECRET!);
};