import { Document, model, Schema, Types } from 'mongoose';

export interface IAuthorizationCode extends Document {
  code: string;
  clientId: string;
  userId: Types.ObjectId;
  redirectUri: string;
  scope: string; // Может содержать "openid profile email"
  expiresAt: Date;
  challenge?: string;
  challengeMethod?: string;
  nonce?: string; // <--- Добавлено для OIDC
}

const codeSchema = new Schema<IAuthorizationCode>({
  code: { type: String, required: true, unique: true },
  clientId: { type: String, required: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  redirectUri: { type: String, required: true },
  scope: { type: String, required: true }, // Теперь обязательно
  expiresAt: { type: Date, required: true },
  challenge: String,
  challengeMethod: String,
  nonce: String // <--- Добавлено
});

codeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const AuthorizationCode = model<IAuthorizationCode>('AuthorizationCode', codeSchema);