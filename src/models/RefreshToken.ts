import { Document, model, Schema, Types } from 'mongoose';

export interface IRefreshToken extends Document {
  token: string;
  clientId: string;
  userId: Types.ObjectId;
  scope?: string;
  expiresAt: Date;
}

const refreshTokenSchema = new Schema<IRefreshToken>({
  token: { type: String, required: true, unique: true },
  clientId: { type: String, required: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  scope: String,
  expiresAt: { type: Date, required: true }
});

refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const RefreshToken = model<IRefreshToken>('RefreshToken', refreshTokenSchema);