import { Document, model, Schema, Types } from 'mongoose';

export interface IAccessToken extends Document {
  token: string;
  clientId: string;
  userId: Types.ObjectId;
  scope?: string;
  expiresAt: Date;
}

const tokenSchema = new Schema<IAccessToken>({
  token: { type: String, required: true, unique: true },
  clientId: { type: String, required: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  scope: String,
  expiresAt: { type: Date, required: true }
});

tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const AccessToken = model<IAccessToken>('AccessToken', tokenSchema);