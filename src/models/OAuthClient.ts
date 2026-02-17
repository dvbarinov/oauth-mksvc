import { Document, model, Schema, Types } from 'mongoose';

export interface IOAuthClient extends Document {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  name: string;
  owner: Types.ObjectId;
  isConfidential: boolean;
  scopes: string[];
}

const clientSchema = new Schema<IOAuthClient>({
  clientId: { type: String, required: true, unique: true },
  clientSecret: { type: String, required: true },
  redirectUris: [{ type: String, required: true }],
  name: { type: String, required: true },
  owner: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  isConfidential: { type: Boolean, default: true },
  scopes: [String]
}, { timestamps: true });

export const OAuthClient = model<IOAuthClient>('OAuthClient', clientSchema);