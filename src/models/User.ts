import { Document, model, Schema } from 'mongoose';
import bcrypt from 'bcrypt';

export interface IUser extends Document {
  email: string;
  passwordHash: string;
  name?: string;
  role: 'user' | 'admin';
  comparePassword(password: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  name: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' } 
}, { timestamps: true });

userSchema.methods.comparePassword = async function (password: string): Promise<boolean> {
  return await bcrypt.compare(password, this.passwordHash);
};

userSchema.statics.hashPassword = async function (password: string): Promise<string> {
  return await bcrypt.hash(password, 12);
};

export const User = model<IUser>('User', userSchema);