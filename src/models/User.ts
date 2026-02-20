import { Document, Model, model, Schema } from 'mongoose';
import bcrypt from 'bcrypt';

// 1. Интерфейс документа (экземпляр пользователя)
export interface IUser extends Document {
  email: string;
  passwordHash: string;
  name?: string;
  role: 'user' | 'admin';
  comparePassword(password: string): Promise<boolean>;
}

// 2. Интерфейс модели (статические методы)
interface IUserModel extends Model<IUser> {
  hashPassword(password: string): Promise<string>;
}

// 3. Создаем схему с явными типами <IUser, IUserModel>
const userSchema = new Schema<IUser, IUserModel>({
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

// 4. Явно приводим тип модели к IUserModel
export const User = model<IUser, IUserModel>('User', userSchema);