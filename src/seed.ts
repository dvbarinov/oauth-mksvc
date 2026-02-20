// src/seed.ts
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { User } from './models/User';
import { OAuthClient } from './models/OAuthClient';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/oauth2db';

const seedDatabase = async () => {
  try {
    // 1. Подключение к MongoDB
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // 2. Очистка старых данных (ОСТОРОЖНО: удаляет все данные!)
    await User.deleteMany({});
    await OAuthClient.deleteMany({});
    console.log('🧹 Cleared existing data');

    // 3. Создание Администратора
    const adminPassword = 'Admin123!';
    const adminHash = await User.hashPassword(adminPassword);
    const admin = await User.create({
      name: 'Super Admin',
      email: 'admin@localhost.com',
      passwordHash: adminHash,
      role: 'admin' // 🔑 Ключевое поле: роль админа
    });
    console.log('👤 Admin created:', admin.email);

    // 4. Создание Обычного пользователя
    const userPassword = 'User123!';
    const userHash = await User.hashPassword(userPassword);
    const user = await User.create({
      name: 'Test User',
      email: 'user@localhost.com',
      passwordHash: userHash,
      role: 'user'
    });
    console.log('👤 User created:', user.email);

    // 5. Создание тестового OAuth-приложения (Клиента)
    // Это НЕ человек, а программа (например, ваш фронтенд или мобильное приложение)
    const clientId = uuidv4();
    const clientSecret = uuidv4();
    
    const oauthClient = await OAuthClient.create({
      clientId,
      clientSecret,
      name: 'My Test Application',
      redirectUris: [
        'http://localhost:3000/callback',
        'http://localhost:3000/auth/callback'
      ],
      scopes: ['openid', 'profile', 'email'],
      isConfidential: false, // true для серверных приложений, false для SPA/Mobile
      owner: admin._id // Принадлежит админу
    });
    console.log('📱 OAuth Client created');

    // 6. Финальный вывод с учетными данными
    console.log('\n' + '='.repeat(50));
    console.log('🎉 SEED COMPLETED SUCCESSFULLY!');
    console.log('='.repeat(50));
    console.log('\n📋 CREDENTIALS (Сохраните это!):\n');
    
    console.log('🔐 ADMIN ACCOUNT:');
    console.log(`   Email:    ${admin.email}`);
    console.log(`   Password: ${adminPassword}`);
    console.log(`   Role:     admin`);
    
    console.log('\n🔐 USER ACCOUNT:');
    console.log(`   Email:    ${user.email}`);
    console.log(`   Password: ${userPassword}`);
    console.log(`   Role:     user`);
    
    console.log('\n📱 OAUTH CLIENT (Application):');
    console.log(`   Client ID:     ${clientId}`);
    console.log(`   Client Secret: ${clientSecret}`);
    console.log(`   Redirect URI:  ${oauthClient.redirectUris[0]}`);
    console.log('\n⚠️  WARNING: Client Secret is shown ONLY ONCE!');
    console.log('='.repeat(50) + '\n');

    // Завершение работы
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
    process.exit(0);

  } catch (error) {
    console.error('❌ Seed failed:', error);
    process.exit(1);
  }
};

seedDatabase();