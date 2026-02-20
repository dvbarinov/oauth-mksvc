// src/routes/developer.ts
import { Router, Request, Response } from 'express';
import { OAuthClient } from '../models/OAuthClient';
import { requireAuth } from '../middleware/requireAuth'; // Обычная проверка логина (не админ!)
import { v4 as uuidv4 } from 'uuid';
import { getUserId } from '../utils/session';
import { z } from 'zod';

const router = Router();

// Доступ есть у любого залогиненного пользователя
router.use(requireAuth);

const appSchema = z.object({
  name: z.string().min(1).max(100),
  redirectUris: z.array(z.string().url()).min(1),
  scopes: z.array(z.string()).optional().default(['openid', 'profile']),
  isConfidential: z.boolean().optional().default(false) // По умолчанию false для SPA/Mobile
});

// --- GET /developer/apps ---
// Показать ТОЛЬКО мои приложения
router.get('/apps', async (req: Request, res: Response) => {
  try {
    const userId = getUserId(req);
    // Фильтр по владельцу!
    const apps = await OAuthClient.find({ owner: userId }).select('-clientSecret');
    
    res.json({
      count: apps.length,
      clients: apps.map(a => ({
        ...a.toObject(),
        hasSecret: !!a.clientSecret,
        secretPreview: a.clientSecret ? a.clientSecret.substring(0, 6) + '...' : null
      }))
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch apps' });
  }
});

// --- POST /developer/apps ---
// Создать МОЕ приложение
router.post('/apps', async (req: Request, res: Response) => {
  const parsed = appSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input', details: parsed.error.format() });
  }

  const { name, redirectUris, scopes, isConfidential } = parsed.data;
  const ownerId = getUserId(req); // Берем ID текущего юзера

  const clientId = uuidv4();
  const clientSecret = uuidv4();

  try {
    const app = new OAuthClient({
      clientId,
      clientSecret,
      redirectUris,
      name,
      owner: ownerId, // 🔑 Привязываем к создателю
      isConfidential,
      scopes
    });

    await app.save();

    res.status(201).json({
      message: 'Application created',
      client: {
        clientId,
        clientSecret, // Показываем секрет только сейчас
        name
      },
      warning: 'Save your clientSecret! It won\'t be shown again.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create application' });
  }
});

// --- POST /developer/apps/:id/rotate-secret ---
// Сбросить секрет ТОЛЬКО если я владелец
router.post('/apps/:id/rotate-secret', async (req: Request, res: Response) => {
  const userId = getUserId(req);
  
  try {
    // Ищем приложение, которое принадлежит ИМЕННО этому юзеру
    const app = await OAuthClient.findOne({ _id: req.params.id, owner: userId });
    
    if (!app) {
      // Если не нашли, то ли приложения нет, ли оно чужое. Не раскрываем деталей.
      return res.status(404).json({ error: 'Application not found or access denied' });
    }

    const newSecret = uuidv4();
    app.clientSecret = newSecret;
    await app.save();

    res.json({
      message: 'Secret rotated',
      client: { clientId: app.clientId, clientSecret: newSecret }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to rotate secret' });
  }
});

// --- DELETE /developer/apps/:id ---
// Удалить ТОЛЬКО своё приложение
router.delete('/apps/:id', async (req: Request, res: Response) => {
  const userId = getUserId(req);
  
  try {
    const result = await OAuthClient.deleteOne({ _id: req.params.id, owner: userId });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Application not found or access denied' });
    }
    
    res.json({ message: 'Application deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

export default router;