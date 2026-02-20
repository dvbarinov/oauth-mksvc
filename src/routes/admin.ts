// src/routes/admin.ts
import { Router, Request, Response } from 'express';
import { OAuthClient } from '../models/OAuthClient';
import { requireAdmin } from '../middleware/requireAdmin';
import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';

const router = Router();

// Все роуты защищены требованием прав админа
router.use(requireAdmin);

// Схема для создания/обновления
const clientSchema = z.object({
  name: z.string().min(1).max(100),
  redirectUris: z.array(z.string().url()).min(1),
  scopes: z.array(z.string()).optional().default(['openid', 'profile']),
  isConfidential: z.boolean().optional().default(true)
});

// --- GET /admin/clients ---
// Список всех клиентов. Секреты НЕ возвращаем (или показываем хэш/маску)
router.get('/clients', async (req: Request, res: Response) => {
  try {
    const clients = await OAuthClient.find().select('-clientSecret'); // Исключаем секрет из выдачи
    res.json({
      count: clients.length,
      clients: clients.map(c => ({
        ...c.toObject(),
        hasSecret: !!c.clientSecret, // Флаг, что секрет установлен
        secretPreview: c.clientSecret ? c.clientSecret.substring(0, 8) + '...' : null
      }))
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch clients' });
  }
});

// --- POST /admin/clients ---
// Создание нового клиента
router.post('/clients', async (req: Request, res: Response) => {
  const parsed = clientSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input', details: parsed.error.format() });
  }

  const { name, redirectUris, scopes, isConfidential } = parsed.data;

  const clientId = uuidv4();
  const clientSecret = uuidv4(); // Генерируем новый секрет

  try {
    const client = new OAuthClient({
      clientId,
      clientSecret, // Сохраняем в БД
      redirectUris,
      name,
      owner: (req as any).adminUser._id, // Владелец - текущий админ
      isConfidential,
      scopes
    });

    await client.save();

    // ВАЖНО: Возвращаем секрет ТОЛЬКО в этом ответе. Больше его никто не увидит.
    res.status(201).json({
      message: 'Client created successfully',
      client: {
        clientId: client.clientId,
        clientSecret: clientSecret, // ⚠️ Единственный шанс увидеть секрет
        name: client.name,
        redirectUris: client.redirectUris
      },
      warning: 'Save this clientSecret immediately. It will never be shown again.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create client' });
  }
});

// --- GET /admin/clients/:id ---
// Детали по ID (MongoDB _id)
router.get('/clients/:id', async (req: Request, res: Response) => {
  try {
    const client = await OAuthClient.findOne({ _id: req.params.id }).select('-clientSecret');
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }
    res.json(client);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- PUT /admin/clients/:id ---
// Обновление настроек (кроме секретов и clientId)
router.put('/clients/:id', async (req: Request, res: Response) => {
  const parsed = clientSchema.partial().safeParse(req.body); // partial позволяет обновлять частично
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input', details: parsed.error.format() });
  }

  try {
    const client = await OAuthClient.findOneAndUpdate(
      { _id: req.params.id },
      { $set: parsed.data },
      { new: true, runValidators: true }
    ).select('-clientSecret');

    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }

    res.json({ message: 'Client updated',  client });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update client' });
  }
});

// --- POST /admin/clients/:id/rotate-secret ---
// Перевыпуск секрета
router.post('/clients/:id/rotate-secret', async (req: Request, res: Response) => {
  try {
    const client = await OAuthClient.findOne({ _id: req.params.id });
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const newSecret = uuidv4();
    client.clientSecret = newSecret;
    await client.save();

    res.json({
      message: 'Secret rotated successfully',
      client: {
        clientId: client.clientId,
        clientSecret: newSecret // ⚠️ Again, show only once
      },
      warning: 'Old secret is now invalid. Update your application configuration immediately.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to rotate secret' });
  }
});

// --- DELETE /admin/clients/:id ---
// Удаление клиента
router.delete('/clients/:id', async (req: Request, res: Response) => {
  try {
    const result = await OAuthClient.deleteOne({ _id: req.params.id });
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }
    
    // Опционально: отозвать все токены этого клиента здесь
    
    res.json({ message: 'Client deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete client' });
  }
});

export default router;