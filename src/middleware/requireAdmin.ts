// src/middleware/requireAdmin.ts
import { Request, Response, NextFunction } from 'express';
import { User } from '../models/User';

export const requireAdmin = async (req: Request, res: Response, next: NextFunction) => {
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Login required' });
  }

  try {
    const user = await User.findById(req.session.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden', message: 'Admin access required' });
    }
    
    // Опционально: добавляем пользователя в запрос для дальнейшего использования
    (req as any).adminUser = user;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
};