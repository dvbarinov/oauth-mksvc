import { Router, Request, Response } from 'express';
import { OAuthClient } from '../models/OAuthClient';
import { v4 as uuidv4 } from 'uuid';
import { setUserId, getUserId } from '../utils/session';

const router = Router();

// Защита: только залогиненные
router.use((req: Request, res: Response, next: Function) => {
  if (!getUserId(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

router.post('/', async (req: Request, res: Response) => {
  const { name, redirectUris, scopes = ['profile'] } = req.body;

  if (!name || !Array.isArray(redirectUris) || redirectUris.length === 0) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  const clientId = uuidv4();
  const clientSecret = uuidv4(); // в продакшене — хэшируй!

  const client = new OAuthClient({
    clientId,
    clientSecret,
    redirectUris,
    name,
    owner: getUserId(req),
    scopes
  });

  await client.save();
  res.json({ clientId, clientSecret });
});

export default router;