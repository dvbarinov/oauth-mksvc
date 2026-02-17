import { Router, Request, Response } from 'express';
import { OAuthClient } from '../models/OAuthClient';
import { v4 as uuidv4 } from 'uuid';
import { registerClientSchema } from '../schemas/client';
import { getUserId } from '../utils/session';

const router = Router();

router.use((req: Request, res: Response, next: Function) => {
  if (!getUserId(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

router.post('/', async (req: Request, res: Response) => {
  const parsed = registerClientSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid client data', details: parsed.error.format() });
  }

  const { name, redirectUris, scopes } = parsed.data;

  const clientId = uuidv4();
  const clientSecret = uuidv4();

  const client = new OAuthClient({
    clientId,
    clientSecret,
    redirectUris,
    name,
    owner: getUserId(req),
    scopes
  });

  await client.save();
  res.json({ clientId, client_secret: clientSecret }); // соответствует RFC (snake_case)
});

export default router;