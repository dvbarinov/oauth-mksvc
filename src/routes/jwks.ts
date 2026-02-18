import { Router, Request, Response } from 'express';
import { getPublicKeyJwk } from '../utils/keys';

const router = Router();

router.get('/.well-known/jwks.json', (req: Request, res: Response) => {
  const jwk = getPublicKeyJwk();
  
  if (!jwk) {
    return res.status(500).json({ error: 'Keys not initialized' });
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=86400'); // Кэш на сутки
  res.json({
    keys: [jwk]
  });
});

export default router;