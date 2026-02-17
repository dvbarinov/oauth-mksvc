const express = require('express');
const OAuthClient = require('../models/OAuthClient');
const { hashPassword } = require('../models/User');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();

// Защита: только залогиненные могут создавать клиентов
router.use((req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
});

router.post('/', async (req, res) => {
  const { name, redirectUris, scopes = ['profile'] } = req.body;
  if (!name || !redirectUris || !Array.isArray(redirectUris)) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  const clientId = uuidv4();
  const clientSecret = uuidv4(); // можно хэшировать при хранении

  const client = new OAuthClient({
    clientId,
    clientSecret, // в продакшене — хэшируй!
    redirectUris,
    name,
    owner: req.session.userId,
    scopes
  });

  await client.save();
  res.json({ clientId, clientSecret }); // отправляй секрет один раз!
});

module.exports = router;