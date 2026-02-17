const mongoose = require('mongoose');

const codeSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  clientId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  redirectUri: { type: String, required: true },
  scope: String,
  expiresAt: { type: Date, required: true },
  challenge: String, // PKCE
  challengeMethod: String // e.g., "S256"
});

codeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('AuthorizationCode', codeSchema);