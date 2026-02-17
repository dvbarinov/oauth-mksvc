const mongoose = require('mongoose');

const clientSchema = new mongoose.Schema({
  clientId: { type: String, required: true, unique: true },
  clientSecret: { type: String, required: true }, // hashed
  redirectUris: [{ type: String, required: true }],
  name: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isConfidential: { type: Boolean, default: true },
  scopes: [String]
}, { timestamps: true });

module.exports = mongoose.model('OAuthClient', clientSchema);