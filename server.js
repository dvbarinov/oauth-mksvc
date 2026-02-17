require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const path = require('path');

const authRoutes = require('./routes/auth');
const oauthRoutes = require('./routes/oauth');
const clientRoutes = require('./routes/clients');

const app = express();
const PORT = process.env.PORT || 3001;

// Подключение MongoDB
mongoose.connect(process.env.MONGODB_URI).then(() => {
  console.log('Connected to MongoDB');
});

// Middleware
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session (в продакшене — store: RedisStore)
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true если HTTPS
}));

// CORS (настрой под свои нужды)
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

// Роуты
app.use('/auth', authRoutes);
app.use('/oauth', oauthRoutes);
app.use('/api/clients', clientRoutes);

// Health check
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`OAuth server running on http://localhost:${PORT}`);
});