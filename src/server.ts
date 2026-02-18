import 'dotenv/config';
import express, { Request, Response } from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import mongoose from 'mongoose';

import authRoutes from './routes/auth';
import oauthRoutes from './routes/oauth';
import clientRoutes from './routes/clients';
import discoveryRoutes from './routes/discovery'; 

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3001;

mongoose.connect(process.env.MONGODB_URI!).then(() => {
  console.log('Connected to MongoDB');
});

app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

app.use('/auth', authRoutes);
app.use('/oauth', oauthRoutes);
app.use('/api/clients', clientRoutes);
app.use('/', discoveryRoutes);

app.get('/health', (_req: Request, res: Response) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`OAuth server running on http://localhost:${PORT}`);
  console.log(`Discovery URL: http://localhost:${PORT}/.well-known/openid-configuration`);
});