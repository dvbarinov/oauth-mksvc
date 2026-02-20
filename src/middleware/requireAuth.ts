import { Request, Response, NextFunction } from 'express';
import { getUserId } from '../utils/session';

export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (!getUserId(req)) {
    const redirect = encodeURIComponent(req.originalUrl);
    return res.redirect(`/auth/login?redirect=${redirect}`);
  }
  next();
};