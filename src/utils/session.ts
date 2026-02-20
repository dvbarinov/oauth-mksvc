import { Request } from 'express';

// Расширяем тип сессии локально для этой утилиты
interface CustomSessionData {
  userId?: string;
}

export const getUserId = (req: Request): string | undefined => {
  return (req.session as unknown as CustomSessionData)?.userId;
};

export const setUserId = (req: Request, id: string): void => {
  //req.session!.userId = id;
  (req.session as unknown as CustomSessionData).userId = id;
};