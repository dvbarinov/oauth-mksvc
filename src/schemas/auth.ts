import { z } from 'zod';

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  redirect: z.string().optional()
});

export const registerSchema = z.object({
  name: z.string().min(2).max(50),
  email: z.string().email(),
  password: z.string().min(8).regex(/[A-Z]/, "Must contain uppercase")
                          .regex(/[0-9]/, "Must contain number"), // Усилим требования к паролю
  redirect: z.string().optional()
});
