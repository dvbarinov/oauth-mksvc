import { z } from 'zod';

export const registerClientSchema = z.object({
  name: z.string().min(1).max(100),
  redirectUris: z.array(z.string().url()).min(1).max(10),
  scopes: z.array(z.string()).optional().default(['profile'])
});