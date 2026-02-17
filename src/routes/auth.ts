import { Router, Request, Response } from 'express';
import { User } from '../models/User';
import { loginSchema } from '../schemas/auth';
import { setUserId } from '../utils/session';

const router = Router();

router.get('/login', (req: Request, res: Response) => {
  const redirect = req.query.redirect?.toString() || '/';
  res.send(`
    <form method="POST">
      <input name="email" placeholder="Email" required><br>
      <input name="password" type="password" placeholder="Password" required><br>
      <input type="hidden" name="redirect" value="${redirect}">
      <button type="submit">Login</button>
    </form>
  `);
});

router.post('/login', async (req: Request, res: Response) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input', details: parsed.error.format() });
  }

  const { email, password, redirect } = parsed.data;
  const user = await User.findOne({ email });
  if (!user || !(await user.comparePassword(password))) {
    return res.status(401).send('Invalid credentials');
  }
  setUserId(req, user._id.toString());
  res.redirect(redirect || '/');
});

export default router;