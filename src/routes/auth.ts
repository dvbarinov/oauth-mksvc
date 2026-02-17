import { Router, Request, Response } from 'express';
import { User } from '../models/User';
import { setUserId, getUserId } from '../utils/session';

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
  const { email, password, redirect } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await user.comparePassword(password))) {
    return res.status(401).send('Invalid credentials');
  }
  setUserId(req, user._id.toString());
  res.redirect(redirect || '/');
});

export default router;