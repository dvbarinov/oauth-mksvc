import { Router, Request, Response } from 'express';
import { User } from '../models/User';
import { loginSchema, registerSchema } from '../schemas/auth';
import { setUserId } from '../utils/session';

const router = Router();

router.get('/login', (req: Request, res: Response) => {
  const redirect = req.query.redirect?.toString() || '/';
  const error = req.query.error;

  res.send(`
    <html>
      <head><title>Login</title><style>body{font-family:sans-serif;max-width:400px;margin:50px auto;}</style></head>
      <body>
        <h2>Вход</h2>
        ${error ? `<p style="color:red">${error}</p>` : ''}
        <form method="POST" action="/auth/login">
          <div style="margin-bottom:10px">
            <label>Email</label><br>
            <input type="email" name="email" required style="width:100%;padding:8px">
          </div>
          <div style="margin-bottom:10px">
            <label>Password</label><br>
            <input type="password" name="password" required style="width:100%;padding:8px">
          </div>
          <input type="hidden" name="redirect" value="${redirect}">
          <button type="submit" style="width:100%;padding:10px;background:#007bff;color:white;border:none;cursor:pointer">Войти</button>
        </form>
        <p style="margin-top:20px;text-align:center">
          Нет аккаунта? <a href="/auth/register?redirect=${encodeURIComponent(redirect)}">Зарегистрироваться</a>
        </p>
      </body>
    </html>
  `);
});

router.post('/login', async (req: Request, res: Response) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input', details: parsed.error.format() });
  }

  const { email, password, redirect } = parsed.data;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      //- return res.status(401).send('Invalid credentials');
      // Редирект обратно на логин с ошибкой (без раскрытия деталей)
      let login_url = '/auth/login?error=Invalid credentials';
      if (redirect) login_url += `${login_url}&redirect=${encodeURIComponent(redirect)}`
      return res.redirect(login_url);
    }

    setUserId(req, user._id.toString());
    res.redirect(redirect || '/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// --- REGISTER ---

router.get('/register', (req: Request, res: Response) => {
  const redirect = req.query.redirect?.toString() || '/';
  
  res.send(`
    <html>
      <head><title>Register</title><style>body{font-family:sans-serif;max-width:400px;margin:50px auto;}</style></head>
      <body>
        <h2>Регистрация</h2>
        <form method="POST" action="/auth/register">
          <div style="margin-bottom:10px">
            <label>Name</label><br>
            <input type="text" name="name" required style="width:100%;padding:8px">
          </div>
          <div style="margin-bottom:10px">
            <label>Email</label><br>
            <input type="email" name="email" required style="width:100%;padding:8px">
          </div>
          <div style="margin-bottom:10px">
            <label>Password (min 8 chars, 1 Upper, 1 Number)</label><br>
            <input type="password" name="password" required style="width:100%;padding:8px">
          </div>
          <input type="hidden" name="redirect" value="${redirect}">
          <button type="submit" style="width:100%;padding:10px;background:#28a745;color:white;border:none;cursor:pointer">Создать аккаунт</button>
        </form>
        <p style="margin-top:20px;text-align:center">
          Уже есть аккаунт? <a href="/auth/login?redirect=${encodeURIComponent(redirect)}">Войти</a>
        </p>
      </body>
    </html>
  `);
});

router.post('/register', async (req: Request, res: Response) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid registration data', details: parsed.error.format() });
  }

  const { name, email, password, redirect } = parsed.data;

  try {
    // Проверка на существующего пользователя
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      let register_url = '/auth/register?error=User already exists';
      if (redirect) register_url += `${register_url}&redirect=${encodeURIComponent(redirect)}`
      return res.redirect(register_url);
    }

    // Хеширование пароля через статический метод модели
    const passwordHash = await User.hashPassword(password);

    const newUser = new User({
      name,
      email,
      passwordHash
    });

    await newUser.save();

    // Автоматический вход после регистрации (опционально, но удобно)
    req.session!.userId = newUser._id.toString();

    res.redirect(redirect || '/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error during registration');
  }
});

// --- LOGOUT ---

router.get('/logout', (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) console.error(err);
    res.redirect('/auth/login');
  });
});

export default router;