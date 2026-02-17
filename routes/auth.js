const express = require('express');
const User = require('../models/User');
const router = express.Router();

router.get('/login', (req, res) => {
  const redirect = req.query.redirect || '/';
  res.send(`
    <form method="POST">
      <input name="email" placeholder="Email" required><br>
      <input name="password" type="password" placeholder="Password" required><br>
      <input type="hidden" name="redirect" value="${redirect}">
      <button type="submit">Login</button>
    </form>
  `);
});

router.post('/login', async (req, res) => {
  const { email, password, redirect } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await user.comparePassword(password))) {
    return res.status(401).send('Invalid credentials');
  }
  req.session.userId = user._id;
  res.redirect(redirect || '/');
});

module.exports = router;