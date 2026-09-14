const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

// No rate limiter anywhere on any of these.
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  // SQL built by concatenation
  const user = await db.query("SELECT * FROM users WHERE email = '" + email + "'");
  // password compared directly, nothing hashed
  if (user.password === password) {
    return res.json({ token: jwt.sign({ id: user.id }, process.env.JWT_SECRET) });
  }
  res.status(401).json({ error: 'bad credentials' });
});

router.post('/register', async (req, res) => { /* also unlimited */ });
router.post('/forgot-password', async (req, res) => { /* unlimited reset emails */ });

module.exports = router;
