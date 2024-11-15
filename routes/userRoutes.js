// routes/userRoutes.js

const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const authMiddleware = require('../utils/authMiddleware');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

// Rate Limiting עבור התחברות
const signInLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // מקסימום 5 ניסיונות התחברות לדקה
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// POST /signup: הרשמה והנפקת JWT
router.post(
  '/signup',
  [
    body('username').isLength({ min: 3, max: 30 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isStrongPassword(),
  ],
  async (req, res) => {
    // בדיקת תקינות הקלט
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Invalid input', errors: errors.array() });
    }

    try {
      const { username, email, password } = req.body;
      const user = new User({ username, email, password });
      await user.save();
      const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '24h' });
      res.status(201).json({ user: { id: user._id, username: user.username, email: user.email }, token });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

// POST /signin: התחברות והנפקת JWT עם Rate Limiting
router.post(
  '/signin',
  signInLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').exists(),
  ],
  async (req, res) => {
    // בדיקת תקינות הקלט
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Invalid input', errors: errors.array() });
    }

    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user || !(await user.isValidPassword(password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '24h' });
      res.json({ user: { id: user._id, username: user.username, email: user.email }, token });
    } catch (error) {
      res.status(500).json({ message: 'Internal Server Error' });
    }
  }
);

// Middleware לאימות
router.use(authMiddleware);

// GET /api/users/ - קבלת כל המשתמשים
router.get('/', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// GET /api/users/:id - קבלת משתמש לפי ID
router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// PUT /api/users/:id - עדכון משתמש לפי ID
router.put(
  '/:id',
  [
    body('username').optional().isLength({ min: 3, max: 30 }).trim().escape(),
    body('email').optional().isEmail().normalizeEmail(),
    body('password').optional().isStrongPassword(),
  ],
  async (req, res) => {
    // בדיקת תקינות הקלט
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Invalid input', errors: errors.array() });
    }

    try {
      const updates = req.body;
      if (updates.password) {
        updates.password = await bcrypt.hash(updates.password, 10);
      }
      const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
      res.json(user);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

// DELETE /api/users/:id - מחיקת משתמש לפי ID
router.delete('/:id', async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

module.exports = router;
