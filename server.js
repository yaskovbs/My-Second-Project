// server.js

require('dotenv').config(); // טעינת משתני סביבה

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const userRoutes = require('./routes/userRoutes');
const connectDB = require('./config/db'); // ייבוא הפונקציה connectDB

const app = express();

// התחברות ל-MongoDB
connectDB();

// הוספת כותרות אבטחה
app.use(helmet());

// Rate Limiting גלובלי
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

// אפשרויות CORS
const corsOptions = {
  origin: ['origin: [http://localhost:3009'], // עדכן לפי הצורך
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(limiter);

// נתיבי המשתמשים
app.use('/api/users', userRoutes);

// טיפול בשגיאות גלובלי
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal Server Error' });
});

// הרצת השרת על פורט 3008
const PORT = process.env.PORT || 3008;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
