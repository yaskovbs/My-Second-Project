// utils/authMiddleware.js

const jwt = require('jsonwebtoken');

// Middleware לאימות ווריפיקציה של JWT
const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }
    const token = authHeader.split(' ')[1]; // הוצאת הטוקן מ-"Bearer <token>"
    const decoded = jwt.verify(token, process.env.SECRET_KEY); // שימוש במפתח הסודי ממשתנה סביבה
    req.user = decoded; // הצמדת המידע המפוענח לבקשה
    next(); // מעבר ל-Middleware או Handler הבא
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' }); // טיפול בטוקן לא תקין
  }
};

module.exports = authMiddleware;
