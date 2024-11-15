// models/User.js

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

// הגדרת הסכימה של המשתמש
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    minlength: 3,
    maxlength: 30,
    trim: true,
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validator.isEmail, 'Invalid email address'],
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8,
  }
});

// הצפנת הסיסמה לפני שמירה באמצעות bcrypt
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    // בדיקת חוזק סיסמה
    if (!validator.isStrongPassword(this.password, {
      minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1
    })) {
      throw new Error('Password is not strong enough');
    }
    this.password = await bcrypt.hash(this.password, 10); // מספר סיבובי הצפנה גבוה
  }
  next();
});

// פונקציה לבדיקת סיסמה
userSchema.methods.isValidPassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

// יצירת מודל מהסכימה
const User = mongoose.model('User', userSchema);
module.exports = User;
