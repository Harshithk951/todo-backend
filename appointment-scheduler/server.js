const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const rateLimit = require('express-rate-limit');
const asyncHandler = require('express-async-handler');

// Import middleware and routes
const authenticateToken = require('./auth');
const errorHandler = require('./error');
const taskRoutes = require('./routes/tasks'); // New task routes
const db = require('./db'); // Centralized DB connection

const app = express();

const JWT_SECRET = 'a-super-secret-key-that-should-be-long-and-random';

const corsOptions = {
  origin: ['http://localhost:3000', 'https://your-frontend-app.vercel.app'],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 100,
	standardHeaders: true,
	legacyHeaders: false,
});
app.use(apiLimiter);

app.use(express.json());

// --- Demo User Seeding ---
const createDemoUser = async () => {
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ? OR username = ?', ['admin@demo.com', 'admin_user']);
    if (rows.length === 0) {
      console.log('Creating demo user...');
      const hashedPassword = await bcrypt.hash('demopassword', 10);
      const sql = 'INSERT INTO users (firstName, lastName, username, email, password, role) VALUES (?, ?, ?, ?, ?, ?)';
      await db.query(sql, ['Admin', 'User', 'admin_user', 'admin@demo.com', hashedPassword, 'User']);
      console.log('Demo user created!');
    } else {
      console.log('Demo user already exists.');
    }
  } catch (error) {
    console.error('Error seeding demo user:', error);
  }
};

// Start DB connection and seed user
db.connect().then(() => {
    console.log('MySQL Connected...');
    createDemoUser();
}).catch(err => {
    console.error('Error connecting to MySQL: ', err);
});

let transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  secure: false,
  auth: {
    user: 'lennie.bins@ethereal.email',
    pass: '4G5yJz1rCgReBFdGuP',
  },
});

// --- API Routes ---
// Public User Routes
app.post('/register', asyncHandler(async (req, res) => {
    const { firstName, lastName, username, email, password } = req.body;
    if (!firstName || !lastName || !username || !email || !password) {
        res.status(400);
        throw new Error('All fields are required.');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [rows] = await db.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, username]);
    if (rows.length > 0) {
        res.status(400);
        throw new Error('User with this email or username already exists.');
    }
    const sql = 'INSERT INTO users (firstName, lastName, username, email, password, role) VALUES (?, ?, ?, ?, ?, ?)';
    await db.query(sql, [firstName, lastName, username, email, hashedPassword, 'New User']);
    res.status(201).json({ message: 'User registered successfully!' });
}));

app.post('/login', asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        res.status(400);
        throw new Error('Email and password are required.');
    }
    const [rows] = await db.query('SELECT * FROM users WHERE username = ? OR email = ?', [email, email]);
    if (rows.length === 0) {
        res.status(401);
        throw new Error('Invalid credentials.');
    }
    const user = rows[0];
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
        res.status(401);
        throw new Error('Invalid credentials.');
    }
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
}));

app.post('/forgot-password', asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email) {
        res.status(400);
        throw new Error('Email is required.');
    }
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
        res.status(200).json({ message: 'If an account with this email exists, a password reset link has been sent.' });
        return;
    }
    const user = rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); 
    await db.query('UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE id = ?', [token, expires, user.id]);
    const resetURL = `http://localhost:3000/reset-password/${token}`;
    const info = await transporter.sendMail({
        from: '"Todo Dashboard App" <no-reply@tododashboard.com>',
        to: user.email,
        subject: 'Password Reset Request',
        text: `Please click the following link to reset your password:\n\n${resetURL}\n\nIf you did not request this, please ignore this email.`,
    });
    console.log("Password reset email sent. Preview URL: %s", nodemailer.getTestMessageUrl(info));
    res.status(200).json({ message: 'If an account with this email exists, a password reset link has been sent.' });
}));

// Protected User Routes
app.get('/api/user/profile', authenticateToken, asyncHandler(async (req, res) => {
    const [rows] = await db.query('SELECT id, CONCAT(firstName, " ", lastName) AS name, email, role, location, avatar FROM users WHERE id = ?', [req.user.id]);
    if (rows.length === 0) {
        res.status(404);
        throw new Error('User not found.');
    }
    res.json(rows[0]);
}));

app.put('/api/user/profile', authenticateToken, asyncHandler(async (req, res) => {
    const { name, email, role, location, avatar } = req.body;
    const [firstName, ...lastNameParts] = name.split(' ');
    const lastName = lastNameParts.join(' ');
    const sql = 'UPDATE users SET firstName = ?, lastName = ?, email = ?, role = ?, location = ?, avatar = ? WHERE id = ?';
    await db.query(sql, [firstName || '', lastName || '', email, role || '', location || '', avatar || '', req.user.id]);
    res.json({ message: 'Profile updated successfully.' });
}));

// Protected Task Routes
app.use('/api/tasks', authenticateToken, taskRoutes); // All task routes are protected

// Central Error Handler
app.use(errorHandler);

const PORT = process.env.PORT || 3001;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server started on http://0.0.0.0:${PORT}`);
});