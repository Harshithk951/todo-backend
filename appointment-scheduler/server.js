const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'a-super-secret-key-that-should-be-long-and-random';
const GOOGLE_CLIENT_ID = '104431383148-4ubgun7hqoicil5bppqrvdam7r0hhv37.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Mac2025!',
  database: 'appointment_db'
}).promise();

const createDemoUser = async () => {
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ? OR username = ?', ['admin@demo.com', 'admin_user']);
    
    if (rows.length === 0) {
      console.log('Demo user not found. Creating demo user...');
      const hashedPassword = await bcrypt.hash('demopassword', 10); 
      const sql = 'INSERT INTO users (firstName, lastName, username, email, password, role, location, avatar) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
      await db.query(sql, ['Admin', 'User', 'admin_user', 'admin@demo.com', hashedPassword, 'User', '', '']);
      console.log('Demo user created successfully!');
    } else {
      console.log('Demo user already exists.');
    }
  } catch (error) {
    console.error('Error seeding demo user:', error);
  }
};

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

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/register', async (req, res) => {
    const { firstName, lastName, username, email, password } = req.body;
    if (!firstName || !lastName || !username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, username]);
        if (rows.length > 0) {
            return res.status(400).json({ message: 'User with this email or username already exists.' });
        }
        const sql = 'INSERT INTO users (firstName, lastName, username, email, password, role, location, avatar) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        await db.query(sql, [firstName, lastName, username, email, hashedPassword, 'New User', '', '']);
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE username = ? OR email = ?', [email, email]);
        if (rows.length === 0) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const user = rows[0];
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});


app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(200).json({ message: 'If an account with this email exists, a password reset link has been sent.' });
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
    } catch (error) {
        console.error('Forgot Password Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});


app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, CONCAT(firstName, " ", lastName) AS name, email, role, location, avatar FROM users WHERE id = ?', [req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
  const { name, email, role, location, avatar } = req.body;
  const [firstName, ...lastNameParts] = name.split(' ');
  const lastName = lastNameParts.join(' ');

  try {
    const sql = 'UPDATE users SET firstName = ?, lastName = ?, email = ?, role = ?, location = ?, avatar = ? WHERE id = ?';
    await db.query(sql, [firstName || '', lastName || '', email, role || '', location || '', avatar || '', req.user.id]);
    res.json({ message: 'Profile updated successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server started on http://0.0.0.0:${PORT}`);
});