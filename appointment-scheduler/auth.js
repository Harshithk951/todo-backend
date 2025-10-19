const jwt = require('jsonwebtoken');

// TODO: Move this secret to a .env file for production
const JWT_SECRET = 'a-super-secret-key-that-should-be-long-and-random';

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Access denied. No token provided or malformed token.' });
    }

    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token is not valid.' });
        }
        req.user = user;
        next();
    });
};

module.exports = authenticateToken;