const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json()); // Parse JSON body

// Enable CORS
app.use(cors({ origin: "http://localhost:3000" }));

// Security Headers (CSP, X-Frame-Options, etc.)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "trusted-cdn.com"],
            frameAncestors: ["'none'"] // Prevent Clickjacking
        }
    }
}));

// In-memory database
let users = [{ id: 1, name: "Alice" }, { id: 2, name: "Bob" }];

// Secret key for JWT
const SECRET_KEY = process.env.SECRET_KEY || 'my-secret-key';

// Middleware for JWT Authentication
const authenticateJWT = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token.replace("Bearer ", ""), SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

// Public Route - Fetch Users
app.get('/users', (req, res) => {
    res.json(users);
});

// Secure Route - Add User (Requires Authentication)
app.post('/users', authenticateJWT, [
    body('name').isString().withMessage('Name must be a string').trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const newUser = { id: users.length + 1, name: req.body.name };
    users.push(newUser);
    res.status(201).json(newUser);
});

// User Login - Get JWT Token
app.post('/login', [
    body('username').isString(),
    body('password').isLength({ min: 6 })
], (req, res) => {
    const { username, password } = req.body;

    if (username === "admin" && password === "password123") {
        const token = jwt.sign({ username, role: "admin" }, SECRET_KEY, { expiresIn: "1h" });
        return res.json({ token });
    }
    res.status(401).json({ error: "Invalid credentials" });
});

// Role-Based Access Control (RBAC) Middleware
const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ error: "Forbidden" });
        }
        next();
    };
};

// Secure Route - Delete User (Admin Only)
app.delete('/users/:id', authenticateJWT, requireRole('admin'), (req, res) => {
    users = users.filter(user => user.id !== parseInt(req.params.id));
    res.json({ message: "User deleted" });
});

// Start the Server on Port 3000
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
