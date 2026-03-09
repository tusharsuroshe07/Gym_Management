const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'gym_super_secret_key_123';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Middleware for authentication
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// Middleware for admin check
const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.sendStatus(403);
    }
};

// Register
app.post('/api/register', async (req, res) => {
    const { username, password, name, phone } = req.body;
    if (!username || !password || !name) {
        return res.status(400).json({ error: 'Username, password, and name are required' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        db.run(`INSERT INTO users (username, password, name, phone, role) VALUES (?, ?, ?, ?, ?)`,
            [username, hashedPassword, name, phone, 'user'], function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Username already exists' });
                    }
                    return res.status(500).json({ error: 'Database error' });
                }
                res.status(201).json({ message: 'User registered successfully', id: this.lastID });
            });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(401).json({ error: 'Invalid username or password' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid username or password' });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
            token,
            user: { id: user.id, username: user.username, name: user.name, role: user.role }
        });
    });
});

// Get user profile
app.get('/api/user/profile', authenticateJWT, (req, res) => {
    db.get(`SELECT id, username, name, phone, role, join_date, membership_type, membership_end_date FROM users WHERE id = ?`, 
    [req.user.id], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    });
});

// Admin: Get all users
app.get('/api/admin/users', authenticateJWT, isAdmin, (req, res) => {
    db.all(`SELECT id, username, name, phone, role, join_date, membership_type, membership_end_date FROM users WHERE role = 'user'`, 
    [], (err, users) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(users);
    });
});

// Admin: Update user membership
app.post('/api/admin/users/:id/membership', authenticateJWT, isAdmin, (req, res) => {
    const userId = req.params.id;
    const { durationMonths } = req.body; // 3, 6, 12

    if (![3, 6, 12].includes(durationMonths)) {
        return res.status(400).json({ error: 'Invalid duration. Must be 3, 6, or 12.' });
    }

    const typeString = durationMonths === 12 ? '1_year' : `${durationMonths}_months`;
    
    // Calculate end date based on current date
    const endDate = new Date();
    endDate.setMonth(endDate.getMonth() + durationMonths);
    const endDateStr = endDate.toISOString().split('T')[0] + ' 23:59:59'; // roughly EOD

    db.run(`UPDATE users SET membership_type = ?, membership_end_date = ? WHERE id = ? AND role = 'user'`,
        [typeString, endDateStr, userId], function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (this.changes === 0) return res.status(404).json({ error: 'User not found or is admin' });
            res.json({ message: 'Membership updated', membership_type: typeString, membership_end_date: endDateStr });
        });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
