const express = require('express');
const serverless = require('serverless-http');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const router = express.Router();
const PORT = 3000;
const SECRET_KEY = 'your_super_secret_jwt_key'; // CHANGE THIS IN A REAL APP

// Middleware
app.use(cors());
app.use(express.json());

// In-memory "database" to start. Replace with a real database later (e.g., MongoDB).
let users = {};
let promoCodes = {};
let siteStatus = { isMaintenanceMode: false, message: "We'll be back soon!" };

// ADMIN login details (for this example, replace with a real admin user)
const ADMIN_USER = { username: 'admin', password: 'admin123' };

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); // Unauthorized

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        req.user = user;
        next();
    });
};

// Middleware to check for admin role
const checkAdminRole = (req, res, next) => {
    if (req.user.username !== 'admin') {
        return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
    next();
};

// --- AUTHENTICATION ENDPOINTS ---

router.post('/auth/register', (req, res) => {
    const { username, password } = req.body;
    if (users[username]) {
        return res.status(409).json({ error: 'Username already exists.' });
    }
    users[username] = {
        password: password,
        chats: {},
        unlockedModels: ["G-4 Fusion"],
        activeModel: "G-4 Fusion",
        avatarColor: `hsl(${Math.random() * 360}, 50%, 50%)`
    };
    const token = jwt.sign({ username: username, role: 'user' }, SECRET_KEY);
    res.json({ token, user: users[username] });
});

router.post('/auth/login', (req, res) => {
    const { username, password } = req.body;

    // Check for admin
    if (username === ADMIN_USER.username && password === ADMIN_USER.password) {
        const token = jwt.sign({ username: ADMIN_USER.username, role: 'admin' }, SECRET_KEY);
        return res.json({ token, user: { username: 'admin' } });
    }

    // Check for regular user
    if (users[username] && users[username].password === password) {
        const token = jwt.sign({ username: username, role: 'user' }, SECRET_KEY);
        return res.json({ token, user: users[username] });
    }

    res.status(401).json({ error: 'Invalid username or password.' });
});

// --- ADMIN ENDPOINTS (SECURED) ---

router.get('/admin/dashboard', authenticateToken, checkAdminRole, (req, res) => {
    // In a real app, you would fetch this from the database
    const userCount = Object.keys(users).length;
    const totalChats = Object.values(users).reduce((acc, user) => acc + Object.keys(user.chats || {}).length, 0);
    const activeCodes = Object.keys(promoCodes).length;
    res.json({ userCount, totalChats, activeCodes, users, promoCodes, siteStatus });
});

router.post('/admin/promo-codes', authenticateToken, checkAdminRole, (req, res) => {
    const { code, model, expiry } = req.body;
    if (!code || !model || !expiry) {
        return res.status(400).json({ error: 'Missing code, model, or expiry date.' });
    }
    promoCodes[code] = { model, expiry };
    res.status(201).json({ message: 'Promo code created successfully.', promoCodes });
});

router.delete('/admin/promo-codes/:code', authenticateToken, checkAdminRole, (req, res) => {
    const { code } = req.params;
    if (!promoCodes[code]) {
        return res.status(404).json({ error: 'Promo code not found.' });
    }
    delete promoCodes[code];
    res.json({ message: 'Promo code deleted successfully.', promoCodes });
});

router.put('/admin/status', authenticateToken, checkAdminRole, (req, res) => {
    const { isMaintenanceMode, message } = req.body;
    siteStatus.isMaintenanceMode = isMaintenanceMode;
    siteStatus.message = message;
    res.json({ message: 'Site status updated.', siteStatus });
});

// --- USER-FACING ENDPOINTS (SECURED) ---

router.get('/user/data', authenticateToken, (req, res) => {
    const user = users[req.user.username];
    if (!user) {
        return res.status(404).json({ error: 'User not found.' });
    }
    res.json(user);
});

router.post('/user/chats', authenticateToken, (req, res) => {
    const { chatId, message } = req.body;
    const user = users[req.user.username];
    if (!user.chats[chatId]) {
        user.chats[chatId] = { id: chatId, timestamp: Date.now(), title: 'New Chat', messages: [] };
    }
    user.chats[chatId].messages.push(message);
    res.status(201).json({ message: 'Message added.', chats: user.chats });
});

router.post('/user/redeem', authenticateToken, (req, res) => {
    const { code } = req.body;
    const codeData = promoCodes[code];
    const user = users[req.user.username];

    if (!codeData || new Date(codeData.expiry) < new Date()) {
        return res.status(400).json({ error: 'Invalid or expired code.' });
    }

    if (user.unlockedModels.includes(codeData.model)) {
        return res.status(409).json({ error: 'Model already unlocked.' });
    }

    user.unlockedModels.push(codeData.model);
    res.json({ message: `${codeData.model} unlocked!`, user });
});

app.use('/api', router);

module.exports.handler = serverless(app);