const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const router = express.Router();
const PORT = process.env.PORT || 3000; 
const SECRET_KEY = 'your_super_secret_jwt_key_that_is_long_and_secure';
const saltRounds = 10; // For bcrypt hashing

// Middleware
app.use(cors());
app.use(express.json());

// --- In-memory "database" ---
let users = {};
let promoCodes = {};
let siteStatus = { isMaintenanceMode: false, message: "We'll be back soon!" };

// --- Shop Features ---
const shopFeatures = [
    { id: 'voice_mode', name: 'Voice Mode', description: 'Enable voice input and output for conversations.', price: 4.99 },
    { id: 'advanced_data_analysis', name: 'Advanced Data Analysis', description: 'Unlock powerful data analysis capabilities.', price: 9.99 },
    { id: 'image_generation', name: 'Image Generation Suite', description: 'Create stunning images from text prompts.', price: 14.99 }
];

// --- Admin User ---
const ADMIN_USER = { username: 'admin', password: 'admin123' };
// Pre-hash the admin password on startup for security
bcrypt.hash(ADMIN_USER.password, saltRounds).then(hash => {
    ADMIN_USER.hashedPassword = hash;
});

// --- Security Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const checkAdminRole = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
    next();
};

// --- AUTHENTICATION ENDPOINTS ---
router.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (users[username] || username.toLowerCase() === 'admin') {
        return res.status(409).json({ error: 'Username already exists.' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        users[username] = {
            password: hashedPassword,
            chats: {},
            unlockedModels: ["G-4 Fusion"],
            purchasedFeatures: [],
            status: 'active', // 'active' or 'banned'
            activeModel: "G-4 Fusion",
            avatarColor: `hsl(${Math.random() * 360}, 50%, 50%)`,
            role: 'user'
        };
        const token = jwt.sign({ username: username, role: 'user' }, SECRET_KEY);
        const { password: _, ...userToReturn } = users[username];
        res.status(201).json({ token, user: {username, ...userToReturn} });
    } catch (error) {
        res.status(500).json({ error: 'Error creating user.' });
    }
});

router.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        if (username.toLowerCase() === ADMIN_USER.username) {
            const match = await bcrypt.compare(password, ADMIN_USER.hashedPassword);
            if (match) {
                const token = jwt.sign({ username: ADMIN_USER.username, role: 'admin' }, SECRET_KEY);
                return res.json({ token, user: { username: 'admin', role: 'admin' } });
            }
        }

        const user = users[username];
        if (user) {
            if (user.status === 'banned') {
                return res.status(403).json({ error: 'This account has been banned.' });
            }
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const token = jwt.sign({ username: username, role: 'user' }, SECRET_KEY);
                const { password: _, ...userToReturn } = user;
                return res.json({ token, user: {username, ...userToReturn} });
            }
        }
        res.status(401).json({ error: 'Invalid username or password.' });
    } catch (error) {
        res.status(500).json({ error: 'Error during login.' });
    }
});

// --- PUBLIC & GENERAL ENDPOINTS ---
router.get('/status', (req, res) => res.json(siteStatus));
router.get('/shop/features', (req, res) => res.json(shopFeatures));

// --- USER ENDPOINTS (SECURED) ---
router.get('/user/data', authenticateToken, (req, res) => {
    const user = users[req.user.username];
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const { password, ...userToReturn } = user;
    res.json({username: req.user.username, ...userToReturn});
});

router.post('/shop/purchase', authenticateToken, (req, res) => {
    const { featureId } = req.body;
    const user = users[req.user.username];
    const feature = shopFeatures.find(f => f.id === featureId);

    if (!feature) return res.status(404).json({ error: 'Feature not found.' });
    if (user.purchasedFeatures.includes(featureId)) {
        return res.status(409).json({ error: 'You already own this feature.' });
    }
    user.purchasedFeatures.push(featureId);
    const { password, ...userToReturn } = user;
    res.json({ message: `Successfully purchased ${feature.name}!`, user: {username: req.user.username, ...userToReturn}});
});

// --- ADMIN ENDPOINTS (SECURED) ---
router.get('/admin/dashboard', authenticateToken, checkAdminRole, (req, res) => {
    // Omitting passwords from the user list sent to admin
    const safeUsers = Object.fromEntries(
        Object.entries(users).map(([username, data]) => {
            const { password, ...rest } = data;
            return [username, {username, ...rest}];
        })
    );
    res.json({ users: safeUsers });
});

router.post('/admin/users/:username/ban', authenticateToken, checkAdminRole, (req, res) => {
    const { username } = req.params;
    const user = users[username];
    if (!user || username === 'admin') {
        return res.status(404).json({ error: 'User not found or cannot be banned.' });
    }
    user.status = 'banned';
    res.json({ message: `User ${username} has been banned.` });
});

router.post('/admin/users/:username/unban', authenticateToken, checkAdminRole, (req, res) => {
    const { username } = req.params;
    const user = users[username];
    if (!user) return res.status(404).json({ error: 'User not found.' });
    user.status = 'active';
    res.json({ message: `User ${username} has been unbanned.` });
});

app.use('/api', router);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

