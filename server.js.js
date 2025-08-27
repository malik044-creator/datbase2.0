const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Initialize the express application
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware for parsing JSON and handling CORS
app.use(cors());
app.use(express.json());

// Database setup
// The database file will be created in the same directory as this script.
const db = new sqlite3.Database('./database.sqlite');

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'employee',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // IP addresses table
    db.run(`CREATE TABLE IF NOT EXISTS ip_addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    
    // Create initial admin user if not exists
    const adminPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, name, role) VALUES (?, ?, ?, ?)`, 
        ['admin', adminPassword, 'Admin User', 'admin']);
});

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token == null) {
        return res.sendStatus(401); // No token provided
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Invalid token
        }
        req.user = user;
        next();
    });
};

// ** NEW: Route to serve the frontend HTML file **
// This tells the server to send the 'index.html' file when someone visits the main URL ('/').
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// User login endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Compare password with hashed password
        if (bcrypt.compareSync(password, user.password)) {
            const accessToken = jwt.sign({ username: user.username, role: user.role, id: user.id }, JWT_SECRET);
            res.json({ accessToken });
        } else {
            res.status(400).json({ message: 'Invalid credentials' });
        }
    });
});

// New endpoint to upload a single IP address
app.post('/api/upload-ip', authenticateToken, (req, res) => {
    const { ip } = req.body;
    const userId = req.user.id;

    // Validate the IP format. This is a simple regex for IPv4.
    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ip || !ipRegex.test(ip)) {
        return res.status(400).json({ message: 'Invalid IP address format' });
    }

    // Check if the IP already exists in the database
    db.get('SELECT * FROM ip_addresses WHERE ip = ?', [ip], (err, existingIp) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }

        // If a duplicate is found, return an error message
        if (existingIp) {
            return res.status(409).json({ message: `Duplicate IP address found: ${ip}` });
        }

        // If the IP is new, insert it into the database
        db.run('INSERT INTO ip_addresses (ip, user_id) VALUES (?, ?)', [ip, userId], function(err) {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            res.status(201).json({ message: 'IP address uploaded successfully' });
        });
    });
});

// Get dashboard stats for the authenticated user
app.get('/api/stats', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role;

    if (userRole === 'admin') {
        // Admin stats (total IPs, employees, duplicates)
        db.get('SELECT COUNT(*) AS count FROM ip_addresses', (err, ipResult) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            db.get('SELECT COUNT(*) AS count FROM users WHERE role = "employee"', (err, empResult) => {
                if (err) return res.status(500).json({ message: 'Database error' });
                db.get(`SELECT COUNT(*) as count FROM (
                    SELECT ip FROM ip_addresses GROUP BY ip HAVING COUNT(*) > 1
                )`, (err, dupResult) => {
                    if (err) return res.status(500).json({ message: 'Database error' });
                    res.json({
                        totalIPs: ipResult.count,
                        totalEmployees: empResult.count,
                        totalDuplicates: dupResult.count
                    });
                });
            });
        });
    } else {
        // Employee stats (their own IPs and duplicates)
        db.get('SELECT COUNT(*) AS count FROM ip_addresses WHERE user_id = ?', [userId], (err, ipResult) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            db.get(`SELECT COUNT(*) AS count FROM ip_addresses 
                    WHERE user_id = ? AND ip IN (
                        SELECT ip FROM ip_addresses GROUP BY ip HAVING COUNT(*) > 1
                    )`, [userId], (err, dupResult) => {
                if (err) return res.status(500).json({ message: 'Database error' });
                res.json({
                    totalIPs: ipResult.count,
                    totalDuplicates: dupResult.count
                });
            });
        });
    }
});

// Get employee list for admin
app.get('/api/admin/employees', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    
    db.all(
        `SELECT users.*, 
         (SELECT COUNT(*) FROM ip_addresses WHERE user_id = users.id) as ipCount,
         (SELECT COUNT(*) FROM ip_addresses WHERE user_id = users.id 
          AND ip IN (SELECT ip FROM ip_addresses GROUP BY ip HAVING COUNT(*) > 1)) as duplicateCount
         FROM users WHERE role = 'employee'`,
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            res.json(rows);
        }
    );
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
