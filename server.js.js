const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database setup
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
    
    // Create initial employee user if not exists
    const johnPassword = bcrypt.hashSync('john123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, name, role) VALUES (?, ?, ?, ?)`, 
        ['john', johnPassword, 'John Doe', 'employee']);
});

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Routes

// Login route
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                name: user.name,
                role: user.role
            }
        });
    });
});

// Get all IPs (admin only)
app.get('/api/ips', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    
    db.all(`
        SELECT ip_addresses.*, users.name as userName 
        FROM ip_addresses 
        JOIN users ON ip_addresses.user_id = users.id 
        ORDER BY ip_addresses.created_at DESC
    `, (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(rows);
    });
});

// Get my IPs
app.get('/api/my/ips', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM ip_addresses WHERE user_id = ? ORDER BY created_at DESC',
        [req.user.id],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            res.json(rows);
        }
    );
});

// Add IPs
app.post('/api/ips', authenticateToken, (req, res) => {
    const { ips } = req.body;
    
    if (!ips || !Array.isArray(ips) || ips.length === 0) {
        return res.status(400).json({ message: 'IP addresses array required' });
    }
    
    let added = 0;
    let duplicates = 0;
    
    // Check for duplicates and insert new IPs
    const checkAndInsert = (index) => {
        if (index >= ips.length) {
            return res.json({ added, duplicates });
        }
        
        const ip = ips[index];
        
        // Check if this user already has this IP
        db.get(
            'SELECT * FROM ip_addresses WHERE ip = ? AND user_id = ?',
            [ip, req.user.id],
            (err, row) => {
                if (err) {
                    return res.status(500).json({ message: 'Database error' });
                }
                
                if (row) {
                    duplicates++;
                    checkAndInsert(index + 1);
                } else {
                    db.run(
                        'INSERT INTO ip_addresses (ip, user_id) VALUES (?, ?)',
                        [ip, req.user.id],
                        function(err) {
                            if (err) {
                                return res.status(500).json({ message: 'Database error' });
                            }
                            added++;
                            checkAndInsert(index + 1);
                        }
                    );
                }
            }
        );
    };
    
    checkAndInsert(0);
});

// Get user stats
app.get('/api/my/stats', authenticateToken, (req, res) => {
    const userId = req.user.id;
    
    // Get total IPs
    db.get(
        'SELECT COUNT(*) as count FROM ip_addresses WHERE user_id = ?',
        [userId],
        (err, ipResult) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            
            // Get duplicate count (simplified - in a real app you'd have better logic)
            db.get(
                `SELECT COUNT(*) as count FROM ip_addresses WHERE user_id = ? 
                 AND ip IN (SELECT ip FROM ip_addresses GROUP BY ip HAVING COUNT(*) > 1)`,
                [userId],
                (err, dupResult) => {
                    if (err) {
                        return res.status(500).json({ message: 'Database error' });
                    }
                    
                    // Get last upload time
                    db.get(
                        'SELECT created_at FROM ip_addresses WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
                        [userId],
                        (err, timeResult) => {
                            if (err) {
                                return res.status(500).json({ message: 'Database error' });
                            }
                            
                            res.json({
                                totalIPs: ipResult.count,
                                duplicates: dupResult.count,
                                lastUpload: timeResult ? timeResult.created_at : null
                            });
                        }
                    );
                }
            );
        }
    );
});

// Get recent IPs for user
app.get('/api/my/recent-ips', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM ip_addresses WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
        [req.user.id],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            res.json(rows);
        }
    );
});

// Admin stats
app.get('/api/admin/stats', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    
    // Get total IPs
    db.get('SELECT COUNT(*) as count FROM ip_addresses', (err, ipResult) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        
        // Get total employees
        db.get('SELECT COUNT(*) as count FROM users WHERE role = "employee"', (err, empResult) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            
            // Get total duplicates
            db.get(
                `SELECT COUNT(*) as count FROM (
                    SELECT ip FROM ip_addresses GROUP BY ip HAVING COUNT(*) > 1
                )`,
                (err, dupResult) => {
                    if (err) {
                        return res.status(500).json({ message: 'Database error' });
                    }
                    
                    res.json({
                        totalIPs: ipResult.count,
                        totalEmployees: empResult.count,
                        totalDuplicates: dupResult.count
                    });
                }
            );
        });
    });
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