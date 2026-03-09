const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const dbPath = path.resolve(__dirname, 'gym.db');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                name TEXT,
                phone TEXT,
                role TEXT DEFAULT 'user',
                join_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                membership_type TEXT,
                membership_end_date DATETIME
            )`, (err) => {
                if (err) {
                    console.error('Error creating users table', err.message);
                } else {
                    // Create default admin if not exists
                    db.get("SELECT * FROM users WHERE username = 'admin'", async (err, row) => {
                        if (!row) {
                            const salt = await bcrypt.genSalt(10);
                            const hashedPassword = await bcrypt.hash('admin123', salt);
                            db.run(`INSERT INTO users (username, password, name, phone, role) VALUES (?, ?, ?, ?, ?)`, 
                                ['admin', hashedPassword, 'Admin User', '0000000000', 'admin'], (err) => {
                                    if (err) {
                                        console.error('Error creating default admin', err.message);
                                    } else {
                                        console.log('Created default admin (admin / admin123)');
                                    }
                                }
                            );
                        }
                    });
                }
            });
        });
    }
});

module.exports = db;
