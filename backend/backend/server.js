const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const dotenv = require('dotenv');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
}));

// CORS configuration for GitHub Pages
app.use(cors({
  origin: ['https://mohamedsillahkanu.github.io', 'http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Logging
app.use(morgan('combined'));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database setup
const db = new sqlite3.Database('./mdm_production.db');

// Initialize database with better schema
db.serialize(() => {
  // Users table for authentication
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    email TEXT,
    role TEXT,
    created_at DATETIME,
    last_login DATETIME
  )`);

  // Devices table with more fields
  db.run(`CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    device_id TEXT UNIQUE,
    name TEXT,
    type TEXT,
    model TEXT,
    os_version TEXT,
    status TEXT,
    last_seen DATETIME,
    user_id TEXT,
    user_name TEXT,
    enrolled_at DATETIME,
    battery_level INTEGER,
    storage_used TEXT,
    ip_address TEXT,
    location TEXT,
    compliance_status TEXT,
    encryption_status BOOLEAN,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Commands table
  db.run(`CREATE TABLE IF NOT EXISTS commands (
    id TEXT PRIMARY KEY,
    device_id TEXT,
    command TEXT,
    parameters TEXT,
    status TEXT,
    issued_by TEXT,
    issued_at DATETIME,
    completed_at DATETIME,
    result TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id),
    FOREIGN KEY(issued_by) REFERENCES users(id)
  )`);

  // Policies table
  db.run(`CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    type TEXT,
    settings TEXT,
    created_by TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    assigned_devices TEXT
  )`);

  // Applications table
  db.run(`CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    name TEXT,
    package_name TEXT,
    version TEXT,
    type TEXT,
    status TEXT,
    device_id TEXT,
    installed_at DATETIME,
    FOREIGN KEY(device_id) REFERENCES devices(id)
  )`);

  // Activity logs
  db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
    id TEXT PRIMARY KEY,
    action TEXT,
    device_id TEXT,
    user_id TEXT,
    details TEXT,
    ip_address TEXT,
    created_at DATETIME,
    FOREIGN KEY(device_id) REFERENCES devices(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Create default admin user if not exists
  const adminId = uuidv4();
  const defaultPassword = process.env.ADMIN_PASSWORD || 'Admin@123';
  const saltRounds = 10;
  
  bcrypt.hash(defaultPassword, saltRounds, (err, hash) => {
    if (err) return;
    
    db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
      if (!row) {
        db.run(
          'INSERT INTO users (id, username, password_hash, email, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
          [adminId, 'admin', hash, 'admin@mdm.local', 'super_admin', new Date().toISOString()]
        );
        console.log('✅ Default admin user created');
        console.log('   Username: admin');
        console.log('   Password:', defaultPassword);
      }
    });
  });

  // Add sample devices for demo
  const sampleDevices = [
    ['dev1', 'SN12345', 'Mike\'s Pixel 7', 'Android', 'Pixel 7', 'Android 14', 'active', new Date().toISOString(), 'user1', 'Mike', new Date().toISOString(), '85', '64/128GB', '192.168.1.101', 'Conference Room', 'compliant', 1],
    ['dev2', 'SN67890', 'Lisa\'s iPhone 15', 'iOS', 'iPhone 15', 'iOS 17', 'active', new Date().toISOString(), 'user2', 'Lisa', new Date().toISOString(), '92', '128/256GB', '192.168.1.102', 'Office', 'compliant', 1],
    ['dev3', 'SN54321', 'John\'s iPad Pro', 'iPadOS', 'iPad Pro', 'iPadOS 17', 'locked', new Date().toISOString(), 'user3', 'John', new Date().toISOString(), '67', '32/128GB', '192.168.1.103', 'Home Office', 'non-compliant', 1]
  ];

  sampleDevices.forEach(device => {
    db.run(
      'INSERT OR IGNORE INTO devices (id, device_id, name, type, model, os_version, status, last_seen, user_id, user_name, enrolled_at, battery_level, storage_used, ip_address, location, compliance_status, encryption_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      device
    );
  });

  console.log('✅ Database initialized');
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// API Routes

// Health check (no auth required)
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Login endpoint
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    bcrypt.compare(password, user.password_hash, (err, result) => {
      if (result) {
        const token = jwt.sign(
          { id: user.id, username: user.username, role: user.role },
          process.env.JWT_SECRET || 'your-secret-key',
          { expiresIn: '24h' }
        );

        // Update last login
        db.run('UPDATE users SET last_login = ? WHERE id = ?', [new Date().toISOString(), user.id]);

        res.json({ 
          token, 
          user: { 
            id: user.id, 
            username: user.username, 
            email: user.email, 
            role: user.role 
          }
        });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    });
  });
});

// Protected routes
app.get('/api/stats', authenticateToken, (req, res) => {
  db.get(`SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
    SUM(CASE WHEN status = 'locked' THEN 1 ELSE 0 END) as locked,
    SUM(CASE WHEN compliance_status = 'non-compliant' THEN 1 ELSE 0 END) as non_compliant
    FROM devices`, (err, stats) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }

    db.get('SELECT COUNT(*) as pending_commands FROM commands WHERE status = ?', ['pending'], (err2, commands) => {
      res.json({
        total: stats.total || 0,
        active: stats.active || 0,
        locked: stats.locked || 0,
        alerts: (stats.non_compliant || 0) + (commands.pending_commands || 0)
      });
    });
  });
});

app.get('/api/devices', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM devices ORDER BY last_seen DESC`, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.post('/api/devices/enroll', authenticateToken, (req, res) => {
  const { name, type, model, os_version, user_name, device_id } = req.body;
  const id = uuidv4();
  const now = new Date().toISOString();
  
  db.run(
    `INSERT INTO devices (
      id, device_id, name, type, model, os_version, status, last_seen, 
      user_name, enrolled_at, compliance_status, encryption_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, device_id || `DEV-${Date.now()}`, name, type, model, os_version, 'active', now, 
     user_name, now, 'compliant', 1],
    function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }

      // Log activity
      db.run(
        'INSERT INTO activity_logs (id, action, device_id, user_id, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [uuidv4(), 'enroll', id, req.user.id, `Device enrolled: ${name}`, req.ip, now]
      );

      res.json({ 
        success: true, 
        device: { 
          id, name, type, model, os_version, status: 'active', 
          user_name, enrolled_at: now 
        }
      });
    }
  );
});

app.post('/api/devices/:deviceId/command', authenticateToken, (req, res) => {
  const { deviceId } = req.params;
  const { command, parameters } = req.body;
  const commandId = uuidv4();
  const now = new Date().toISOString();

  db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
    if (err || !device) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }

    // Create command record
    db.run(
      'INSERT INTO commands (id, device_id, command, parameters, status, issued_by, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [commandId, deviceId, command, JSON.stringify(parameters), 'pending', req.user.id, now],
      function(err) {
        if (err) {
          res.status(500).json({ error: err.message });
          return;
        }

        // Simulate command execution (in production, device would poll and execute)
        setTimeout(() => {
          const result = executeCommand(command, device, parameters);
          
          db.run(
            'UPDATE commands SET status = ?, completed_at = ?, result = ? WHERE id = ?',
            ['completed', new Date().toISOString(), JSON.stringify(result), commandId]
          );

          // Update device status based on command
          if (command === 'lock') {
            db.run('UPDATE devices SET status = ? WHERE id = ?', ['locked', deviceId]);
          } else if (command === 'unlock') {
            db.run('UPDATE devices SET status = ? WHERE id = ?', ['active', deviceId]);
          } else if (command === 'wipe') {
            db.run('UPDATE devices SET status = ?, compliance_status = ? WHERE id = ?', 
              ['wiped', 'non-compliant', deviceId]);
          }

          // Log activity
          db.run(
            'INSERT INTO activity_logs (id, action, device_id, user_id, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [uuidv4(), command, deviceId, req.user.id, `Command ${command} executed`, req.ip, new Date().toISOString()]
          );
        }, 2000);

        res.json({ 
          success: true, 
          command_id: commandId,
          message: `Command ${command} queued for device ${device.name}`
        });
      }
    );
  });
});

// Helper function to simulate command execution
function executeCommand(command, device, parameters) {
  const results = {
    lock: { success: true, message: 'Device locked successfully' },
    unlock: { success: true, message: 'Device unlocked successfully' },
    wipe: { success: true, message: 'Device wiped successfully' },
    locate: { 
      success: true, 
      location: {
        lat: 40.7128 + (Math.random() - 0.5) * 0.1,
        lng: -74.0060 + (Math.random() - 0.5) * 0.1,
        accuracy: 10,
        timestamp: new Date().toISOString()
      }
    },
    ping: { success: true, message: 'Device responded', battery: device.battery_level },
    'install-app': { 
      success: true, 
      message: `App ${parameters?.package_name} installed`,
      package_name: parameters?.package_name
    }
  };

  return results[command] || { success: true, message: 'Command executed' };
}

app.get('/api/activity', authenticateToken, (req, res) => {
  db.all(`
    SELECT 
      a.id,
      a.action,
      a.details,
      a.created_at as time,
      d.name as device_name,
      u.username as user_name
    FROM activity_logs a
    LEFT JOIN devices d ON a.device_id = d.id
    LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC
    LIMIT 20
  `, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.get('/api/commands/history', authenticateToken, (req, res) => {
  db.all(`
    SELECT 
      c.*,
      d.name as device_name,
      u.username as issued_by_name
    FROM commands c
    LEFT JOIN devices d ON c.device_id = d.id
    LEFT JOIN users u ON c.issued_by = u.id
    ORDER BY c.issued_at DESC
    LIMIT 50
  `, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Webhook endpoint for devices to report status
app.post('/api/device/webhook', (req, res) => {
  const { device_id, status, battery, location, apps } = req.body;

  db.run(
    `UPDATE devices 
     SET status = ?, last_seen = ?, battery_level = ?, location = ?, ip_address = ?
     WHERE device_id = ?`,
    [status, new Date().toISOString(), battery, location, req.ip, device_id],
    function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }

      // Update apps if provided
      if (apps && Array.isArray(apps)) {
        apps.forEach(app => {
          db.run(
            'INSERT OR REPLACE INTO applications (id, name, package_name, version, type, status, device_id, installed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [uuidv4(), app.name, app.package_name, app.version, app.type, 'installed', device_id, new Date().toISOString()]
          );
        });
      }

      res.json({ success: true, message: 'Status updated' });
    }
  );
});

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'public')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Start server
app.listen(PORT, () => {
  console.log(`
  🚀 MDM Production Server
  =========================
  📱 Server: http://localhost:${PORT}
  🔑 API: http://localhost:${PORT}/api
  💾 Database: SQLite
  🌍 Environment: ${process.env.NODE_ENV || 'development'}
  =========================
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing database...');
  db.close();
  process.exit(0);
});
