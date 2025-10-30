require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// Simple in-memory cache implementation
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes default TTL

const getCachedData = (key) => {
  const item = cache.get(key);
  if (item && Date.now() < item.expiry) {
    return item.data;
  }
  cache.delete(key);
  return null;
};

const setCachedData = (key, data, ttl = CACHE_TTL) => {
  cache.set(key, {
    data,
    expiry: Date.now() + ttl
  });
};

const clearCache = (pattern) => {
  if (typeof pattern === 'string') {
    cache.delete(pattern);
  } else if (pattern instanceof RegExp) {
    for (const key of cache.keys()) {
      if (pattern.test(key)) {
        cache.delete(key);
      }
    }
  }
};

const clearAllArticleCache = () => {
  // Clear all article-related cache keys
  for (const key of cache.keys()) {
    if (key.startsWith('articles-') || key.startsWith('debate-topics') || key.startsWith('topics')) {
      cache.delete(key);
    }
  }
};

// SSE clients for real-time updates
const updateClients = new Set();

// Database connection
let pool;
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { 
      rejectUnauthorized: false,
      sslmode: 'require'
    }
  });
} else {
  pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: { 
      rejectUnauthorized: false,
      sslmode: 'require'
    }
  });
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://urown-delta.vercel.app',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Serve static files from the React app
const buildPath = path.join(__dirname, '../urown-frontend/build');
const publicPath = path.join(__dirname, '../urown-frontend/public');

// Check if build directory exists before serving it
if (fs.existsSync(buildPath)) {
  app.use(express.static(buildPath));
} else {
  console.log('Build directory not found. Using public directory for static files.');
}

// Check if public directory exists before serving it
if (fs.existsSync(publicPath)) {
  app.use(express.static(publicPath));
} else {
  console.log('Public directory not found. Some static files may not be available.');
}

// Handle specific static files explicitly with fallbacks
app.get('/favicon.ico', (req, res) => {
  const faviconPath = path.join(publicPath, 'favicon.ico');
  if (fs.existsSync(faviconPath)) {
    res.sendFile(faviconPath);
  } else {
    res.status(404).send('Favicon not found');
  }
});

app.get('/apple-touch-icon.png', (req, res) => {
  const iconPath = path.join(publicPath, 'apple-touch-icon.png');
  if (fs.existsSync(iconPath)) {
    res.sendFile(iconPath);
  } else {
    res.status(404).send('Apple touch icon not found');
  }
});

app.get('/manifest.json', (req, res) => {
  const manifestPath = path.join(publicPath, 'manifest.json');
  if (fs.existsSync(manifestPath)) {
    res.sendFile(manifestPath);
  } else {
    res.status(404).send('Manifest not found');
  }
});

// Session configuration
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  }
}));

// Environment-based rate limiting
const isDevelopment = process.env.NODE_ENV === 'development';

const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: isDevelopment ? 10000 : parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 1000,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// More lenient rate limiting for authenticated routes
const authLimiter = rateLimit({
  windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: isDevelopment ? 20000 : parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS) || 2000,
  message: { error: 'Too many requests from this account, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => !req.user,
});

// Apply general limiter to all routes
app.use('/api', generalLimiter);

// Apply more lenient limiter to authenticated routes
app.use('/api/user', authLimiter);

// Database initialization
const initDatabase = async () => {
  try {
    // Check if the full_name column needs to be modified
    try {
      const columnCheck = await pool.query(`
        SELECT column_name, is_nullable 
        FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'full_name'
      `);
      
      if (columnCheck.rows.length > 0 && columnCheck.rows[0].is_nullable === 'NO') {
        await pool.query(`
          ALTER TABLE users ALTER COLUMN full_name DROP NOT NULL
        `);
        console.log('Modified full_name column to allow NULL values');
      }
    } catch (alterError) {
      console.log('Could not alter full_name column:', alterError.message);
    }
    
    // Create users table first (no dependencies)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20),
        full_name VARCHAR(255),
        display_name VARCHAR(100) NOT NULL UNIQUE,
        date_of_birth DATE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        tier VARCHAR(20) DEFAULT 'Silver',
        weekly_articles_count INTEGER DEFAULT 0,
        weekly_reset_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        terms_agreed BOOLEAN DEFAULT FALSE,
        role VARCHAR(20) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        display_name_updated_at TIMESTAMP,
        email_updated_at TIMESTAMP,
        phone_updated_at TIMESTAMP,
        password_updated_at TIMESTAMP,
        account_status VARCHAR(20) DEFAULT 'active',
        soft_deleted_at TIMESTAMP,
        hard_deleted_at TIMESTAMP,
        deletion_reason TEXT,
        followers INTEGER DEFAULT 0,
        CONSTRAINT min_age CHECK (date_of_birth <= CURRENT_DATE - INTERVAL '15 years')
      )
    `);

    // Create followers table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS followers (
        id SERIAL PRIMARY KEY,
        follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(follower_id, following_id)
      )
    `);

    // Create trigger to update followers count
    await pool.query(`
      CREATE OR REPLACE FUNCTION update_followers_count()
      RETURNS TRIGGER AS $$       BEGIN
        IF TG_OP = 'INSERT' THEN
          UPDATE users SET followers = followers + 1 WHERE id = NEW.following_id;
          RETURN NEW;
        ELSIF TG_OP = 'DELETE' THEN
          UPDATE users SET followers = followers - 1 WHERE id = OLD.following_id;
          RETURN OLD;
        END IF;
        RETURN NULL;
      END;
      $$ LANGUAGE plpgsql;
    `);

    await pool.query(`
      DROP TRIGGER IF EXISTS followers_trigger ON followers;
      CREATE TRIGGER followers_trigger
        AFTER INSERT OR DELETE ON followers
        FOR EACH ROW
        EXECUTE FUNCTION update_followers_count();
    `);

    // Create topics table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS topics (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create article_topics junction table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS article_topics (
        article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
        topic_id INTEGER REFERENCES topics(id) ON DELETE CASCADE,
        PRIMARY KEY (article_id, topic_id)
      )
    `);

    // Create debate_topics table (referenced by articles)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS debate_topics (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Create articles table (references debate_topics)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS articles (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        published BOOLEAN DEFAULT FALSE,
        featured BOOLEAN DEFAULT FALSE,
        views INTEGER DEFAULT 0,
        parent_article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
        debate_topic_id INTEGER REFERENCES debate_topics(id) ON DELETE CASCADE,
        is_debate_winner BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create session table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS session (
        sid varchar NOT NULL,
        sess json NOT NULL,
        expire timestamp(6) NOT NULL,
        PRIMARY KEY (sid)
      )
    `);

    // Create editorial board certifications table with expiration support
    await pool.query(`
      CREATE TABLE IF NOT EXISTS editorial_certifications (
        id SERIAL PRIMARY KEY,
        article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
        admin_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        certified BOOLEAN DEFAULT FALSE,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(article_id)
      )
    `);
    
    // Create audit log table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(50) NOT NULL,
        target_type VARCHAR(50) NOT NULL,
        target_id INTEGER NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create contact messages table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(20),
        category VARCHAR(50) NOT NULL,
        content TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'waiting' CHECK (status IN ('waiting', 'in_progress', 'resolved')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT email_or_phone_required CHECK (email IS NOT NULL OR phone IS NOT NULL)
      )
    `);

    // Create reported articles table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reported_articles (
        id SERIAL PRIMARY KEY,
        article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        reason TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'reviewed', 'resolved', 'dismissed')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create user_warnings table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_warnings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reason TEXT NOT NULL,
        admin_id INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create user_bans table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_bans (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ban_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ban_end TIMESTAMP NOT NULL,
        reason TEXT NOT NULL,
        admin_id INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create debate_winners table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS debate_winners (
        id SERIAL PRIMARY KEY,
        debate_topic_id INTEGER REFERENCES debate_topics(id) ON DELETE CASCADE,
        article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
        selected_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        selected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(debate_topic_id, article_id)
      )
    `);

    // Insert default topics if they don't exist
    const defaultTopics = [
      'Politics', 'Business', 'Finance', 'Sports', 'Food', 'Travel',
      'Technology', 'Health', 'Entertainment', 'Science', 'Environment'
    ];

    for (const topic of defaultTopics) {
      await pool.query(`
        INSERT INTO topics (name) 
        VALUES ($1) 
        ON CONFLICT (name) DO NOTHING
      `, [topic]);
    }

    // Set super-admin for the specified user
    try {
      await pool.query(`
        UPDATE users 
        SET role = 'super-admin' 
        WHERE id = 1 AND email = 'natolilemessa089@gmail.com'
      `);
      console.log('Super-admin assigned to user ID 1');
    } catch (updateError) {
      console.log('Could not update super-admin:', updateError.message);
    }

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
};

// Function to check and expire certifications
const checkExpiredCertifications = async () => {
  try {
    const result = await pool.query(`
      UPDATE editorial_certifications 
      SET certified = FALSE 
      WHERE certified = TRUE AND expires_at <= CURRENT_TIMESTAMP
      RETURNING article_id
    `);
    
    if (result.rows.length > 0) {
      console.log(`Expired ${result.rows.length} certifications`);
      clearAllArticleCache();
      
      // Notify clients about certification changes
      result.rows.forEach(row => {
        updateClients.forEach(client => {
          client.write(`data: ${JSON.stringify({ type: 'certification_expired', articleId: row.article_id })}\n\n`);
        });
      });
    }
  } catch (error) {
    console.error('Error checking expired certifications:', error);
  }
};

// Check expired certifications every hour
setInterval(checkExpiredCertifications, 60 * 60 * 1000);

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    // Check if user is banned
    try {
      const banResult = await pool.query(
        'SELECT ban_end, reason FROM user_bans WHERE user_id = $1 AND ban_end > CURRENT_TIMESTAMP',
        [user.userId]
      );

      if (banResult.rows.length > 0) {
        const ban = banResult.rows[0];
        const banEnd = new Date(ban.ban_end);
        const now = new Date();
        const diffMs = banEnd - now;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

        let timeLeft = '';
        if (diffDays > 0) {
          timeLeft = `${diffDays} day${diffDays !== 1 ? 's' : ''}`;
          if (diffHours > 0) {
            timeLeft += ` and ${diffHours} hour${diffHours !== 1 ? 's' : ''}`;
          }
        } else {
          timeLeft = `${diffHours} hour${diffHours !== 1 ? 's' : ''}`;
        }

        return res.status(401).json({ 
          error: `Your account has been banned. Reason: "${ban.reason}." The ban will expire in ${timeLeft}. If you disagree contact us at, nilecommun@gmail.com` 
        });
      }
    } catch (error) {
      console.error('Error checking ban status:', error);
    }

    req.user = user;
    next();
  });
};

// Middleware to check if user is an admin
const authenticateAdmin = (req, res, next) => {
  authenticateToken(req, res, async () => {
    try {
      const result = await pool.query(
        'SELECT role FROM users WHERE id = $1',
        [req.user.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const user = result.rows[0];
      
      if (user.role !== 'admin' && user.role !== 'super-admin') {
        return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
      }

      req.user.role = user.role;
      next();
    } catch (error) {
      console.error('Admin authentication error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
};

// Middleware to check if user is a super-admin
const authenticateSuperAdmin = (req, res, next) => {
  authenticateToken(req, res, async () => {
    try {
      const result = await pool.query(
        'SELECT role FROM users WHERE id = $1',
        [req.user.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const user = result.rows[0];
      
      if (user.role !== 'super-admin') {
        return res.status(403).json({ error: 'Access denied. Super-admin privileges required.' });
      }

      req.user.role = user.role;
      next();
    } catch (error) {
      console.error('Super-admin authentication error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
};

// Middleware to check if user is an editorial board member
const authenticateEditorialBoard = (req, res, next) => {
  authenticateToken(req, res, async () => {
    try {
      const result = await pool.query(
        'SELECT role FROM users WHERE id = $1',
        [req.user.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const user = result.rows[0];
      
      if (user.role !== 'editorial-board' && user.role !== 'admin' && user.role !== 'super-admin') {
        return res.status(403).json({ error: 'Access denied. Editorial board privileges required.' });
      }

      req.user.role = user.role;
      next();
    } catch (error) {
      console.error('Editorial board authentication error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
};

// Function to log admin actions
const logAdminAction = async (adminId, action, targetType, targetId, details = null) => {
  try {
    await pool.query(
      `INSERT INTO audit_log (admin_id, action, target_type, target_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [adminId, action, targetType, targetId, details]
    );
  } catch (error) {
    console.error('Error logging admin action:', error);
  }
};

// Function to notify clients of updates
const notifyClients = (data) => {
  updateClients.forEach(client => {
    client.write(`data: ${JSON.stringify(data)}\n\n`);
  });
};

// Validation middleware
const validateSignup = [
  body('email').notEmpty().withMessage('Email is required')
    .isEmail().normalizeEmail().withMessage('Please enter a valid email address'),
  body('phone').optional({ checkFalsy: true }).isMobilePhone('any').withMessage('Please enter a valid phone number'),
  body('full_name').isLength({ min: 2, max: 255 }).trim().withMessage('Full name must be at least 2 characters'),
  body('display_name').isLength({ min: 2, max: 100 }).trim().withMessage('Display name must be at least 2 characters'),
  body('date_of_birth').isISO8601().toDate().withMessage('Please enter a valid date of birth'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number'),
  body('terms_agreed').equals('true').withMessage('You must agree to the terms of service'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(error => error.msg);
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errorMessages 
      });
    }
    next();
  }
];

const validateLogin = [
  body('identifier').notEmpty().trim(),
  body('password').notEmpty(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }
    next();
  }
];

// SSE endpoint for real-time updates
app.get('/api/updates', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  // Send initial connection message
  res.write(`data: ${JSON.stringify({ type: 'connected' })}\n\n`);
  
  // Add client to updateClients set
  updateClients.add(res);
  
  // Clean up on disconnect
  req.on('close', () => {
    updateClients.delete(res);
  });
  
  req.on('error', () => {
    updateClients.delete(res);
  });
});

// Routes
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT NOW()');
    res.json({ status: 'OK', message: 'UROWN API is running and database connection is working' });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ status: 'ERROR', message: 'Database connection failed' });
  }
});

// Get all available topics
app.get('/api/topics', async (req, res) => {
  try {
    const cacheKey = 'topics-all';
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      const result = await pool.query('SELECT * FROM topics ORDER BY name');
      cachedData = result.rows;
      setCachedData(cacheKey, cachedData, 10 * 60 * 1000); // Cache for 10 minutes
    }
    
    res.json({ topics: cachedData });
  } catch (error) {
    console.error('Get topics error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Submit contact form (public route)
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, category, content } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Name is required' });
    }

    if (!email && !phone) {
      return res.status(400).json({ error: 'Either email or phone number is required' });
    }

    if (email && !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!category || !category.trim()) {
      return res.status(400).json({ error: 'Category is required' });
    }

    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const result = await pool.query(
      `INSERT INTO contact_messages (name, email, phone, category, content)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name.trim(), email || null, phone || null, category.trim(), content.trim()]
    );

    res.status(201).json({
      message: 'Contact message submitted successfully',
      contact: result.rows[0]
    });

  } catch (error) {
    console.error('Contact form submission error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all contact messages (super-admin only)
app.get('/api/admin/contacts', authenticateSuperAdmin, async (req, res) => {
  try {
    const { status, category } = req.query;
    
    let query = 'SELECT * FROM contact_messages';
    const params = [];
    
    if (status || category) {
      query += ' WHERE';
      
      if (status) {
        query += ' status = $1';
        params.push(status);
      }
      
      if (category) {
        if (status) {
          query += ' AND';
          query += ` category = $${params.length + 1}`;
        } else {
          query += ' category = $1';
        }
        params.push(category);
      }
    }
    
    query += ' ORDER BY created_at DESC';
    
    const result = await pool.query(query, params);
    
    res.json({ contacts: result.rows });
  } catch (error) {
    console.error('Get contact messages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update contact message status (super-admin only)
app.put('/api/admin/contacts/:id/status', authenticateSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['waiting', 'in_progress', 'resolved'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const contactResult = await pool.query(
      'SELECT * FROM contact_messages WHERE id = $1',
      [id]
    );

    if (contactResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    await pool.query(
      'UPDATE contact_messages SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [status, id]
    );

    res.json({ message: 'Status updated successfully' });
  } catch (error) {
    console.error('Update contact status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete contact message (super-admin only)
app.delete('/api/admin/contacts/:id', authenticateSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const contactResult = await pool.query(
      'SELECT * FROM contact_messages WHERE id = $1',
      [id]
    );

    if (contactResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    await pool.query('DELETE FROM contact_messages WHERE id = $1', [id]);

    res.json({ message: 'Contact message deleted successfully' });
  } catch (error) {
    console.error('Delete contact message error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Report an article
app.post('/api/articles/:id/report', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    const userId = req.user.userId;

    const articleResult = await pool.query(
      'SELECT * FROM articles WHERE id = $1',
      [id]
    );

    if (articleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }

    const existingReport = await pool.query(
      'SELECT id FROM reported_articles WHERE article_id = $1 AND user_id = $2',
      [id, userId]
    );

    if (existingReport.rows.length > 0) {
      return res.status(400).json({ error: 'You have already reported this article' });
    }

    const result = await pool.query(
      `INSERT INTO reported_articles (article_id, user_id, reason)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [id, userId, reason]
    );

    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'article_reported', articleId: id });

    res.status(201).json({
      message: 'Article reported successfully',
      report: result.rows[0]
    });

  } catch (error) {
    console.error('Report article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all reported articles (admin only)
app.get('/api/admin/reported-articles', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    
    let query = `
      SELECT ra.*, a.title as article_title, a.content as article_content, 
             u.display_name as reporter_name, u.email as reporter_email,
             au.display_name as author_name
      FROM reported_articles ra
      JOIN articles a ON ra.article_id = a.id
      LEFT JOIN users u ON ra.user_id = u.id
      LEFT JOIN users au ON a.user_id = au.id
    `;
    
    const params = [];
    
    if (status) {
      query += ' WHERE ra.status = $1';
      params.push(status);
    }
    
    query += ' ORDER BY ra.created_at DESC';
    
    const result = await pool.query(query, params);
    
    res.json({ reportedArticles: result.rows });
  } catch (error) {
    console.error('Get reported articles error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update report status (admin only)
app.put('/api/admin/reported-articles/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'reviewed', 'resolved', 'dismissed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const reportResult = await pool.query(
      'SELECT * FROM reported_articles WHERE id = $1',
      [id]
    );

    if (reportResult.rows.length === 0) {
      return res.status(404).json({ error: 'Report not found' });
    }

    await pool.query(
      'UPDATE reported_articles SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [status, id]
    );

    res.json({ message: 'Status updated successfully' });
  } catch (error) {
    console.error('Update report status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete reported article (admin only)
app.delete('/api/admin/articles/:id/delete', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const articleResult = await pool.query(
      `SELECT a.*, u.display_name as author_name 
       FROM articles a
       JOIN users u ON a.user_id = u.id
       WHERE a.id = $1`,
      [id]
    );
    
    if (articleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }
    
    const article = articleResult.rows[0];
    
    await pool.query('DELETE FROM articles WHERE id = $1', [id]);
    
    await logAdminAction(
      req.user.userId,
      'delete_reported',
      'article',
      parseInt(id),
      `Deleted reported article: ${article.title} by ${article.author_name}`
    );
    
    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'article_deleted', articleId: id });
    
    res.json({ message: 'Article deleted successfully' });
  } catch (error) {
    console.error('Delete reported article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Give a warning to a user
app.post('/api/admin/users/:userId/warnings', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body;
    
    if (!reason || !reason.trim()) {
      return res.status(400).json({ error: 'Reason is required' });
    }

    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    if (user.account_status === 'soft_deleted' || user.account_status === 'hard_deleted') {
      return res.status(400).json({ error: 'Cannot warn a deleted account' });
    }

    await pool.query(
      `INSERT INTO user_warnings (user_id, reason, admin_id)
       VALUES ($1, $2, $3)`,
      [userId, reason, req.user.userId]
    );

    const warningCountResult = await pool.query(
      'SELECT COUNT(*) as count FROM user_warnings WHERE user_id = $1',
      [userId]
    );

    const warningCount = parseInt(warningCountResult.rows[0].count);

    if (warningCount >= 3) {
      await pool.query(
        `UPDATE users 
         SET account_status = 'soft_deleted', 
             soft_deleted_at = CURRENT_TIMESTAMP,
             deletion_reason = 'Account deleted due to 3 warnings'
         WHERE id = $1`,
        [userId]
      );

      await logAdminAction(
        req.user.userId,
        'soft_delete',
        'user',
        parseInt(userId),
        `Soft deleted user ${user.display_name} due to 3 warnings`
      );
    }

    res.json({ 
      message: 'Warning added successfully',
      warningCount,
      accountDeleted: warningCount >= 3
    });

  } catch (error) {
    console.error('Add warning error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove a warning from a user
app.delete('/api/admin/users/:userId/warnings/:warningId', authenticateAdmin, async (req, res) => {
  try {
    const { userId, warningId } = req.params;

    const warningResult = await pool.query(
      'SELECT * FROM user_warnings WHERE id = $1 AND user_id = $2',
      [warningId, userId]
    );

    if (warningResult.rows.length === 0) {
      return res.status(404).json({ error: 'Warning not found' });
    }

    await pool.query(
      'DELETE FROM user_warnings WHERE id = $1',
      [warningId]
    );

    const warningCountResult = await pool.query(
      'SELECT COUNT(*) as count FROM user_warnings WHERE user_id = $1',
      [userId]
    );

    const warningCount = parseInt(warningCountResult.rows[0].count);

    if (warningCount < 3) {
      const userResult = await pool.query(
        'SELECT * FROM users WHERE id = $1',
        [userId]
      );

      const user = userResult.rows[0];
      
      if (user.account_status === 'soft_deleted' && user.deletion_reason === 'Account deleted due to 3 warnings') {
        await pool.query(
          `UPDATE users 
           SET account_status = 'active', 
               soft_deleted_at = NULL,
               deletion_reason = NULL
           WHERE id = $1`,
          [userId]
        );

        await logAdminAction(
          req.user.userId,
          'reactivate',
          'user',
          parseInt(userId),
          `Reactivated user ${user.display_name} after warning removal`
        );
      }
    }

    res.json({ 
      message: 'Warning removed successfully',
      warningCount
    });

  } catch (error) {
    console.error('Remove warning error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get users with warnings (accounts to delete)
app.get('/api/admin/users/accounts-to-delete', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, 
        u.display_name, 
        u.email, 
        u.account_status,
        u.soft_deleted_at,
        COUNT(w.id) as warning_count,
        MAX(w.created_at) as last_warning_at
      FROM users u
      LEFT JOIN user_warnings w ON u.id = w.user_id
      WHERE u.account_status IN ('active', 'soft_deleted')
      GROUP BY u.id
      HAVING COUNT(w.id) >= 3 OR u.account_status = 'soft_deleted'
      ORDER BY u.soft_deleted_at DESC NULLS LAST, u.created_at DESC
    `);

    res.json({ users: result.rows });
  } catch (error) {
    console.error('Get accounts to delete error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Undo account deletion
app.post('/api/admin/users/:userId/undo-delete', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1 AND account_status = $2',
      [userId, 'soft_deleted']
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Soft deleted user not found' });
    }

    const user = userResult.rows[0];

    await pool.query(
      `UPDATE users 
       SET account_status = 'active', 
           soft_deleted_at = NULL,
           deletion_reason = NULL
       WHERE id = $1`,
      [userId]
    );

    await logAdminAction(
      req.user.userId,
      'undo_delete',
      'user',
      parseInt(userId),
      `Undeleted user ${user.display_name}`
    );

    res.json({ message: 'Account reactivated successfully' });

  } catch (error) {
    console.error('Undo delete error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Cleanup old warnings
app.post('/api/admin/cleanup-warnings', authenticateAdmin, async (req, res) => {
  try {
    const usersToClean = await pool.query(`
      SELECT user_id, MAX(created_at) as last_warning
      FROM user_warnings
      GROUP BY user_id
      HAVING MAX(created_at) < CURRENT_TIMESTAMP - INTERVAL '14 days'
    `);

    let cleanedCount = 0;
    
    for (const user of usersToClean.rows) {
      await pool.query(
        'DELETE FROM user_warnings WHERE user_id = $1',
        [user.user_id]
      );
      
      cleanedCount++;
    }

    res.json({ 
      message: 'Warning cleanup completed',
      usersCleaned: cleanedCount
    });

  } catch (error) {
    console.error('Cleanup warnings error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Hard delete accounts that have been soft deleted for 5+ days
app.post('/api/admin/hard-delete-accounts', authenticateAdmin, async (req, res) => {
  try {
    const usersToDelete = await pool.query(`
      SELECT id, display_name, email
      FROM users
      WHERE account_status = 'soft_deleted' 
        AND soft_deleted_at <= CURRENT_TIMESTAMP - INTERVAL '5 days'
    `);

    let deletedCount = 0;
    
    for (const user of usersToDelete.rows) {
      await pool.query(
        'DELETE FROM users WHERE id = $1',
        [user.id]
      );
      
      await logAdminAction(
        req.user.userId,
        'hard_delete',
        'user',
        parseInt(user.id),
        `Hard deleted user ${user.display_name} (${user.email})`
      );
      
      deletedCount++;
    }

    res.json({ 
      message: 'Account hard deletion completed',
      usersDeleted: deletedCount
    });

  } catch (error) {
    console.error('Hard delete accounts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Ban a user
app.post('/api/admin/users/:id/ban', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { banEnd, reason } = req.body;

    if (!banEnd || new Date(banEnd) <= new Date()) {
      return res.status(400).json({ error: 'Ban end time must be in the future' });
    }

    if (!reason || !reason.trim()) {
      return res.status(400).json({ error: 'Reason is required' });
    }

    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const existingBan = await pool.query(
      'SELECT * FROM user_bans WHERE user_id = $1 AND ban_end > CURRENT_TIMESTAMP',
      [id]
    );

    if (existingBan.rows.length > 0) {
      return res.status(400).json({ error: 'User is already banned' });
    }

    await pool.query(
      `INSERT INTO user_bans (user_id, ban_end, reason, admin_id)
       VALUES ($1, $2, $3, $4)`,
      [id, banEnd, reason, req.user.userId]
    );

    await logAdminAction(
      req.user.userId,
      'ban',
      'user',
      parseInt(id),
      `Banned user until ${banEnd}. Reason: ${reason}`
    );

    res.json({ message: 'User banned successfully' });
  } catch (error) {
    console.error('Ban user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Unban a user
app.delete('/api/admin/users/:id/ban', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const banResult = await pool.query(
      'SELECT * FROM user_bans WHERE user_id = $1 AND ban_end > CURRENT_TIMESTAMP',
      [id]
    );

    if (banResult.rows.length === 0) {
      return res.status(404).json({ error: 'User is not currently banned' });
    }

    await pool.query(
      'UPDATE user_bans SET ban_end = CURRENT_TIMESTAMP WHERE user_id = $1',
      [id]
    );

    await logAdminAction(
      req.user.userId,
      'unban',
      'user',
      parseInt(id),
      'Unbanned user'
    );

    res.json({ message: 'User unbanned successfully' });
  } catch (error) {
    console.error('Unban user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, phone, full_name, display_name, date_of_birth, password, terms_agreed } = req.body;
    
    const errors = {};
    
    if (!email) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.email = 'Please enter a valid email address';
    }
    
    if (phone && !/^\+?[1-9]\d{1,14}$/.test(phone.replace(/\s/g, ''))) {
      errors.phone = 'Please enter a valid phone number';
    }
    
    if (full_name && full_name.trim().length > 0 && full_name.trim().length < 2) {
      errors.full_name = 'Full name must be at least 2 characters';
    }
    
    if (!display_name || display_name.trim().length < 2) {
      errors.display_name = 'Display name must be at least 2 characters';
    }
    
    if (!date_of_birth) {
      errors.date_of_birth = 'Date of birth is required';
    } else {
      const birthDate = new Date(date_of_birth);
      const today = new Date();
      const age = Math.floor((today - birthDate) / (365.25 * 24 * 60 * 60 * 1000));
      if (age < 15) {
        errors.date_of_birth = 'You must be at least 15 years old to register';
      }
    }
    
    if (!password || password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    } else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      errors.password = 'Password must contain uppercase, lowercase, and number';
    }
    
    if (terms_agreed !== true) {
      errors.terms_agreed = 'You must agree to the terms of service';
    }
    
    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors 
      });
    }
    
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR display_name = $2',
      [email, display_name]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email or display name already exists' });
    }

    const saltRounds = 12;
    const password_hash = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      `INSERT INTO users (email, phone, full_name, display_name, date_of_birth, password_hash, terms_agreed)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, email, phone, full_name, display_name, tier, role, created_at`,
      [email, phone || null, full_name || null, display_name, date_of_birth, password_hash, terms_agreed]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { userId: user.id, email: user.email, displayName: user.display_name },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        full_name: user.full_name,
        display_name: user.display_name,
        tier: user.tier,
        role: user.role,
        created_at: user.created_at
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      error: 'Internal server error', 
      details: error.message || 'An unknown error occurred during registration' 
    });
  }
});

// Login
app.post('/api/auth/login', validateLogin, async (req, res) => {
  try {
    const { identifier, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE (email = $1 OR display_name = $1) AND account_status = $2',
      [identifier, 'active']
    );

    if (result.rows.length === 0) {
      const deletedUserResult = await pool.query(
        'SELECT * FROM users WHERE (email = $1 OR display_name = $1) AND account_status IN ($2, $3)',
        [identifier, 'soft_deleted', 'hard_deleted']
      );

      if (deletedUserResult.rows.length > 0) {
        const user = deletedUserResult.rows[0];
        
        if (user.account_status === 'soft_deleted') {
          return res.status(401).json({ 
            error: `Your account has been deleted. Reason: ${user.deletion_reason || 'No reason provided'}. 
                   If you believe this is a mistake, please contact nilecommun@gmail.com.` 
          });
        } else {
          return res.status(401).json({ 
            error: 'Your account has been permanently deleted.' 
          });
        }
      }
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const banResult = await pool.query(
      'SELECT ban_end, reason FROM user_bans WHERE user_id = $1 AND ban_end > CURRENT_TIMESTAMP',
      [user.id]
    );

    if (banResult.rows.length > 0) {
      const ban = banResult.rows[0];
      const banEnd = new Date(ban.ban_end);
      const now = new Date();
      const diffMs = banEnd - now;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

      let timeLeft = '';
      if (diffDays > 0) {
        timeLeft = `${diffDays} day${diffDays !== 1 ? 's' : ''}`;
        if (diffHours > 0) {
          timeLeft += ` and ${diffHours} hour${diffHours !== 1 ? 's' : ''}`;
        }
      } else {
        timeLeft = `${diffHours} hour${diffHours !== 1 ? 's' : ''}`;
      }

      return res.status(401).json({ 
        error: `Your account has been banned. Reason: "${ban.reason}". The ban will expire in ${timeLeft}. If you disagree contact us at, nilecommun@gmail.com` 
      });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, displayName: user.display_name },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        full_name: user.full_name,
        display_name: user.display_name,
        tier: user.tier,
        role: user.role,
        weekly_articles_count: user.weekly_articles_count,
        display_name_updated_at: user.display_name_updated_at,
        email_updated_at: user.email_updated_at,
        phone_updated_at: user.phone_updated_at,
        password_updated_at: user.password_updated_at
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, phone, full_name, display_name, tier, role, weekly_articles_count, weekly_reset_date, display_name_updated_at, email_updated_at, phone_updated_at, password_updated_at, created_at, followers FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    const now = new Date();
    const resetDate = new Date(user.weekly_reset_date);
    const daysSinceReset = Math.floor((now - resetDate) / (24 * 60 * 60 * 1000));

    if (daysSinceReset >= 7) {
      await pool.query(
        'UPDATE users SET weekly_articles_count = 0, weekly_reset_date = $1 WHERE id = $2',
        [now, user.id]
      );
      user.weekly_articles_count = 0;
    }

    res.json({ user });

  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { display_name, email, phone } = req.body;

    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    const now = new Date();
    const updates = [];
    const values = [];
    let queryIndex = 1;

    if (display_name && display_name !== user.display_name) {
      const lastUpdate = user.display_name_updated_at ? new Date(user.display_name_updated_at) : null;
      const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

      if (daysSinceLastUpdate < 14) {
        const daysLeft = 14 - daysSinceLastUpdate;
        return res.status(400).json({ 
          error: `You can change your display name again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
        });
      }

      const displayNameCheck = await pool.query(
        'SELECT id FROM users WHERE display_name = $1 AND id != $2',
        [display_name, userId]
      );

      if (displayNameCheck.rows.length > 0) {
        return res.status(400).json({ error: 'Display name is already in use' });
      }

      updates.push(`display_name = $${queryIndex++}`);
      values.push(display_name);
      updates.push(`display_name_updated_at = $${queryIndex++}`);
      values.push(now);
    }

    if (email && email !== user.email) {
      const lastUpdate = user.email_updated_at ? new Date(user.email_updated_at) : null;
      const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

      if (daysSinceLastUpdate < 14) {
        const daysLeft = 14 - daysSinceLastUpdate;
        return res.status(400).json({ 
          error: `You can change your email again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
        });
      }

      const emailCheck = await pool.query(
        'SELECT id FROM users WHERE email = $1 AND id != $2',
        [email, userId]
      );

      if (emailCheck.rows.length > 0) {
        return res.status(400).json({ error: 'Email is already in use' });
      }

      updates.push(`email = $${queryIndex++}`);
      values.push(email);
      updates.push(`email_updated_at = $${queryIndex++}`);
      values.push(now);
    }

    if (phone !== undefined && phone !== user.phone) {
      const lastUpdate = user.phone_updated_at ? new Date(user.phone_updated_at) : null;
      const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

      if (daysSinceLastUpdate < 14) {
        const daysLeft = 14 - daysSinceLastUpdate;
        return res.status(400).json({ 
          error: `You can change your phone number again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
        });
      }

      if (phone) {
        const phoneCheck = await pool.query(
          'SELECT id FROM users WHERE phone = $1 AND id != $2',
          [phone, userId]
        );

        if (phoneCheck.rows.length > 0) {
          return res.status(400).json({ error: 'Phone number is already in use' });
        }
      }

      updates.push(`phone = $${queryIndex++}`);
      values.push(phone || null);
      updates.push(`phone_updated_at = $${queryIndex++}`);
      values.push(now);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No changes provided' });
    }

    values.push(userId);

    const updateQuery = `
      UPDATE users 
      SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $${queryIndex}
      RETURNING id, email, phone, full_name, display_name, tier, role, display_name_updated_at, email_updated_at, phone_updated_at, password_updated_at, created_at
    `;

    const result = await pool.query(updateQuery, values);
    const updatedUser = result.rows[0];

    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password
app.put('/api/user/password', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }

    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    const now = new Date();

    const lastUpdate = user.password_updated_at ? new Date(user.password_updated_at) : null;
    const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

    if (daysSinceLastUpdate < 14) {
      const daysLeft = 14 - daysSinceLastUpdate;
      return res.status(400).json({ 
        error: `You can change your password again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
      });
    }

    const isValidPassword = await bcrypt.compare(current_password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(new_password, saltRounds);

    await pool.query(
      'UPDATE users SET password_hash = $1, password_updated_at = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
      [newPasswordHash, now, userId]
    );

    res.json({ message: 'Password changed successfully' });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete user account (soft delete)
app.delete('/api/user', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { confirmation } = req.body;

    if (confirmation !== 'I want to delete my account') {
      return res.status(400).json({ error: 'Incorrect confirmation text' });
    }

    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    await pool.query(
      `UPDATE users 
       SET account_status = 'soft_deleted', 
           soft_deleted_at = CURRENT_TIMESTAMP,
           deletion_reason = 'User requested account deletion'
       WHERE id = $1`,
      [userId]
    );

    await logAdminAction(
      userId,
      'delete_account',
      'user',
      userId,
      `User deleted their own account: ${user.display_name} (${user.email})`
    );

    res.json({ message: 'Account deleted successfully' });

  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user statistics
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const articlesResult = await pool.query(
      `SELECT id, published, views, created_at, updated_at
       FROM articles 
       WHERE user_id = $1`,
      [req.user.userId]
    );
    
    const articles = articlesResult.rows;
    const publishedArticles = articles.filter(article => article.published).length;
    const draftArticles = articles.filter(article => !article.published).length;
    
    const totalViews = articles.reduce((sum, article) => sum + (article.views || 0), 0);
    
    res.json({
      stats: {
        totalArticles: articles.length,
        publishedArticles,
        draftArticles,
        views: totalViews
      }
    });
  } catch (error) {
    console.error('Get user stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new article
app.post('/api/articles', authenticateToken, async (req, res) => {
  try {
    const { title, content, published = false, featured = false, parent_article_id, debate_topic_id, topicIds = [] } = req.body;
    const userId = req.user.userId;

    if (!title?.trim() || !content?.trim()) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    if (title.length > 255) {
      return res.status(400).json({ error: 'Title must be 255 characters or less' });
    }

    if (topicIds.length > 3) {
      return res.status(400).json({ error: 'You can select a maximum of 3 topics' });
    }

    if (topicIds.length > 0) {
      const topicCheck = await pool.query(
        'SELECT id FROM topics WHERE id = ANY($1)',
        [topicIds]
      );
      
      if (topicCheck.rows.length !== topicIds.length) {
        return res.status(400).json({ error: 'One or more selected topics are invalid' });
      }
    }

    if (parent_article_id) {
      const parentResult = await pool.query(
        'SELECT id FROM articles WHERE id = $1 AND published = true',
        [parent_article_id]
      );

      if (parentResult.rows.length === 0) {
        return res.status(400).json({ error: 'Parent article not found or not published' });
      }

      const counterCountResult = await pool.query(
        'SELECT COUNT(*) as count FROM articles WHERE parent_article_id = $1',
        [parent_article_id]
      );

      if (parseInt(counterCountResult.rows[0].count) >= 5) {
        return res.status(400).json({ error: 'Maximum number of counter opinions reached for this article' });
      }
    }

    if (debate_topic_id) {
      const topicResult = await pool.query(
        'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
        [debate_topic_id]
      );

      if (topicResult.rows.length === 0) {
        return res.status(400).json({ error: 'Debate topic not found or expired' });
      }

      const existingOpinion = await pool.query(
        'SELECT id FROM articles WHERE debate_topic_id = $1 AND user_id = $2',
        [debate_topic_id, userId]
      );

      if (existingOpinion.rows.length > 0) {
        return res.status(400).json({ error: 'You have already written an opinion for this debate topic' });
      }
    }

    if (published && !parent_article_id && !debate_topic_id) {
      const userResult = await pool.query(
        'SELECT weekly_articles_count, tier FROM users WHERE id = $1',
        [userId]
      );
      
      const user = userResult.rows[0];
      const silverLimit = parseInt(process.env.SILVER_TIER_WEEKLY_LIMIT) || 2;
      
      if (user.weekly_articles_count >= silverLimit) {
        return res.status(400).json({ error: 'Weekly article limit reached' });
      }
    }

    const result = await pool.query(
      'INSERT INTO articles (user_id, title, content, published, featured, parent_article_id, debate_topic_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [userId, title.trim(), content.trim(), published, featured, parent_article_id || null, debate_topic_id || null]
    );

    const article = result.rows[0];

    if (topicIds.length > 0) {
      const topicValues = topicIds.map(topicId => `(${article.id}, ${topicId})`).join(', ');
      await pool.query(
        `INSERT INTO article_topics (article_id, topic_id) VALUES ${topicValues}`
      );
    }

    if (published && !parent_article_id && !debate_topic_id) {
      await pool.query(
        'UPDATE users SET weekly_articles_count = weekly_articles_count + 1 WHERE id = $1',
        [userId]
      );
    }

    const updatedUserResult = await pool.query(
      'SELECT id, email, phone, full_name, display_name, tier, role, weekly_articles_count, weekly_reset_date, display_name_updated_at, email_updated_at, phone_updated_at, password_updated_at, created_at FROM users WHERE id = $1',
      [userId]
    );

    const updatedUser = updatedUserResult.rows[0];

    const statsResult = await pool.query(
      `SELECT 
        COUNT(*) as total_articles,
        COUNT(CASE WHEN published = true THEN 1 END) as published_articles,
        COUNT(CASE WHEN published = false THEN 1 END) as draft_articles,
        COALESCE(SUM(views), 0) as total_views
       FROM articles 
       WHERE user_id = $1`,
      [userId]
    );

    const stats = {
      totalArticles: parseInt(statsResult.rows[0].total_articles),
      publishedArticles: parseInt(statsResult.rows[0].published_articles),
      draftArticles: parseInt(statsResult.rows[0].draft_articles),
      views: parseInt(statsResult.rows[0].total_views) || 0
    };

    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'article_created', article });

    res.status(201).json({
      message: published ? 'Article published successfully' : 'Article saved as draft',
      article,
      user: updatedUser,
      stats
    });

  } catch (error) {
    console.error('Create article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all published articles (for browse and homepage)
app.get('/api/articles', async (req, res) => {
  try {
    const { featured, limit = 20, offset = 0, parent_article_id, debate_topic_id, topicId, certified } = req.query;
    
    // Create cache key based on query parameters
    const cacheKey = `articles-${limit}-${offset}-${featured || 'false'}-${parent_article_id || 'null'}-${debate_topic_id || 'null'}-${topicId || 'null'}-${certified || 'false'}`;
    
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      let query = `
        SELECT a.id, a.title, a.content, a.created_at, a.updated_at, a.views, a.parent_article_id, a.debate_topic_id,
               u.display_name, u.tier,
               a.featured, ec.certified, a.is_debate_winner,
               COALESCE(
                 ARRAY_AGG(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL),
                 ARRAY[]::VARCHAR[]
               ) as topics
        FROM articles a
        JOIN users u ON a.user_id = u.id
        LEFT JOIN editorial_certifications ec ON a.id = ec.article_id
        LEFT JOIN article_topics at ON a.id = at.article_id
        LEFT JOIN topics t ON at.topic_id = t.id
        WHERE a.published = true
      `;
      
      const params = [];
      
      if (debate_topic_id) {
        query += ' AND a.debate_topic_id = $' + (params.length + 1) + ' AND a.is_debate_winner = true';
        params.push(debate_topic_id);
      } else {
        query += ' AND (a.debate_topic_id IS NULL OR a.is_debate_winner = true)';
      }
      
      if (featured === 'true') {
        query += ' AND a.featured = true';
      }
      
      if (parent_article_id) {
        query += ' AND a.parent_article_id = $' + (params.length + 1);
        params.push(parent_article_id);
      }
      
      if (topicId) {
        query += ' AND EXISTS (SELECT 1 FROM article_topics WHERE article_id = a.id AND topic_id = $' + (params.length + 1) + ')';
        params.push(topicId);
      }
      
      if (certified === 'true') {
        query += ' AND ec.certified = true';
      }
      
      query += ' GROUP BY a.id, u.display_name, u.tier, ec.certified ORDER BY a.created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
      params.push(parseInt(limit), parseInt(offset));

      const result = await pool.query(query, params);
      cachedData = result.rows;
      
      // Cache for 5 minutes
      setCachedData(cacheKey, cachedData, 5 * 60 * 1000);
    }
    
    res.json({ articles: cachedData });
  } catch (error) {
    console.error('Get articles error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's own articles
app.get('/api/user/articles', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.title, a.content, a.published, a.featured, a.views, a.created_at, a.updated_at, a.parent_article_id, a.debate_topic_id,
              ec.certified,
              COALESCE(
                ARRAY_AGG(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL),
                ARRAY[]::VARCHAR[]
              ) as topics
       FROM articles a
       LEFT JOIN editorial_certifications ec ON a.id = ec.article_id
       LEFT JOIN article_topics at ON a.id = at.article_id
       LEFT JOIN topics t ON at.topic_id = t.id
       WHERE a.user_id = $1 
       GROUP BY a.id, ec.certified
       ORDER BY a.updated_at DESC`,
      [req.user.userId]
    );

    res.json({ articles: result.rows });
  } catch (error) {
    console.error('Get user articles error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single article
app.get('/api/articles/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const cacheKey = `article-${id}`;
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      const articleResult = await pool.query(
        `SELECT a.id, a.title, a.content, a.published, a.featured, a.created_at, a.updated_at, a.views, a.parent_article_id, a.debate_topic_id,
                u.display_name, u.tier, ec.certified,
                COALESCE(
                  ARRAY_AGG(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL),
                  ARRAY[]::VARCHAR[]
                ) as topics
         FROM articles a
         JOIN users u ON a.user_id = u.id
         LEFT JOIN editorial_certifications ec ON a.id = ec.article_id
         LEFT JOIN article_topics at ON a.id = at.article_id
         LEFT JOIN topics t ON at.topic_id = t.id
         WHERE a.id = $1
         GROUP BY a.id, u.display_name, u.tier, ec.certified`,
        [id]
      );

      if (articleResult.rows.length === 0) {
        return res.status(404).json({ error: 'Article not found' });
      }

      cachedData = articleResult.rows[0];
      
      // Cache for 10 minutes
      setCachedData(cacheKey, cachedData, 10 * 60 * 1000);
    }
    
    let article = cachedData;
    
    if (!article.published) {
      const token = req.headers['authorization']?.split(' ')[1];
      if (token) {
        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET);
          const ownerCheck = await pool.query('SELECT user_id FROM articles WHERE id = $1', [id]);
          if (ownerCheck.rows[0]?.user_id !== decoded.userId) {
            return res.status(404).json({ error: 'Article not found' });
          }
        } catch {
          return res.status(404).json({ error: 'Article not found' });
        }
      } else {
        return res.status(404).json({ error: 'Article not found' });
      }
    }

    const sessionKey = `article_view_${id}`;
    const hasViewed = req.session[sessionKey];
    
    if (article.published && !hasViewed) {
      await pool.query(
        'UPDATE articles SET views = views + 1 WHERE id = $1',
        [id]
      );
      
      req.session[sessionKey] = true;
      
      const updatedViewResult = await pool.query(
        'SELECT views FROM articles WHERE id = $1',
        [id]
      );
      
      article.views = updatedViewResult.rows[0].views;
      
      // Update cache with new view count
      setCachedData(cacheKey, article, 10 * 60 * 1000);
    }

    res.json({ article });

  } catch (error) {
    console.error('Get article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update article
app.put('/api/articles/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, published, featured, topicIds = [] } = req.body;
    const userId = req.user.userId;

    const ownerCheck = await pool.query(
      'SELECT user_id, published as current_published, parent_article_id, debate_topic_id FROM articles WHERE id = $1',
      [id]
    );

    if (ownerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }

    if (ownerCheck.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to edit this article' });
    }

    const currentlyPublished = ownerCheck.rows[0].current_published;
    const isCounterOpinion = ownerCheck.rows[0].parent_article_id !== null;
    const isDebateOpinion = ownerCheck.rows[0].debate_topic_id !== null;

    if (topicIds.length > 3) {
      return res.status(400).json({ error: 'You can select a maximum of 3 topics' });
    }

    if (topicIds.length > 0) {
      const topicCheck = await pool.query(
        'SELECT id FROM topics WHERE id = ANY($1)',
        [topicIds]
      );
      
      if (topicCheck.rows.length !== topicIds.length) {
        return res.status(400).json({ error: 'One or more selected topics are invalid' });
      }
    }

    if (published && !currentlyPublished && !isCounterOpinion && !isDebateOpinion) {
      const userResult = await pool.query(
        'SELECT weekly_articles_count, tier FROM users WHERE id = $1',
        [userId]
      );
      
      const user = userResult.rows[0];
      const silverLimit = parseInt(process.env.SILVER_TIER_WEEKLY_LIMIT) || 2;
      
      if (user.weekly_articles_count >= silverLimit) {
        return res.status(400).json({ error: 'Weekly article limit reached' });
      }
    }

    const result = await pool.query(
      `UPDATE articles 
       SET title = $1, content = $2, published = $3, featured = $4, updated_at = CURRENT_TIMESTAMP
       WHERE id = $5 
       RETURNING *`,
      [title?.trim(), content?.trim(), published, featured, id]
    );

    await pool.query(
      'DELETE FROM article_topics WHERE article_id = $1',
      [id]
    );

    if (topicIds.length > 0) {
      const topicValues = topicIds.map(topicId => `(${id}, ${topicId})`).join(', ');
      await pool.query(
        `INSERT INTO article_topics (article_id, topic_id) VALUES ${topicValues}`
      );
    }

    if (published && !currentlyPublished && !isCounterOpinion && !isDebateOpinion) {
      await pool.query(
        'UPDATE users SET weekly_articles_count = weekly_articles_count + 1 WHERE id = $1',
        [userId]
      );
    }

    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'article_updated', article: result.rows[0] });

    res.json({
      message: 'Article updated successfully',
      article: result.rows[0]
    });

  } catch (error) {
    console.error('Update article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete article
app.delete('/api/articles/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    const ownerCheck = await pool.query(
      'SELECT user_id FROM articles WHERE id = $1',
      [id]
    );

    if (ownerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }

    if (ownerCheck.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to delete this article' });
    }

    await pool.query('DELETE FROM articles WHERE id = $1', [id]);

    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'article_deleted', articleId: id });

    res.json({ message: 'Article deleted successfully' });

  } catch (error) {
    console.error('Delete article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Editorial board routes

// Get articles for editorial board
app.get('/api/editorial/articles', authenticateEditorialBoard, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.title, a.content, a.published, a.featured, a.views, a.created_at, a.updated_at, a.parent_article_id, a.debate_topic_id,
              u.id as user_id, u.display_name, u.tier, u.role,
              ec.certified, dt.title as debate_topic_title, a.is_debate_winner,
              COALESCE(
                ARRAY_AGG(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL),
                ARRAY[]::VARCHAR[]
              ) as topics
       FROM articles a
       JOIN users u ON a.user_id = u.id
       LEFT JOIN editorial_certifications ec ON a.id = ec.article_id
       LEFT JOIN debate_topics dt ON a.debate_topic_id = dt.id
       LEFT JOIN article_topics at ON a.id = at.article_id
       LEFT JOIN topics t ON at.topic_id = t.id
       ORDER BY a.created_at DESC`
    );

    res.json({ articles: result.rows });
  } catch (error) {
    console.error('Get editorial articles error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle editorial certification
app.post('/api/editorial/articles/:id/certify', authenticateEditorialBoard, async (req, res) => {
  try {
    const { id } = req.params;
    const { certified, expiresAt } = req.body;
    
    const articleResult = await pool.query(
      'SELECT * FROM articles WHERE id = $1',
      [id]
    );
    
    if (articleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }
    
    const article = articleResult.rows[0];
    
    const certResult = await pool.query(
      'SELECT * FROM editorial_certifications WHERE article_id = $1',
      [id]
    );
    
    if (certResult.rows.length > 0) {
      await pool.query(
        'UPDATE editorial_certifications SET certified = $1, expires_at = $2, updated_at = CURRENT_TIMESTAMP WHERE article_id = $3',
        [certified, expiresAt || null, id]
      );
    } else {
      await pool.query(
        'INSERT INTO editorial_certifications (article_id, admin_id, certified, expires_at) VALUES ($1, $2, $3, $4)',
        [id, req.user.userId, certified, expiresAt || null]
      );
    }
    
    await logAdminAction(
      req.user.userId,
      certified ? 'certify' : 'uncertify',
      'article',
      parseInt(id),
      `${certified ? 'Certified' : 'Uncertified'} article: ${article.title}`
    );
    
    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ 
      type: 'certification_changed', 
      articleId: id, 
      certified,
      expiresAt 
    });
    
    res.json({ 
      message: certified ? 'Article certified successfully' : 'Article uncertified successfully',
      certified 
    });
  } catch (error) {
    console.error('Toggle certification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin routes

// Get all users
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.phone, u.full_name, u.display_name, u.tier, u.role, 
              u.weekly_articles_count, u.created_at, u.updated_at,
              ub.ban_end, ub.reason as ban_reason
       FROM users u
       LEFT JOIN user_bans ub ON u.id = ub.user_id AND ub.ban_end > CURRENT_TIMESTAMP
       WHERE u.account_status = 'active'
       ORDER BY u.created_at DESC`
    );

    res.json({ users: result.rows });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user by ID
app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      `SELECT u.id, u.email, u.phone, u.full_name, u.display_name, u.tier, u.role, 
              u.weekly_articles_count, u.created_at, u.updated_at,
              ub.ban_end, ub.reason as ban_reason
       FROM users u
       LEFT JOIN user_bans ub ON u.id = ub.user_id AND ub.ban_end > CURRENT_TIMESTAMP
       WHERE u.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user role
app.put('/api/admin/users/:id/role', authenticateSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    
    const validRoles = ['user', 'editorial-board', 'admin', 'super-admin'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentUser = userResult.rows[0];
    const oldRole = currentUser.role;
    
    await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2',
      [role, id]
    );
    
    await logAdminAction(
      req.user.userId,
      'update_role',
      'user',
      parseInt(id),
      `Changed role from ${oldRole} to ${role}`
    );
    
    res.json({ message: 'User role updated successfully' });
  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete user
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    await pool.query(
      `UPDATE users 
       SET account_status = 'soft_deleted', 
           soft_deleted_at = CURRENT_TIMESTAMP,
           deletion_reason = 'Account deleted by admin'
       WHERE id = $1`,
      [id]
    );
    
    await logAdminAction(
      req.user.userId,
      'delete',
      'user',
      parseInt(id),
      `Soft deleted user: ${user.display_name} (${user.email})`
    );
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all articles
app.get('/api/admin/articles', authenticateEditorialBoard, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.title, a.content, a.published, a.featured, a.views, a.created_at, a.updated_at, a.parent_article_id, a.debate_topic_id,
              u.id as user_id, u.display_name, u.tier, u.role,
              ec.certified,
              COALESCE(
                ARRAY_AGG(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL),
                ARRAY[]::VARCHAR[]
              ) as topics
       FROM articles a
       JOIN users u ON a.user_id = u.id
       LEFT JOIN editorial_certifications ec ON a.id = ec.article_id
       LEFT JOIN article_topics at ON a.id = at.article_id
       LEFT JOIN topics t ON at.topic_id = t.id
       GROUP BY a.id, u.id, u.display_name, u.tier, u.role, ec.certified
       ORDER BY a.created_at DESC`
    );

    res.json({ articles: result.rows });
  } catch (error) {
    console.error('Get articles error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete article
app.delete('/api/admin/articles/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const articleResult = await pool.query(
      `SELECT a.*, u.display_name as author_name 
       FROM articles a
       JOIN users u ON a.user_id = u.id
       WHERE a.id = $1`,
      [id]
    );
    
    if (articleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }
    
    const article = articleResult.rows[0];
    
    await pool.query('DELETE FROM articles WHERE id = $1', [id]);
    
    await logAdminAction(
      req.user.userId,
      'delete',
      'article',
      parseInt(id),
      `Deleted article: ${article.title} by ${article.author_name}`
    );
    
    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'article_deleted', articleId: id });
    
    res.json({ message: 'Article deleted successfully' });
  } catch (error) {
    console.error('Delete article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get audit log
app.get('/api/admin/audit-log', authenticateSuperAdmin, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    
    const result = await pool.query(
      `SELECT al.*, u.display_name as admin_name
       FROM audit_log al
       LEFT JOIN users u ON al.admin_id = u.id
       ORDER BY al.created_at DESC
       LIMIT $1 OFFSET $2`,
      [parseInt(limit), parseInt(offset)]
    );
    
    const countResult = await pool.query(
      'SELECT COUNT(*) FROM audit_log'
    );
    
    res.json({
      auditLog: result.rows,
      total: parseInt(countResult.rows[0].count)
    });
  } catch (error) {
    console.error('Get audit log error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get admin dashboard stats
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const userCountsResult = await pool.query(
      `SELECT role, COUNT(*) as count
       FROM users
       WHERE account_status = 'active'
       GROUP BY role`
    );
    
    const articleCountsResult = await pool.query(
      `SELECT 
         COUNT(*) as total_articles,
         COUNT(CASE WHEN published = true THEN 1 END) as published_articles,
         COUNT(CASE WHEN published = false THEN 1 END) as draft_articles,
         COUNT(CASE WHEN certified = true THEN 1 END) as certified_articles
       FROM articles a
       LEFT JOIN editorial_certifications ec ON a.id = ec.article_id`
    );
    
    const viewsResult = await pool.query(
      'SELECT COALESCE(SUM(views), 0) as total_views FROM articles'
    );
    
    const recentActivityResult = await pool.query(
      `SELECT al.action, al.target_type, al.created_at, u.display_name as admin_name
       FROM audit_log al
       LEFT JOIN users u ON al.admin_id = u.id
       ORDER BY al.created_at DESC
       LIMIT 10`
    );
    
    res.json({
      userCounts: userCountsResult.rows,
      articleStats: articleCountsResult.rows[0],
      totalViews: parseInt(viewsResult.rows[0].total_views),
      recentActivity: recentActivityResult.rows
    });
  } catch (error) {
    console.error('Get admin stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debate Topics Endpoints

// Get active debate topics
app.get('/api/debate-topics', async (req, res) => {
  try {
    console.log('Fetching debate topics...');
    
    const cacheKey = 'debate-topics-active';
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      await pool.query(`
        DELETE FROM articles 
        WHERE debate_topic_id IN (
          SELECT id FROM debate_topics WHERE expires_at <= CURRENT_TIMESTAMP
        )
      `);
      
      await pool.query(`
        DELETE FROM debate_topics 
        WHERE expires_at <= CURRENT_TIMESTAMP
      `);
      
      const result = await pool.query(`
        SELECT dt.*, COUNT(a.id) as opinions_count
        FROM debate_topics dt
        LEFT JOIN articles a ON dt.id = a.debate_topic_id
        WHERE dt.expires_at > CURRENT_TIMESTAMP
        GROUP BY dt.id
        ORDER BY dt.created_at DESC
        LIMIT 3
      `);
      
      cachedData = result.rows;
      setCachedData(cacheKey, cachedData, 2 * 60 * 1000); // Cache for 2 minutes
    }
    
    console.log(`Found ${cachedData.length} debate topics`);
    res.json({ topics: cachedData });
  } catch (error) {
    console.error('Get debate topics error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Get a specific debate topic and its opinions
app.get('/api/debate-topics/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const cacheKey = `debate-topic-${id}`;
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      const topicResult = await pool.query(
        'SELECT * FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
        [id]
      );
      
      if (topicResult.rows.length === 0) {
        return res.status(404).json({ error: 'Debate topic not found or expired' });
      }
      
      const topic = topicResult.rows[0];
      
      const opinionsResult = await pool.query(`
        SELECT a.*, u.display_name, u.tier
        FROM articles a
        JOIN users u ON a.user_id = u.id
        WHERE a.debate_topic_id = $1 AND a.published = true
        ORDER BY a.created_at DESC
      `, [id]);
      
      cachedData = { topic, opinions: opinionsResult.rows };
      setCachedData(cacheKey, cachedData, 2 * 60 * 1000);
    }
    
    res.json(cachedData);
  } catch (error) {
    console.error('Get debate topic error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get opinions for a debate topic
app.get('/api/debate-topics/:id/opinions', async (req, res) => {
  try {
    const { id } = req.params;
    
    const cacheKey = `debate-opinions-${id}`;
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      const topicCheck = await pool.query(
        'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
        [id]
      );
      
      if (topicCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Debate topic not found or expired' });
      }
      
      const opinionsResult = await pool.query(`
        SELECT a.*, u.display_name, u.tier
        FROM articles a
        JOIN users u ON a.user_id = u.id
        WHERE a.debate_topic_id = $1 AND a.published = true
        ORDER BY a.created_at DESC
      `, [id]);
      
      cachedData = opinionsResult.rows;
      setCachedData(cacheKey, cachedData, 2 * 60 * 1000);
    }
    
    res.json({ opinions: cachedData });
  } catch (error) {
    console.error('Get debate opinions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new opinion for a debate topic
app.post('/api/debate-topics/:id/opinions', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;
    const userId = req.user.userId;
    
    if (!title?.trim() || !content?.trim()) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    
    const topicCheck = await pool.query(
      'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
      [id]
    );
    
    if (topicCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found or expired' });
    }
    
    const existingOpinion = await pool.query(
      'SELECT id FROM articles WHERE debate_topic_id = $1 AND user_id = $2',
      [id, userId]
    );
    
    if (existingOpinion.rows.length > 0) {
      return res.status(400).json({ error: 'You have already written an opinion for this debate topic' });
    }
    
    const result = await pool.query(
      `INSERT INTO articles (user_id, title, content, published, debate_topic_id)
       VALUES ($1, $2, $3, true, $4)
       RETURNING *`,
      [userId, title.trim(), content.trim(), id]
    );
    
    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'debate_opinion_created', article: result.rows[0] });
    
    res.status(201).json({
      message: 'Opinion created successfully',
      article: result.rows[0]
    });
  } catch (error) {
    console.error('Create debate opinion error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new debate topic
app.post('/api/debate-topics', authenticateEditorialBoard, async (req, res) => {
  try {
    const { title, description } = req.body;
    const userId = req.user.userId;
    
    if (!title?.trim() || !description?.trim()) {
      return res.status(400).json({ error: 'Title and description are required' });
    }
    
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);
    
    const result = await pool.query(
      `INSERT INTO debate_topics (title, description, expires_at, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [title.trim(), description.trim(), expiresAt, userId]
    );
    
    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'debate_topic_created', topic: result.rows[0] });
    
    res.status(201).json({
      message: 'Debate topic created successfully',
      topic: result.rows[0]
    });
  } catch (error) {
    console.error('Create debate topic error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark an article as a winner for a debate topic
app.post('/api/debate-topics/:id/winners/:articleId', authenticateEditorialBoard, async (req, res) => {
  try {
    const { id, articleId } = req.params;
    const userId = req.user.userId;

    const topicCheck = await pool.query(
      'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
      [id]
    );

    if (topicCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found or expired' });
    }

    const articleCheck = await pool.query(
      'SELECT id FROM articles WHERE id = $1 AND debate_topic_id = $2',
      [articleId, id]
    );

    if (articleCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found or does not belong to this debate topic' });
    }

    const existingWinner = await pool.query(
      'SELECT id FROM debate_winners WHERE debate_topic_id = $1 AND article_id = $2',
      [id, articleId]
    );

    if (existingWinner.rows.length > 0) {
      return res.status(400).json({ error: 'Article is already marked as a winner' });
    }

    await pool.query(
      `INSERT INTO debate_winners (debate_topic_id, article_id, selected_by)
       VALUES ($1, $2, $3)`,
      [id, articleId, userId]
    );

    await pool.query(
      'UPDATE articles SET is_debate_winner = TRUE WHERE id = $1',
      [articleId]
    );

    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'debate_winner_selected', debateTopicId: id, articleId });

    res.json({ message: 'Article marked as winner successfully' });
  } catch (error) {
    console.error('Mark article as winner error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get winning articles for a debate topic
app.get('/api/debate-topics/:id/winners', async (req, res) => {
  try {
    const { id } = req.params;

    const topicCheck = await pool.query(
      'SELECT id FROM debate_topics WHERE id = $1',
      [id]
    );

    if (topicCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found' });
    }

    const cacheKey = `debate-winners-${id}`;
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      const winnersResult = await pool.query(`
        SELECT a.*, u.display_name, u.tier
        FROM articles a
        JOIN users u ON a.user_id = u.id
        JOIN debate_winners dw ON a.id = dw.article_id
        WHERE dw.debate_topic_id = $1 AND a.published = TRUE
        ORDER BY dw.selected_at DESC
      `, [id]);
      
      cachedData = winnersResult.rows;
      setCachedData(cacheKey, cachedData, 5 * 60 * 1000);
    }

    res.json({ winners: cachedData });
  } catch (error) {
    console.error('Get debate winners error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove winner status from an article
app.delete('/api/debate-topics/:id/winners/:articleId', authenticateEditorialBoard, async (req, res) => {
  try {
    const { id, articleId } = req.params;

    const winnerCheck = await pool.query(
      'SELECT id FROM debate_winners WHERE debate_topic_id = $1 AND article_id = $2',
      [id, articleId]
    );

    if (winnerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Article is not marked as a winner for this debate topic' });
    }

    await pool.query(
      'DELETE FROM debate_winners WHERE debate_topic_id = $1 AND article_id = $2',
      [id, articleId]
    );

    await pool.query(
      'UPDATE articles SET is_debate_winner = FALSE WHERE id = $1',
      [articleId]
    );

    // Clear cache and notify clients
    clearAllArticleCache();
    notifyClients({ type: 'debate_winner_removed', debateTopicId: id, articleId });

    res.json({ message: 'Winner status removed successfully' });
  } catch (error) {
    console.error('Remove winner status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get public user profile by display name
app.get('/api/users/:display_name', async (req, res) => {
  try {
    const { display_name } = req.params;
    const decodedDisplayName = decodeURIComponent(display_name);
    
    const cacheKey = `user-profile-${decodedDisplayName}`;
    let cachedData = getCachedData(cacheKey);
    
    if (!cachedData) {
      const userResult = await pool.query(
        `SELECT id, display_name, tier, role, created_at, followers
         FROM users 
         WHERE display_name = $1 AND account_status = 'active'`,
        [decodedDisplayName]
      );
      
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const user = userResult.rows[0];
      
      const articlesResult = await pool.query(
        `SELECT a.id, a.title, a.content, a.created_at, a.updated_at, a.views,
                ec.certified, a.is_debate_winner,
                COALESCE(
                  ARRAY_AGG(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL),
                  ARRAY[]::VARCHAR[]
                ) as topics
         FROM articles a
         LEFT JOIN editorial_certifications ec ON a.id = ec.article_id
         LEFT JOIN article_topics at ON a.id = at.article_id
         LEFT JOIN topics t ON at.topic_id = t.id
         WHERE a.user_id = $1 AND a.published = true
         GROUP BY a.id, ec.certified
         ORDER BY a.created_at DESC`,
        [user.id]
      );
      
      const totalViews = articlesResult.rows.reduce((sum, article) => sum + (article.views || 0), 0);
      const totalArticles = articlesResult.rows.length;
      
      let isFollowing = false;
      const authHeader = req.headers['authorization'];
      if (authHeader) {
        const token = authHeader.split(' ')[1];
        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET);
          const followCheck = await pool.query(
            'SELECT id FROM followers WHERE follower_id = $1 AND following_id = $2',
            [decoded.userId, user.id]
          );
          isFollowing = followCheck.rows.length > 0;
        } catch (err) {
          // Token is invalid, ignore
        }
      }
      
      cachedData = {
        user: {
          id: user.id,
          display_name: user.display_name,
          tier: user.tier,
          role: user.role,
          created_at: user.created_at,
          followers: user.followers || 0,
          isFollowing
        },
        articles: articlesResult.rows,
        stats: {
          totalArticles,
          totalViews
        }
      };
      
      setCachedData(cacheKey, cachedData, 5 * 60 * 1000);
    }
    
    res.json(cachedData);
  } catch (error) {
    console.error('Get public user profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Follow a user
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const followerId = req.user.userId;
    
    const userResult = await pool.query(
      'SELECT id FROM users WHERE id = $1 AND account_status = $2',
      [id, 'active']
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (parseInt(id) === followerId) {
      return res.status(400).json({ error: 'You cannot follow yourself' });
    }
    
    const followCheck = await pool.query(
      'SELECT id FROM followers WHERE follower_id = $1 AND following_id = $2',
      [followerId, id]
    );
    
    if (followCheck.rows.length > 0) {
      return res.status(400).json({ error: 'You are already following this user' });
    }
    
    await pool.query(
      'INSERT INTO followers (follower_id, following_id) VALUES ($1, $2)',
      [followerId, id]
    );
    
    // Clear relevant cache
    clearCache(/^user-profile-/);
    
    res.json({ message: 'User followed successfully' });
  } catch (error) {
    console.error('Follow user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Unfollow a user
app.delete('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const followerId = req.user.userId;
    
    const userResult = await pool.query(
      'SELECT id FROM users WHERE id = $1 AND account_status = $2',
      [id, 'active']
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const followCheck = await pool.query(
      'SELECT id FROM followers WHERE follower_id = $1 AND following_id = $2',
      [followerId, id]
    );
    
    if (followCheck.rows.length === 0) {
      return res.status(400).json({ error: 'You are not following this user' });
    }
    
    await pool.query(
      'DELETE FROM followers WHERE follower_id = $1 AND following_id = $2',
      [followerId, id]
    );
    
    // Clear relevant cache
    clearCache(/^user-profile-/);
    
    res.json({ message: 'User unfollowed successfully' });
  } catch (error) {
    console.error('Unfollow user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// Catch-all route for React app
app.get('*', (req, res) => {
  if (fs.existsSync(buildPath)) {
    res.sendFile(path.join(buildPath, 'index.html'));
  } else {
    res.status(404).send('Frontend build not found');
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler for API routes only
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

// Start server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  try {
    console.log('Initializing database...');
    await initDatabase();
    console.log('Database initialization complete. Server is ready.');
  } catch (error) {
    console.error('Failed to initialize database:', error);
  }
});

module.exports = app;