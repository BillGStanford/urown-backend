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
      // First check if the column exists and its constraints
      const columnCheck = await pool.query(`
        SELECT column_name, is_nullable 
        FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'full_name'
      `);
      
      if (columnCheck.rows.length > 0 && columnCheck.rows[0].is_nullable === 'NO') {
        // If the column exists but doesn't allow NULL, alter it
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

    // Add ideology columns if they don't exist
    try {
      await pool.query(`
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS ideology VARCHAR(100),
        ADD COLUMN IF NOT EXISTS ideology_details JSONB,
        ADD COLUMN IF NOT EXISTS ideology_public BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS ideology_updated_at TIMESTAMP
      `);
      console.log('Ideology columns added to users table');
    } catch (error) {
      console.log('Ideology columns may already exist:', error.message);
    }

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

    // Create editorial board certifications table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS editorial_certifications (
        id SERIAL PRIMARY KEY,
        article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
        admin_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        certified BOOLEAN DEFAULT FALSE,
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
        // Calculate remaining time in a human-readable format
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
      // Continue to next if there's an error checking ban
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

// server.js - Update the validateSignup middleware
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
      // Return more detailed error information
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
    const result = await pool.query('SELECT * FROM topics ORDER BY name');
    res.json({ topics: result.rows });
  } catch (error) {
    console.error('Get topics error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Submit contact form (public route)
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, category, content } = req.body;

    // Validate input
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

    // Insert into database
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

    // Validate status
    const validStatuses = ['waiting', 'in_progress', 'resolved'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Check if contact message exists
    const contactResult = await pool.query(
      'SELECT * FROM contact_messages WHERE id = $1',
      [id]
    );

    if (contactResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    // Update status
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

    // Check if contact message exists
    const contactResult = await pool.query(
      'SELECT * FROM contact_messages WHERE id = $1',
      [id]
    );

    if (contactResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    // Delete contact message
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

    // Check if article exists
    const articleResult = await pool.query(
      'SELECT * FROM articles WHERE id = $1',
      [id]
    );

    if (articleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }

    // Check if user has already reported this article
    const existingReport = await pool.query(
      'SELECT id FROM reported_articles WHERE article_id = $1 AND user_id = $2',
      [id, userId]
    );

    if (existingReport.rows.length > 0) {
      return res.status(400).json({ error: 'You have already reported this article' });
    }

    // Create report
    const result = await pool.query(
      `INSERT INTO reported_articles (article_id, user_id, reason)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [id, userId, reason]
    );

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

    // Validate status
    const validStatuses = ['pending', 'reviewed', 'resolved', 'dismissed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Check if report exists
    const reportResult = await pool.query(
      'SELECT * FROM reported_articles WHERE id = $1',
      [id]
    );

    if (reportResult.rows.length === 0) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Update status
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

    // Get article data before deletion for logging
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
    
    // Delete article
    await pool.query('DELETE FROM articles WHERE id = $1', [id]);
    
    // Log the action
    await logAdminAction(
      req.user.userId,
      'delete_reported',
      'article',
      parseInt(id),
      `Deleted reported article: ${article.title} by ${article.author_name}`
    );
    
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

    // Check if user exists
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    // Don't allow warnings for deleted accounts
    if (user.account_status === 'soft_deleted' || user.account_status === 'hard_deleted') {
      return res.status(400).json({ error: 'Cannot warn a deleted account' });
    }

    // Add the warning
    await pool.query(
      `INSERT INTO user_warnings (user_id, reason, admin_id)
       VALUES ($1, $2, $3)`,
      [userId, reason, req.user.userId]
    );

    // Count warnings for this user
    const warningCountResult = await pool.query(
      'SELECT COUNT(*) as count FROM user_warnings WHERE user_id = $1',
      [userId]
    );

    const warningCount = parseInt(warningCountResult.rows[0].count);

    // If user has 3 warnings, mark for deletion
    if (warningCount >= 3) {
      await pool.query(
        `UPDATE users 
         SET account_status = 'soft_deleted', 
             soft_deleted_at = CURRENT_TIMESTAMP,
             deletion_reason = 'Account deleted due to 3 warnings'
         WHERE id = $1`,
        [userId]
      );

      // Log the action
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

    // Check if warning exists and belongs to user
    const warningResult = await pool.query(
      'SELECT * FROM user_warnings WHERE id = $1 AND user_id = $2',
      [warningId, userId]
    );

    if (warningResult.rows.length === 0) {
      return res.status(404).json({ error: 'Warning not found' });
    }

    // Delete the warning
    await pool.query(
      'DELETE FROM user_warnings WHERE id = $1',
      [warningId]
    );

    // Count remaining warnings
    const warningCountResult = await pool.query(
      'SELECT COUNT(*) as count FROM user_warnings WHERE user_id = $1',
      [userId]
    );

    const warningCount = parseInt(warningCountResult.rows[0].count);

    // If user was soft deleted due to warnings and now has less than 3, reactivate
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

        // Log the action
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

    // Check if user exists and is soft deleted
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1 AND account_status = $2',
      [userId, 'soft_deleted']
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Soft deleted user not found' });
    }

    const user = userResult.rows[0];

    // Reactivate the account
    await pool.query(
      `UPDATE users 
       SET account_status = 'active', 
           soft_deleted_at = NULL,
           deletion_reason = NULL
       WHERE id = $1`,
      [userId]
    );

    // Log the action
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

// Cleanup old warnings (remove warnings older than 2 weeks with no new warnings)
app.post('/api/admin/cleanup-warnings', authenticateAdmin, async (req, res) => {
  try {
    // Find users whose latest warning is older than 2 weeks
    const usersToClean = await pool.query(`
      SELECT user_id, MAX(created_at) as last_warning
      FROM user_warnings
      GROUP BY user_id
      HAVING MAX(created_at) < CURRENT_TIMESTAMP - INTERVAL '14 days'
    `);

    let cleanedCount = 0;
    
    for (const user of usersToClean.rows) {
      // Delete all warnings for this user
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
    // Find users soft deleted 5+ days ago
    const usersToDelete = await pool.query(`
      SELECT id, display_name, email
      FROM users
      WHERE account_status = 'soft_deleted' 
        AND soft_deleted_at <= CURRENT_TIMESTAMP - INTERVAL '5 days'
    `);

    let deletedCount = 0;
    
    for (const user of usersToDelete.rows) {
      // Hard delete the user (articles will remain with user_id set to NULL)
      await pool.query(
        'DELETE FROM users WHERE id = $1',
        [user.id]
      );
      
      // Log the action
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

    // Validate banEnd (should be a future date)
    if (!banEnd || new Date(banEnd) <= new Date()) {
      return res.status(400).json({ error: 'Ban end time must be in the future' });
    }

    if (!reason || !reason.trim()) {
      return res.status(400).json({ error: 'Reason is required' });
    }

    // Check if user exists
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user is already banned
    const existingBan = await pool.query(
      'SELECT * FROM user_bans WHERE user_id = $1 AND ban_end > CURRENT_TIMESTAMP',
      [id]
    );

    if (existingBan.rows.length > 0) {
      return res.status(400).json({ error: 'User is already banned' });
    }

    // Create the ban
    await pool.query(
      `INSERT INTO user_bans (user_id, ban_end, reason, admin_id)
       VALUES ($1, $2, $3, $4)`,
      [id, banEnd, reason, req.user.userId]
    );

    // Log the action
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

    // Check if user exists and is banned
    const banResult = await pool.query(
      'SELECT * FROM user_bans WHERE user_id = $1 AND ban_end > CURRENT_TIMESTAMP',
      [id]
    );

    if (banResult.rows.length === 0) {
      return res.status(404).json({ error: 'User is not currently banned' });
    }

    // Remove the ban by setting ban_end to now
    await pool.query(
      'UPDATE user_bans SET ban_end = CURRENT_TIMESTAMP WHERE user_id = $1',
      [id]
    );

    // Log the action
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
// In server.js, update the signup route
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, phone, full_name, display_name, date_of_birth, password, terms_agreed } = req.body;
    
    // Manual validation for better error messages
    const errors = {};
    
    // Email validation
    if (!email) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.email = 'Please enter a valid email address';
    }
    
    // Phone validation (optional)
    if (phone && !/^\+?[1-9]\d{1,14}$/.test(phone.replace(/\s/g, ''))) {
      errors.phone = 'Please enter a valid phone number';
    }
    
    // Full name validation (now optional)
    if (full_name && full_name.trim().length > 0 && full_name.trim().length < 2) {
      errors.full_name = 'Full name must be at least 2 characters';
    }
    
    // Display name validation
    if (!display_name || display_name.trim().length < 2) {
      errors.display_name = 'Display name must be at least 2 characters';
    }
    
    // Date of birth validation
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
    
    // Password validation
    if (!password || password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    } else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      errors.password = 'Password must contain uppercase, lowercase, and number';
    }
    
    // Terms validation
    if (terms_agreed !== true) {
      errors.terms_agreed = 'You must agree to the terms of service';
    }
    
    // If there are validation errors, return them
    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors 
      });
    }
    
    // Check if email already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR display_name = $2',
      [email, display_name]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email or display name already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const password_hash = await bcrypt.hash(password, saltRounds);

    // Create user (phone and full_name are now optional)
    const result = await pool.query(
      `INSERT INTO users (email, phone, full_name, display_name, date_of_birth, password_hash, terms_agreed)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, email, phone, full_name, display_name, tier, role, created_at`,
      [email, phone || null, full_name || null, display_name, date_of_birth, password_hash, terms_agreed]
    );

    const user = result.rows[0];

    // Generate JWT token
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
    // Return more detailed error information
    res.status(500).json({ 
      error: 'Internal server error', 
      details: error.message || 'An unknown error occurred during registration' 
    });
  }
});

// Login
// server.js - Update the login route
app.post('/api/auth/login', validateLogin, async (req, res) => {
  try {
    const { identifier, password } = req.body;

    // Find user by email or display_name
    const result = await pool.query(
      'SELECT * FROM users WHERE (email = $1 OR display_name = $1) AND account_status = $2',
      [identifier, 'active']
    );

    if (result.rows.length === 0) {
      // Check if account exists but is deleted
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

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if user is banned
    const banResult = await pool.query(
      'SELECT ban_end, reason FROM user_bans WHERE user_id = $1 AND ban_end > CURRENT_TIMESTAMP',
      [user.id]
    );

    if (banResult.rows.length > 0) {
      const ban = banResult.rows[0];
      // Calculate remaining time in a human-readable format
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

    // Generate JWT token
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
      `SELECT id, email, phone, full_name, display_name, tier, role, 
              weekly_articles_count, weekly_reset_date, 
              display_name_updated_at, email_updated_at, phone_updated_at, password_updated_at, 
              created_at, followers,
              ideology, ideology_details, ideology_public, ideology_updated_at
       FROM users 
       WHERE id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    // Check if we need to reset weekly article count
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

// Update user profile (display name, email, phone)
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { display_name, email, phone } = req.body;

    // Get current user data
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

    // Check display name update
    if (display_name && display_name !== user.display_name) {
      const lastUpdate = user.display_name_updated_at ? new Date(user.display_name_updated_at) : null;
      const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

      if (daysSinceLastUpdate < 14) {
        const daysLeft = 14 - daysSinceLastUpdate;
        return res.status(400).json({ 
          error: `You can change your display name again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
        });
      }

      // Check if display name is already in use by another user
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

    // Check email update
    if (email && email !== user.email) {
      const lastUpdate = user.email_updated_at ? new Date(user.email_updated_at) : null;
      const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

      if (daysSinceLastUpdate < 14) {
        const daysLeft = 14 - daysSinceLastUpdate;
        return res.status(400).json({ 
          error: `You can change your email again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
        });
      }

      // Check if email is already in use by another user
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

    // Check phone update
    if (phone !== undefined && phone !== user.phone) {
      const lastUpdate = user.phone_updated_at ? new Date(user.phone_updated_at) : null;
      const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

      if (daysSinceLastUpdate < 14) {
        const daysLeft = 14 - daysSinceLastUpdate;
        return res.status(400).json({ 
          error: `You can change your phone number again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
        });
      }

      // Check if phone is already in use by another user
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

    // Add user ID to values
    values.push(userId);

    // Update the user
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

    // Get current user data
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    const now = new Date();

    // Check if password can be changed (14-day cooldown)
    const lastUpdate = user.password_updated_at ? new Date(user.password_updated_at) : null;
    const daysSinceLastUpdate = lastUpdate ? Math.floor((now - lastUpdate) / (24 * 60 * 60 * 1000)) : 14;

    if (daysSinceLastUpdate < 14) {
      const daysLeft = 14 - daysSinceLastUpdate;
      return res.status(400).json({ 
        error: `You can change your password again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
      });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(current_password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(new_password, saltRounds);

    // Update password
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

    // Get user data for logging
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    // Soft delete the user
    await pool.query(
      `UPDATE users 
       SET account_status = 'soft_deleted', 
           soft_deleted_at = CURRENT_TIMESTAMP,
           deletion_reason = 'User requested account deletion'
       WHERE id = $1`,
      [userId]
    );

    // Log the action
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
    // Get user's articles
    const articlesResult = await pool.query(
      `SELECT id, published, views, created_at, updated_at
       FROM articles 
       WHERE user_id = $1`,
      [req.user.userId]
    );
    
    const articles = articlesResult.rows;
    const publishedArticles = articles.filter(article => article.published).length;
    const draftArticles = articles.filter(article => !article.published).length;
    
    // Calculate total views
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

    // Validate input
    if (!title?.trim() || !content?.trim()) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    if (title.length > 255) {
      return res.status(400).json({ error: 'Title must be 255 characters or less' });
    }

    // Validate topic selection (max 3 topics)
    if (topicIds.length > 3) {
      return res.status(400).json({ error: 'You can select a maximum of 3 topics' });
    }

    // Validate that all topic IDs exist
    if (topicIds.length > 0) {
      const topicCheck = await pool.query(
        'SELECT id FROM topics WHERE id = ANY($1)',
        [topicIds]
      );
      
      if (topicCheck.rows.length !== topicIds.length) {
        return res.status(400).json({ error: 'One or more selected topics are invalid' });
      }
    }

    // If this is a counter opinion, validate the parent article
    if (parent_article_id) {
      // Check if parent article exists and is published
      const parentResult = await pool.query(
        'SELECT id FROM articles WHERE id = $1 AND published = true',
        [parent_article_id]
      );

      if (parentResult.rows.length === 0) {
        return res.status(400).json({ error: 'Parent article not found or not published' });
      }

      // Check if parent article already has 5 counter opinions
      const counterCountResult = await pool.query(
        'SELECT COUNT(*) as count FROM articles WHERE parent_article_id = $1',
        [parent_article_id]
      );

      if (parseInt(counterCountResult.rows[0].count) >= 5) {
        return res.status(400).json({ error: 'Maximum number of counter opinions reached for this article' });
      }
    }

    // If this is a debate opinion, validate the debate topic
    if (debate_topic_id) {
      // Check if debate topic exists and is active
      const topicResult = await pool.query(
        'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
        [debate_topic_id]
      );

      if (topicResult.rows.length === 0) {
        return res.status(400).json({ error: 'Debate topic not found or expired' });
      }

      // Check if user has already written an opinion for this topic
      const existingOpinion = await pool.query(
        'SELECT id FROM articles WHERE debate_topic_id = $1 AND user_id = $2',
        [debate_topic_id, userId]
      );

      if (existingOpinion.rows.length > 0) {
        return res.status(400).json({ error: 'You have already written an opinion for this debate topic' });
      }
    }

    // Check weekly limit only if publishing an original article (not a counter opinion or debate opinion)
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

    // Create article
    const result = await pool.query(
      'INSERT INTO articles (user_id, title, content, published, featured, parent_article_id, debate_topic_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [userId, title.trim(), content.trim(), published, featured, parent_article_id || null, debate_topic_id || null]
    );

    const article = result.rows[0];

    // Link article with topics if provided
    if (topicIds.length > 0) {
      const topicValues = topicIds.map(topicId => `(${article.id}, ${topicId})`).join(', ');
      await pool.query(
        `INSERT INTO article_topics (article_id, topic_id) VALUES ${topicValues}`
      );
    }

    // Update weekly count only if publishing an original article (not a counter opinion or debate opinion)
    if (published && !parent_article_id && !debate_topic_id) {
      await pool.query(
        'UPDATE users SET weekly_articles_count = weekly_articles_count + 1 WHERE id = $1',
        [userId]
      );
    }

    // Get updated user data to return to client
    const updatedUserResult = await pool.query(
      'SELECT id, email, phone, full_name, display_name, tier, role, weekly_articles_count, weekly_reset_date, display_name_updated_at, email_updated_at, phone_updated_at, password_updated_at, created_at FROM users WHERE id = $1',
      [userId]
    );

    const updatedUser = updatedUserResult.rows[0];

    // Get updated user statistics
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

// Replace the existing /api/articles GET endpoint in server.js (around line 1700)
// This version fixes the disappearing certified articles issue

// Get all published articles (for browse and homepage)
app.get('/api/articles', async (req, res) => {
  try {
    const { featured, limit = 20, offset = 0, parent_article_id, debate_topic_id, topicId, certified } = req.query;
    
    // DEBUG: Log the request parameters
    console.log('GET /api/articles - Request params:', {
      featured,
      limit,
      offset,
      parent_article_id,
      debate_topic_id,
      topicId,
      certified
    });
    
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
    
    // FIX: Only filter debate articles when specifically requesting a debate topic
    // OR when the debate topic has expired
    if (debate_topic_id) {
      // If specifically requesting a debate topic, show only that topic's articles
      query += ' AND a.debate_topic_id = $' + (params.length + 1);
      params.push(debate_topic_id);
      
      // Check if the debate topic is active
      const debateTopicCheck = await pool.query(
        'SELECT expires_at FROM debate_topics WHERE id = $1',
        [debate_topic_id]
      );
      
      if (debateTopicCheck.rows.length > 0) {
        const expiresAt = new Date(debateTopicCheck.rows[0].expires_at);
        const now = new Date();
        
        // If debate has expired, only show winners
        if (expiresAt <= now) {
          query += ' AND a.is_debate_winner = true';
        }
      }
    } else {
      // FIX: In general browse, show all articles EXCEPT:
      // 1. Non-winning debate articles from EXPIRED debates only
      // Articles from active debates should be visible even if not winners yet
      query += ` AND (
        a.debate_topic_id IS NULL 
        OR a.is_debate_winner = true
        OR EXISTS (
          SELECT 1 FROM debate_topics dt 
          WHERE dt.id = a.debate_topic_id 
          AND dt.expires_at > CURRENT_TIMESTAMP
        )
      )`;
    }
    
    // Featured filter
    if (featured === 'true') {
      query += ' AND a.featured = true';
    }
    
    // Certified filter (for homepage certified articles)
    if (certified === 'true') {
      query += ' AND ec.certified = true';
    }
    
    // Parent article filter (for counter opinions)
    if (parent_article_id) {
      query += ' AND a.parent_article_id = $' + (params.length + 1);
      params.push(parent_article_id);
    }
    
    // Topic filter
    if (topicId) {
      query += ' AND EXISTS (SELECT 1 FROM article_topics WHERE article_id = a.id AND topic_id = $' + (params.length + 1) + ')';
      params.push(topicId);
    }
    
    query += ' GROUP BY a.id, u.display_name, u.tier, ec.certified ORDER BY a.created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
    params.push(parseInt(limit), parseInt(offset));

    // DEBUG: Log the final query and params
    console.log('Executing query with params:', params);
    
    const result = await pool.query(query, params);
    
    // DEBUG: Log results count and certified count
    const certifiedCount = result.rows.filter(a => a.certified).length;
    console.log(`GET /api/articles - Results: ${result.rows.length} total, ${certifiedCount} certified`);
    
    res.json({ articles: result.rows });
  } catch (error) {
    console.error('Get articles error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
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
    
    // First, get the article to check if it's published and who owns it
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

    let article = articleResult.rows[0];
    
    // Only show published articles to non-owners
    if (!article.published) {
      // Check if user is the owner
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

    // Check if we should increment the view count
    // We'll use a session-based approach to prevent double counting
    const sessionKey = `article_view_${id}`;
    const hasViewed = req.session[sessionKey];
    
    // Only increment view count if article is published and not viewed in this session
    if (article.published && !hasViewed) {
      await pool.query(
        'UPDATE articles SET views = views + 1 WHERE id = $1',
        [id]
      );
      
      // Mark as viewed in this session
      req.session[sessionKey] = true;
      
      // Get updated view count
      const updatedViewResult = await pool.query(
        'SELECT views FROM articles WHERE id = $1',
        [id]
      );
      
      article.views = updatedViewResult.rows[0].views;
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

    // Check if user owns the article
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

    // Validate topic selection (max 3 topics)
    if (topicIds.length > 3) {
      return res.status(400).json({ error: 'You can select a maximum of 3 topics' });
    }

    // Validate that all topic IDs exist
    if (topicIds.length > 0) {
      const topicCheck = await pool.query(
        'SELECT id FROM topics WHERE id = ANY($1)',
        [topicIds]
      );
      
      if (topicCheck.rows.length !== topicIds.length) {
        return res.status(400).json({ error: 'One or more selected topics are invalid' });
      }
    }

    // Check weekly limit only if publishing for first time and it's an original article (not a counter opinion or debate opinion)
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

    // Update article
    const result = await pool.query(
      `UPDATE articles 
       SET title = $1, content = $2, published = $3, featured = $4, updated_at = CURRENT_TIMESTAMP
       WHERE id = $5 
       RETURNING *`,
      [title?.trim(), content?.trim(), published, featured, id]
    );

    // Update article topics
    // First, remove all existing topic associations
    await pool.query(
      'DELETE FROM article_topics WHERE article_id = $1',
      [id]
    );

    // Then, add new topic associations if provided
    if (topicIds.length > 0) {
      const topicValues = topicIds.map(topicId => `(${id}, ${topicId})`).join(', ');
      await pool.query(
        `INSERT INTO article_topics (article_id, topic_id) VALUES ${topicValues}`
      );
    }

    // Update weekly count only if publishing for first time and it's an original article (not a counter opinion or debate opinion)
    if (published && !currentlyPublished && !isCounterOpinion && !isDebateOpinion) {
      await pool.query(
        'UPDATE users SET weekly_articles_count = weekly_articles_count + 1 WHERE id = $1',
        [userId]
      );
    }

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

    // Check if user owns the article
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

    res.json({ message: 'Article deleted successfully' });

  } catch (error) {
    console.error('Delete article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Editorial board routes

// Get articles for editorial board (editorial board, admin, and super-admin only)
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

// Toggle editorial certification (editorial board only)
app.post('/api/editorial/articles/:id/certify', authenticateEditorialBoard, async (req, res) => {
  try {
    const { id } = req.params;
    const { certified } = req.body;
    
    // Check if article exists
    const articleResult = await pool.query(
      'SELECT * FROM articles WHERE id = $1',
      [id]
    );
    
    if (articleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }
    
    const article = articleResult.rows[0];
    
    // Check if certification already exists
    const certResult = await pool.query(
      'SELECT * FROM editorial_certifications WHERE article_id = $1',
      [id]
    );
    
    if (certResult.rows.length > 0) {
      // Update existing certification
      await pool.query(
        'UPDATE editorial_certifications SET certified = $1, updated_at = CURRENT_TIMESTAMP WHERE article_id = $2',
        [certified, id]
      );
    } else {
      // Create new certification
      await pool.query(
        'INSERT INTO editorial_certifications (article_id, admin_id, certified) VALUES ($1, $2, $3)',
        [id, req.user.userId, certified]
      );
    }
    
    // Log the action
    await logAdminAction(
      req.user.userId,
      certified ? 'certify' : 'uncertify',
      'article',
      parseInt(id),
      `${certified ? 'Certified' : 'Uncertified'} article: ${article.title}`
    );
    
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

// Get all users (admin only)
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

// Get user by ID (admin only)
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

// Update user role (super-admin only)
app.put('/api/admin/users/:id/role', authenticateSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    
    // Validate role
    const validRoles = ['user', 'editorial-board', 'admin', 'super-admin'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    
    // Get current user data
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentUser = userResult.rows[0];
    const oldRole = currentUser.role;
    
    // Update user role
    await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2',
      [role, id]
    );
    
    // Log the action
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

// Delete user (admin only) - soft delete
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Prevent self-deletion
    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    // Get user data before deletion for logging
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Soft delete the user
    await pool.query(
      `UPDATE users 
       SET account_status = 'soft_deleted', 
           soft_deleted_at = CURRENT_TIMESTAMP,
           deletion_reason = 'Account deleted by admin'
       WHERE id = $1`,
      [id]
    );
    
    // Log the action
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

// Get all articles (admin and editorial board only)
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

// Delete article (admin only)
app.delete('/api/admin/articles/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get article data before deletion for logging
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
    
    // Delete article
    await pool.query('DELETE FROM articles WHERE id = $1', [id]);
    
    // Log the action
    await logAdminAction(
      req.user.userId,
      'delete',
      'article',
      parseInt(id),
      `Deleted article: ${article.title} by ${article.author_name}`
    );
    
    res.json({ message: 'Article deleted successfully' });
  } catch (error) {
    console.error('Delete article error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get audit log (super-admin only)
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

// Get admin dashboard stats (admin only)
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    // Get user counts by role
    const userCountsResult = await pool.query(
      `SELECT role, COUNT(*) as count
       FROM users
       WHERE account_status = 'active'
       GROUP BY role`
    );
    
    // Get article counts
    const articleCountsResult = await pool.query(
      `SELECT 
         COUNT(*) as total_articles,
         COUNT(CASE WHEN published = true THEN 1 END) as published_articles,
         COUNT(CASE WHEN published = false THEN 1 END) as draft_articles,
         COUNT(CASE WHEN certified = true THEN 1 END) as certified_articles
       FROM articles a
       LEFT JOIN editorial_certifications ec ON a.id = ec.article_id`
    );
    
    // Get total views
    const viewsResult = await pool.query(
      'SELECT COALESCE(SUM(views), 0) as total_views FROM articles'
    );
    
    // Get recent activity
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

// Replace the /api/debate-topics GET endpoint in server.js (around line 2150)
// This version prevents deletion of certified debate articles

// Get active debate topics (public route)
app.get('/api/debate-topics', async (req, res) => {
  try {
    console.log('Fetching debate topics...');
    
    // FIX: Instead of deleting expired debate articles, just mark them
    // This preserves certified articles for the archive
    
    // First, mark non-winning articles from expired debates as hidden
    console.log('Marking expired debate opinions...');
    await pool.query(`
      UPDATE articles 
      SET published = false
      WHERE debate_topic_id IN (
        SELECT id FROM debate_topics WHERE expires_at <= CURRENT_TIMESTAMP
      )
      AND is_debate_winner = false
      AND NOT EXISTS (
        SELECT 1 FROM editorial_certifications ec 
        WHERE ec.article_id = articles.id 
        AND ec.certified = true
      )
    `);
    
    // Only delete the debate topics themselves, not the articles
    // This way, winning articles and certified articles remain visible
    console.log('Archiving expired debate topics...');
    await pool.query(`
      DELETE FROM debate_topics 
      WHERE expires_at <= CURRENT_TIMESTAMP
    `);
    
    // Get active debate topics (limited to 3)
    console.log('Querying active debate topics...');
    const result = await pool.query(`
      SELECT dt.*, COUNT(a.id) as opinions_count
      FROM debate_topics dt
      LEFT JOIN articles a ON dt.id = a.debate_topic_id AND a.published = true
      WHERE dt.expires_at > CURRENT_TIMESTAMP
      GROUP BY dt.id
      ORDER BY dt.created_at DESC
      LIMIT 3
    `);
    
    console.log(`Found ${result.rows.length} debate topics`);
    res.json({ topics: result.rows });
  } catch (error) {
    console.error('Get debate topics error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Get a specific debate topic and its opinions (public route)
app.get('/api/debate-topics/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get debate topic
    const topicResult = await pool.query(
      'SELECT * FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
      [id]
    );
    
    if (topicResult.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found or expired' });
    }
    
    const topic = topicResult.rows[0];
    
    // Get opinions for this topic
    const opinionsResult = await pool.query(`
      SELECT a.*, u.display_name, u.tier
      FROM articles a
      JOIN users u ON a.user_id = u.id
      WHERE a.debate_topic_id = $1 AND a.published = true
      ORDER BY a.created_at DESC
    `, [id]);
    
    res.json({ 
      topic, 
      opinions: opinionsResult.rows 
    });
  } catch (error) {
    console.error('Get debate topic error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get opinions for a debate topic (public route)
app.get('/api/debate-topics/:id/opinions', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if debate topic exists and is active
    const topicCheck = await pool.query(
      'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
      [id]
    );
    
    if (topicCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found or expired' });
    }
    
    // Get opinions for this topic
    const opinionsResult = await pool.query(`
      SELECT a.*, u.display_name, u.tier
      FROM articles a
      JOIN users u ON a.user_id = u.id
      WHERE a.debate_topic_id = $1 AND a.published = true
      ORDER BY a.created_at DESC
    `, [id]);
    
    res.json({ opinions: opinionsResult.rows });
  } catch (error) {
    console.error('Get debate opinions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new opinion for a debate topic (authenticated users)
app.post('/api/debate-topics/:id/opinions', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;
    const userId = req.user.userId;
    
    // Validate input
    if (!title?.trim() || !content?.trim()) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    
    // Check if debate topic exists and is active
    const topicCheck = await pool.query(
      'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
      [id]
    );
    
    if (topicCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found or expired' });
    }
    
    // Check if user has already written an opinion for this topic
    const existingOpinion = await pool.query(
      'SELECT id FROM articles WHERE debate_topic_id = $1 AND user_id = $2',
      [id, userId]
    );
    
    if (existingOpinion.rows.length > 0) {
      return res.status(400).json({ error: 'You have already written an opinion for this debate topic' });
    }
    
    // Create the opinion as an article
    const result = await pool.query(
      `INSERT INTO articles (user_id, title, content, published, debate_topic_id)
       VALUES ($1, $2, $3, true, $4)
       RETURNING *`,
      [userId, title.trim(), content.trim(), id]
    );
    
    res.status(201).json({
      message: 'Opinion created successfully',
      article: result.rows[0]
    });
  } catch (error) {
    console.error('Create debate opinion error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new debate topic (editorial board only)
app.post('/api/debate-topics', authenticateEditorialBoard, async (req, res) => {
  try {
    const { title, description } = req.body;
    const userId = req.user.userId;
    
    // Validate input
    if (!title?.trim() || !description?.trim()) {
      return res.status(400).json({ error: 'Title and description are required' });
    }
    
    // Calculate expiration time (24 hours from now)
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);
    
    // Create the debate topic
    const result = await pool.query(
      `INSERT INTO debate_topics (title, description, expires_at, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [title.trim(), description.trim(), expiresAt, userId]
    );
    
    res.status(201).json({
      message: 'Debate topic created successfully',
      topic: result.rows[0]
    });
  } catch (error) {
    console.error('Create debate topic error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark an article as a winner for a debate topic (editorial board only)
app.post('/api/debate-topics/:id/winners/:articleId', authenticateEditorialBoard, async (req, res) => {
  try {
    const { id, articleId } = req.params;
    const userId = req.user.userId;

    // Check if debate topic exists and is active
    const topicCheck = await pool.query(
      'SELECT id FROM debate_topics WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP',
      [id]
    );

    if (topicCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found or expired' });
    }

    // Check if article exists and belongs to the debate topic
    const articleCheck = await pool.query(
      'SELECT id FROM articles WHERE id = $1 AND debate_topic_id = $2',
      [articleId, id]
    );

    if (articleCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Article not found or does not belong to this debate topic' });
    }

    // Check if article is already a winner
    const existingWinner = await pool.query(
      'SELECT id FROM debate_winners WHERE debate_topic_id = $1 AND article_id = $2',
      [id, articleId]
    );

    if (existingWinner.rows.length > 0) {
      return res.status(400).json({ error: 'Article is already marked as a winner' });
    }

    // Mark the article as a winner
    await pool.query(
      `INSERT INTO debate_winners (debate_topic_id, article_id, selected_by)
       VALUES ($1, $2, $3)`,
      [id, articleId, userId]
    );

    // Update the article to mark it as a debate winner
    await pool.query(
      'UPDATE articles SET is_debate_winner = TRUE WHERE id = $1',
      [articleId]
    );

    res.json({ message: 'Article marked as winner successfully' });
  } catch (error) {
    console.error('Mark article as winner error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get winning articles for a debate topic (public route)
app.get('/api/debate-topics/:id/winners', async (req, res) => {
  try {
    const { id } = req.params;

    // Check if debate topic exists
    const topicCheck = await pool.query(
      'SELECT id FROM debate_topics WHERE id = $1',
      [id]
    );

    if (topicCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Debate topic not found' });
    }

    // Get winning articles for this topic
    const winnersResult = await pool.query(`
      SELECT a.*, u.display_name, u.tier
      FROM articles a
      JOIN users u ON a.user_id = u.id
      JOIN debate_winners dw ON a.id = dw.article_id
      WHERE dw.debate_topic_id = $1 AND a.published = TRUE
      ORDER BY dw.selected_at DESC
    `, [id]);

    res.json({ winners: winnersResult.rows });
  } catch (error) {
    console.error('Get debate winners error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove winner status from an article (editorial board only)
app.delete('/api/debate-topics/:id/winners/:articleId', authenticateEditorialBoard, async (req, res) => {
  try {
    const { id, articleId } = req.params;

    // Check if article is a winner for this debate topic
    const winnerCheck = await pool.query(
      'SELECT id FROM debate_winners WHERE debate_topic_id = $1 AND article_id = $2',
      [id, articleId]
    );

    if (winnerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Article is not marked as a winner for this debate topic' });
    }

    // Remove the winner status
    await pool.query(
      'DELETE FROM debate_winners WHERE debate_topic_id = $1 AND article_id = $2',
      [id, articleId]
    );

    // Update the article to mark it as not a debate winner
    await pool.query(
      'UPDATE articles SET is_debate_winner = FALSE WHERE id = $1',
      [articleId]
    );

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
    
    // Replace spaces with actual spaces (URL encoding will handle this)
    const decodedDisplayName = decodeURIComponent(display_name);
    
    // Get user info
    const userResult = await pool.query(
      `SELECT id, display_name, tier, role, created_at, followers,
              CASE 
                WHEN ideology_public = TRUE THEN ideology 
                ELSE NULL 
              END as ideology,
              CASE 
                WHEN ideology_public = TRUE THEN ideology_details 
                ELSE NULL 
              END as ideology_details
       FROM users 
       WHERE display_name = $1 AND account_status = 'active'`,
      [decodedDisplayName]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Get user's published articles
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
    
    // Calculate stats
    const totalViews = articlesResult.rows.reduce((sum, article) => sum + (article.views || 0), 0);
    const totalArticles = articlesResult.rows.length;
    
    // Check if user is authenticated to determine if they're following this user
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
    
    res.json({
      user: {
        id: user.id,
        display_name: user.display_name,
        tier: user.tier,
        role: user.role,
        created_at: user.created_at,
        followers: user.followers || 0,
        ideology: user.ideology,
        ideology_details: user.ideology_details,
        isFollowing
      },
      articles: articlesResult.rows,
      stats: {
        totalArticles,
        totalViews
      }
    });
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
    
    // Check if user exists
    const userResult = await pool.query(
      'SELECT id FROM users WHERE id = $1 AND account_status = $2',
      [id, 'active']
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user is trying to follow themselves
    if (parseInt(id) === followerId) {
      return res.status(400).json({ error: 'You cannot follow yourself' });
    }
    
    // Check if already following
    const followCheck = await pool.query(
      'SELECT id FROM followers WHERE follower_id = $1 AND following_id = $2',
      [followerId, id]
    );
    
    if (followCheck.rows.length > 0) {
      return res.status(400).json({ error: 'You are already following this user' });
    }
    
    // Create follow relationship
    await pool.query(
      'INSERT INTO followers (follower_id, following_id) VALUES ($1, $2)',
      [followerId, id]
    );
    
    // REMOVE THIS LINE - The trigger will handle this automatically
    // await pool.query(
    //   'UPDATE users SET followers = followers + 1 WHERE id = $1',
    //   [id]
    // );
    
    res.json({ message: 'User followed successfully' });
  } catch (error) {
    console.error('Follow user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// In the unfollow endpoint (around line 3320)
app.delete('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const followerId = req.user.userId;
    
    // Check if user exists
    const userResult = await pool.query(
      'SELECT id FROM users WHERE id = $1 AND account_status = $2',
      [id, 'active']
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if following
    const followCheck = await pool.query(
      'SELECT id FROM followers WHERE follower_id = $1 AND following_id = $2',
      [followerId, id]
    );
    
    if (followCheck.rows.length === 0) {
      return res.status(400).json({ error: 'You are not following this user' });
    }
    
    // Remove follow relationship
    await pool.query(
      'DELETE FROM followers WHERE follower_id = $1 AND following_id = $2',
      [followerId, id]
    );
    
    // REMOVE THIS LINE - The trigger will handle this automatically
    // await pool.query(
    //   'UPDATE users SET followers = followers - 1 WHERE id = $1',
    //   [id]
    // );
    
    res.json({ message: 'User unfollowed successfully' });
  } catch (error) {
    console.error('Unfollow user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user ideology
app.put('/api/user/ideology', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { ideology, ideology_details, ideology_public } = req.body;

    // Validate input
    if (!ideology || !ideology.trim()) {
      return res.status(400).json({ error: 'Ideology is required' });
    }

    // Update user ideology
    const result = await pool.query(
      `UPDATE users 
       SET ideology = $1, 
           ideology_details = $2, 
           ideology_public = $3, 
           ideology_updated_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $4
       RETURNING id, email, phone, full_name, display_name, tier, role, ideology, ideology_details, ideology_public, ideology_updated_at`,
      [ideology.trim(), ideology_details ? JSON.stringify(ideology_details) : null, ideology_public, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'Ideology updated successfully',
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Update ideology error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's own ideology (including private)
app.get('/api/user/ideology', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ideology, ideology_details, ideology_public, ideology_updated_at
       FROM users 
       WHERE id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ ideology: result.rows[0] });

  } catch (error) {
    console.error('Get ideology error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle ideology visibility
app.put('/api/user/ideology/visibility', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { ideology_public } = req.body;

    if (typeof ideology_public !== 'boolean') {
      return res.status(400).json({ error: 'ideology_public must be a boolean' });
    }

    const result = await pool.query(
      `UPDATE users 
       SET ideology_public = $1, 
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING ideology_public`,
      [ideology_public, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'Ideology visibility updated successfully',
      ideology_public: result.rows[0].ideology_public
    });

  } catch (error) {
    console.error('Update ideology visibility error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout (client-side token removal, server-side acknowledgment)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// Add this catch-all route at the very end, before the error handling middleware
// This serves the React app for any route that doesn't match API routes
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
    // Continue running even if database initialization fails
    // The tables might already exist
  }
});

module.exports = app;