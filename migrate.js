// migrate.js
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

async function migrate() {
  console.log('Running database migrations...');

  try {
    // Add role column to users table if it doesn't exist
    try {
      await pool.query(`
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user'
      `);
      console.log('Added role column to users table');
    } catch (error) {
      console.log('Error adding role column:', error.message);
    }

    // Add featured column to articles table if it doesn't exist
    try {
      await pool.query(`
        ALTER TABLE articles 
        ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT FALSE
      `);
      console.log('Added featured column to articles table');
    } catch (error) {
      console.log('Error adding featured column:', error.message);
    }

    // Add views column to articles table if it doesn't exist
    try {
      await pool.query(`
        ALTER TABLE articles 
        ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0
      `);
      console.log('Added views column to articles table');
    } catch (error) {
      console.log('Error adding views column:', error.message);
    }

    // Create editorial_certifications table if it doesn't exist
    try {
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
      console.log('Created editorial_certifications table');
    } catch (error) {
      console.log('Error creating editorial_certifications table:', error.message);
    }

    // Create audit_log table if it doesn't exist
    try {
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
      console.log('Created audit_log table');
    } catch (error) {
      console.log('Error creating audit_log table:', error.message);
    }

    // Create session table if it doesn't exist
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS session (
          sid varchar NOT NULL,
          sess json NOT NULL,
          expire timestamp(6) NOT NULL,
          PRIMARY KEY (sid)
        )
      `);
      console.log('Created session table');
    } catch (error) {
      console.log('Error creating session table:', error.message);
    }

    // Set super-admin for the specified user
    try {
      await pool.query(`
        UPDATE users 
        SET role = 'super-admin' 
        WHERE id = 1 AND email = 'natolilemessa089@gmail.com'
      `);
      console.log('Set super-admin role for user ID 1');
    } catch (error) {
      console.log('Error setting super-admin:', error.message);
    }

    console.log('Database migrations completed successfully!');
  } catch (error) {
    console.error('Error running migrations:', error);
  } finally {
    await pool.end();
  }
}

migrate();