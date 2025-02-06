-- CREATE TABLE IF NOT EXISTS users (
--             id INTEGER PRIMARY KEY AUTOINCREMENT,
--             username TEXT UNIQUE NOT NULL,
--             password TEXT NOT NULL,
--             email TEXT UNIQUE NOT NULL,
--             verified INTEGER DEFAULT 0,
--             verification_token TEXT
--             );

-- CREATE TABLE IF NOT EXISTS reviews (
--             id INTEGER PRIMARY KEY AUTOINCREMENT,
--             title TEXT NOT NULL,
--             review_date TEXT NOT NULL,
--             reviewer_name TEXT NOT NULL,
--             rating INTEGER NOT NULL,
--             review_text TEXT NOT NULL,
--             user_id INTEGER,
--             FOREIGN KEY(user_id) REFERENCES users(id)
--             );

-- ALTER TABLE users ADD COLUMN reset_token TEXT;

-- PRAGMA table_info(reviews);