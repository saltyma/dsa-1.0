import sqlite3

# Connect to SQLite database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create users table
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    salt TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

# Create artworks table
c.execute('''
CREATE TABLE IF NOT EXISTS artworks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    unique_id TEXT NOT NULL,
    artwork TEXT NOT NULL,
    signature TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# Commit and close the connection
conn.commit()
conn.close()

print("Database initialized successfully.")
