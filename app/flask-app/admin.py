import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "database.db"  # Ensure this matches your app's database file

# Admin credentials
username = "Oden"  # Change as needed
password = "Oden123"  # Change to a strong password

# Hash the password
hashed_password = generate_password_hash(password)

# Connect to SQLite and insert admin user
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Ensure table exists
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

# Insert admin credentials
try:
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    print(f"Admin user '{username}' added successfully!")
except sqlite3.IntegrityError:
    print(f"User '{username}' already exists.")

conn.close()
