#!/usr/bin/env python3
"""
Database initialization script for the Chrome Extension Backend
"""

import sqlite3
import os

def init_database():
    """Initialize the SQLite database with users table"""

    # Remove existing database if it exists (for fresh start)
    if os.path.exists('users.db'):
        os.remove('users.db')
        print("Removed existing database")

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    print("Created users table")

    conn.commit()
    conn.close()

    print("Database initialized successfully!")

if __name__ == '__main__':
    init_database()