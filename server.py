from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import jwt
import threading
import os
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)

# Enable CORS for all routes - this is crucial for Chrome extension communication
CORS(app, origins=["chrome-extension://*"], supports_credentials=True)

# Secret key for JWT tokens - in production, use environment variable
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SECRET_KEY'] = SECRET_KEY

# Database lock for thread safety
db_lock = threading.Lock()

def init_database():
    """Initialize the SQLite database with users table"""
    with db_lock:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Create users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

def hash_password(password):
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_jwt_token(username):
    """Generate a JWT token for a user"""
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_jwt_token(token):
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()

        if not data or not all(k in data for k in ('username', 'password', 'email')):
            return jsonify({'error': 'Missing required fields'}), 400

        username = data['username'].strip()
        password = data['password']
        email = data['email'].strip()

        # Basic validation
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        if '@' not in email:
            return jsonify({'error': 'Invalid email format'}), 400

        # Hash the password
        password_hash = hash_password(password)

        # Insert user into database
        with db_lock:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()

            try:
                cursor.execute(
                    'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                    (username, password_hash, email)
                )
                conn.commit()

                # Generate JWT token
                token = generate_jwt_token(username)

                return jsonify({
                    'message': 'User registered successfully',
                    'token': token,
                    'username': username
                }), 201

            except sqlite3.IntegrityError:
                return jsonify({'error': 'Username or email already exists'}), 400
            finally:
                conn.close()

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Login a user"""
    try:
        data = request.get_json()

        if not data or not all(k in data for k in ('username', 'password')):
            return jsonify({'error': 'Missing username or password'}), 400

        username = data['username'].strip()
        password = data['password']

        # Get user from database
        with db_lock:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()

            cursor.execute(
                'SELECT username, password_hash FROM users WHERE username = ?',
                (username,)
            )
            user = cursor.fetchone()
            conn.close()

        if user and verify_password(password, user[1]):
            # Generate JWT token
            token = generate_jwt_token(username)
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'username': username
            }), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout a user (client-side token removal)"""
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/verify', methods=['GET'])
def verify_token():
    """Verify if a token is valid"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401

        token = auth_header.split(' ')[1]
        username = verify_jwt_token(token)

        if username:
            return jsonify({'valid': True, 'username': username}), 200
        else:
            return jsonify({'valid': False, 'error': 'Invalid or expired token'}), 401

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/user/profile', methods=['GET'])
def get_profile():
    """Get user profile (protected route)"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401

        token = auth_header.split(' ')[1]
        username = verify_jwt_token(token)

        if not username:
            return jsonify({'error': 'Invalid or expired token'}), 401

        # Get user profile from database
        with db_lock:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()

            cursor.execute(
                'SELECT username, email, created_at FROM users WHERE username = ?',
                (username,)
            )
            user = cursor.fetchone()
            conn.close()

        if user:
            return jsonify({
                'username': user[0],
                'email': user[1],
                'created_at': user[2]
            }), 200
        else:
            return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        'message': 'Chrome Extension Backend API',
        'version': '1.0.0',
        'endpoints': [
            '/api/register',
            '/api/login', 
            '/api/logout',
            '/api/verify',
            '/api/user/profile',
            '/health'
        ]
    }), 200

if __name__ == '__main__':
    # Initialize database
    init_database()

    # Get port from environment variable (Render.com sets this)
    port = int(os.environ.get('PORT', 5000))

    # Run the app
    # For development: debug=True, host='localhost'
    # For production: debug=False, host='0.0.0.0' (required for Render.com)
    app.run(
        debug=False,  # Set to False for production
        host='0.0.0.0',  # Required for Render.com
        port=port,
        threaded=True  # Enable threading for concurrent requests
    )
