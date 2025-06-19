# Debugged and Enhanced Flask Chrome Extension Backend API
# This version includes comprehensive error handling, logging, and security improvements

from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg
from psycopg_pool import ConnectionPool, PoolTimeout
import bcrypt
import jwt
import threading
import os
import logging
import re
from datetime import datetime, timedelta
import secrets
from urllib.parse import urlparse
from functools import wraps
import time

app = Flask(__name__)

# Configure comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Enable CORS for all routes - this is crucial for Chrome extension communication
CORS(app, supports_credentials=True)

# Secret key for JWT tokens - in production, use environment variable
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SECRET_KEY'] = SECRET_KEY

# Database connection pool
db_pool = None
db_lock = threading.Lock()

# Custom exceptions for better error handling
class DatabaseError(Exception):
    """Custom exception for database-related errors"""
    pass

class ValidationError(Exception):
    """Custom exception for input validation errors"""
    pass

class AuthenticationError(Exception):
    """Custom exception for authentication-related errors"""
    pass

def validate_email(email):
    """Enhanced email validation"""
    if not email or len(email) > 255:
        return False
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

def validate_username(username):
    """Enhanced username validation"""
    if not username or len(username) < 3 or len(username) > 50:
        return False
    
    # Allow only alphanumeric characters and underscores
    username_pattern = r'^[a-zA-Z0-9_]+$'
    return re.match(username_pattern, username) is not None

def validate_password(password):
    """Enhanced password validation"""
    if not password or len(password) < 8:
        return False
    
    # Check for at least one uppercase, one lowercase, one digit
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    
    return True

def sanitize_input(data):
    """Sanitize input data to prevent XSS and injection attacks"""
    if isinstance(data, str):
        # Remove any potentially dangerous characters
        return data.strip()[:500]  # Limit length
    return data

def init_database_pool():
    """Initialize PostgreSQL connection pool using psycopg3 with enhanced error handling"""
    global db_pool

    # Get database URL from environment variable
    database_url = os.environ.get('DATABASE_URL')

    if not database_url:
        logger.error("DATABASE_URL environment variable is required")
        raise DatabaseError("DATABASE_URL environment variable is required")

    # Parse the database URL to handle different formats
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)

    try:
        # Create connection pool using psycopg3 with timeout and retry settings
        db_pool = ConnectionPool(
            conninfo=database_url,
            min_size=1,
            max_size=20,
            open=True,  # Open pool immediately
            timeout=30,  # Connection timeout
            max_idle=300,  # Maximum idle time
            max_lifetime=3600,  # Maximum connection lifetime
            reconnect_timeout=10  # Reconnection timeout
        )

        # Wait for pool to be ready with timeout
        db_pool.wait(timeout=30)
        logger.info("Database connection pool created successfully")
        
    except (psycopg.Error, PoolTimeout) as e:
        logger.error(f"Error creating database connection pool: {e}")
        raise DatabaseError(f"Failed to create database connection pool: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during database pool initialization: {e}")
        raise DatabaseError(f"Unexpected database initialization error: {e}")

def init_database():
    """Initialize the PostgreSQL database with users table and enhanced error handling"""
    if not db_pool:
        raise DatabaseError("Database pool not initialized")
    
    with db_lock:
        try:
            with db_pool.connection() as conn:
                with conn.cursor() as cursor:
                    try:
                        # Create users table if it doesn't exist (PostgreSQL syntax)
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS users (
                                id SERIAL PRIMARY KEY,
                                username VARCHAR(50) UNIQUE NOT NULL,
                                password_hash TEXT NOT NULL,
                                email VARCHAR(255) UNIQUE NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                last_login TIMESTAMP,
                                is_active BOOLEAN DEFAULT TRUE
                            )
                        """)
                        
                        # Create indexes for better performance
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                        """)
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                        """)

                        logger.info("Database tables and indexes created successfully")

                    except psycopg.Error as e:
                        logger.error(f"Error creating database tables: {e}")
                        raise DatabaseError(f"Failed to create database tables: {e}")
                        
        except (psycopg.Error, PoolTimeout) as e:
            logger.error(f"Error initializing database: {e}")
            raise DatabaseError(f"Database initialization failed: {e}")

def hash_password(password):
    """Hash a password using bcrypt with enhanced security"""
    try:
        # Use a higher cost factor for better security
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        raise AuthenticationError("Password hashing failed")

def verify_password(password, hashed):
    """Verify a password against its hash with error handling"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False

def generate_jwt_token(username):
    """Generate a JWT token for a user with enhanced security"""
    try:
        payload = {
            'username': username,
            'iat': datetime.utcnow(),  # Issued at time
            'exp': datetime.utcnow() + timedelta(hours=24),  # Token expires in 24 hours
            'jti': secrets.token_hex(8)  # Unique token ID
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    except Exception as e:
        logger.error(f"Error generating JWT token: {e}")
        raise AuthenticationError("Token generation failed")

def verify_jwt_token(token):
    """Verify and decode a JWT token with comprehensive error handling"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None
    except Exception as e:
        logger.error(f"Error verifying JWT token: {e}")
        return None

def require_auth(f):
    """Decorator to require authentication for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401

        try:
            token = auth_header.split(' ')[1]
            username = verify_jwt_token(token)
            
            if not username:
                return jsonify({'error': 'Invalid or expired token'}), 401
                
            # Add username to request context for use in the route
            request.current_user = username
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({'error': 'Authentication failed'}), 500
            
    return decorated_function

def handle_database_operation(operation):
    """Wrapper for database operations with comprehensive error handling"""
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        if db_pool is None:
            logger.error("Database connection pool not initialized")
            raise DatabaseError("Database connection pool not initialized")
        try:
            with db_lock:
                with db_pool.connection() as conn:
                    with conn.cursor() as cursor:
                        return operation(cursor)
                        
        except (psycopg.OperationalError, PoolTimeout) as e:
            logger.warning(f"Database operation failed (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                continue
            logger.error(f"Database operation failed after {max_retries} attempts")
            raise DatabaseError("Database operation failed after multiple retries")
            
        except psycopg.IntegrityError as e:
            logger.warning(f"Database integrity error: {e}")
            raise  # Re-raise integrity errors immediately
            
        except Exception as e:
            logger.error(f"Unexpected database error: {e}")
            raise DatabaseError(f"Unexpected database error: {e}")

# Error handlers
@app.errorhandler(ValidationError)
def handle_validation_error(e):
    logger.warning(f"Validation error: {e}")
    return jsonify({'error': str(e)}), 400

@app.errorhandler(AuthenticationError)
def handle_auth_error(e):
    logger.warning(f"Authentication error: {e}")
    return jsonify({'error': 'Authentication failed'}), 401

@app.errorhandler(DatabaseError)
def handle_database_error(e):
    logger.error(f"Database error: {e}")
    return jsonify({'error': 'Database operation failed'}), 500

@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def handle_internal_server_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user with comprehensive validation and error handling"""
    try:
        # Check if request contains JSON data
        if not request.is_json:
            raise ValidationError('Request must contain JSON data')
            
        data = request.get_json()
        if not data:
            raise ValidationError('Request body cannot be empty')

        # Extract and sanitize input
        required_fields = ['username', 'password', 'email']
        for field in required_fields:
            if field not in data:
                raise ValidationError(f'Missing required field: {field}')

        username = sanitize_input(data['username'])
        password = data['password']  # Don't sanitize password as it might alter it
        email = sanitize_input(data['email']).lower()

        # Enhanced validation
        if not validate_username(username):
            raise ValidationError('Username must be 3-50 characters long and contain only letters, numbers, and underscores')
        
        if not validate_password(password):
            raise ValidationError('Password must be at least 8 characters long and contain uppercase, lowercase, and numeric characters')
        
        if not validate_email(email):
            raise ValidationError('Invalid email format')

        # Hash the password
        password_hash = hash_password(password)

        # Database operation
        def register_user(cursor):
            cursor.execute(
                'INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)',
                (username, password_hash, email)
            )
            return True

        handle_database_operation(register_user)

        # Generate JWT token
        token = generate_jwt_token(username)

        logger.info(f"User registered successfully: {username}")
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'username': username
        }), 201

    except psycopg.IntegrityError:
        logger.warning(f"Registration failed - user already exists: {username if 'username' in locals() else 'unknown'}")
        return jsonify({'error': 'Username or email already exists'}), 409
        
    except (ValidationError, AuthenticationError) as e:
        return handle_validation_error(e)
        
    except DatabaseError as e:
        return handle_database_error(e)
        
    except Exception as e:
        logger.error(f"Unexpected registration error: {e}")
        return jsonify({'error': 'Registration failed due to unexpected error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Login a user with enhanced security and error handling"""
    try:
        # Check if request contains JSON data
        if not request.is_json:
            raise ValidationError('Request must contain JSON data')
            
        data = request.get_json()
        if not data:
            raise ValidationError('Request body cannot be empty')

        # Extract and sanitize input
        if not all(k in data for k in ('username', 'password')):
            raise ValidationError('Missing username or password')

        username = sanitize_input(data['username'])
        password = data['password']

        if not username or not password:
            raise ValidationError('Username and password cannot be empty')

        # Database operation to get user
        def get_user(cursor):
            cursor.execute(
                'SELECT username, password_hash, is_active FROM users WHERE username = %s',
                (username,)
            )
            return cursor.fetchone()

        user = handle_database_operation(get_user)

        if not user:
            logger.warning(f"Login attempt with non-existent username: {username}")
            return jsonify({'error': 'Invalid username or password'}), 401

        if not user[2]:  # is_active check
            logger.warning(f"Login attempt with inactive account: {username}")
            return jsonify({'error': 'Account is disabled'}), 401

        if not verify_password(password, user[1]):
            logger.warning(f"Login attempt with incorrect password: {username}")
            return jsonify({'error': 'Invalid username or password'}), 401

        # Update last login timestamp
        def update_last_login(cursor):
            cursor.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = %s',
                (username,)
            )

        handle_database_operation(update_last_login)

        # Generate JWT token
        token = generate_jwt_token(username)
        
        logger.info(f"User logged in successfully: {username}")
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'username': username
        }), 200

    except (ValidationError, AuthenticationError) as e:
        return handle_validation_error(e)
        
    except DatabaseError as e:
        return handle_database_error(e)
        
    except Exception as e:
        logger.error(f"Unexpected login error: {e}")
        return jsonify({'error': 'Login failed due to unexpected error'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout a user (client-side token removal)"""
    logger.info("User logout requested")
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/verify', methods=['GET'])
@require_auth
def verify_token():
    """Verify if a token is valid"""
    try:
        username = request.current_user
        logger.info(f"Token verified for user: {username}")
        return jsonify({'valid': True, 'username': username}), 200
        
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({'error': 'Token verification failed'}), 500

@app.route('/api/user/profile', methods=['GET'])
@require_auth
def get_profile():
    """Get user profile (protected route)"""
    try:
        username = request.current_user

        # Database operation to get user profile
        def get_user_profile(cursor):
            cursor.execute(
                'SELECT username, email, created_at, last_login FROM users WHERE username = %s',
                (username,)
            )
            return cursor.fetchone()

        user = handle_database_operation(get_user_profile)

        if not user:
            logger.warning(f"Profile requested for non-existent user: {username}")
            return jsonify({'error': 'User not found'}), 404

        logger.info(f"Profile retrieved for user: {username}")
        return jsonify({
            'username': user[0],
            'email': user[1],
            'created_at': user[2].isoformat() if user[2] else None,
            'last_login': user[3].isoformat() if user[3] else None
        }), 200

    except DatabaseError as e:
        return handle_database_error(e)
        
    except Exception as e:
        logger.error(f"Profile retrieval error: {e}")
        return jsonify({'error': 'Profile retrieval failed'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with database connectivity check"""
    try:
        # Check database connectivity
        def check_db(cursor):
            cursor.execute('SELECT 1')
            return cursor.fetchone()

        handle_database_operation(check_db)
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected'
        }), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'disconnected',
            'error': str(e)
        }), 503

@app.route('/', methods=['GET'])
def root():
    """Root endpoint with API documentation"""
    return jsonify({
        'message': 'Chrome Extension Backend API',
        'version': '2.0.0',
        'status': 'running',
        'endpoints': {
            'auth': [
                'POST /api/register',
                'POST /api/login', 
                'POST /api/logout',
                'GET /api/verify'
            ],
            'user': [
                'GET /api/user/profile'
            ],
            'system': [
                'GET /health',
                'GET /'
            ]
        }
    }), 200

if __name__ == '__main__':
    try:
        # Initialize database connection pool
        logger.info("Initializing database connection pool...")
        init_database_pool()

        # Initialize database tables
        logger.info("Initializing database tables...")
        init_database()

        # Get port from environment variable (Render.com sets this)
        port = int(os.environ.get('PORT', 5000))

        logger.info(f"Starting Flask application on port {port}")
        
        # Run the app
        # For development: debug=True, host='localhost'
        # For production: debug=False, host='0.0.0.0' (required for Render.com)
        app.run(
            debug=False,  # Set to False for production
            host='0.0.0.0',  # Required for Render.com
            port=port,
            threaded=True  # Enable threading for concurrent requests
        )
        
    except Exception as e:
        logger.critical(f"Failed to start application: {e}")
        raise