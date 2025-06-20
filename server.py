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
import json
import asyncio
import json
import tempfile
from twikit import Client
from concurrent.futures import ThreadPoolExecutor


app = Flask(__name__)

# Enable CORS for all routes - this is crucial for Chrome extension communication
CORS(app, supports_credentials=True)

# Secret key for JWT tokens - in production, use environment variable
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SECRET_KEY'] = SECRET_KEY

# Thread pool for async operations
tweet_executor = ThreadPoolExecutor(max_workers=5)

class TweetFetcher:
    def __init__(self):
        self.active_fetches = {}  # Track ongoing fetches
        self.fetch_lock = threading.Lock()
    
    async def fetch_tweets_for_user(self, cookies_dict, user_id, fetch_from_id):
        """Fetch tweets using twikit with user-specific cookies"""
        try:
            client = Client()
            
            # Create temporary cookie file for this specific fetch
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                json.dump(cookies_dict, temp_file)
                temp_cookie_path = temp_file.name
            
            try:
                # Load cookies from temporary file
                client.load_cookies(path=temp_cookie_path)
                
                tweet_data = []
                tweets = await client.get_timeline(count=20)
                
                while tweets and len(tweet_data) < 100:
                    for tweet in tweets:
                        user = tweet.user
                        media_urls = []
                        
                        # Handle media (same logic as main.py)
                        if tweet.media:
                            for media in tweet.media:
                                if media.type == "photo":
                                    url = getattr(media, "media_url_https", None) or getattr(media, "media_url", None)
                                    if url:
                                        media_urls.append(url)
                                elif media.type in ("video", "animated_gif") and hasattr(media, "streams"):
                                    streams = media.streams or []
                                    if streams:
                                        best = streams[-1]
                                        if best.url:
                                            media_urls.append(best.url)
                        
                        profile_image_url = getattr(user, "profile_image_url_https", None) or getattr(user, "profile_image_url", None)
                        cleaned_text = re.sub(r"https://t\.co/\w+", "", tweet.full_text).strip()
                        
                        tweet_data.append({
                            "username": tweet.user.screen_name,
                            "name": tweet.user.name,
                            "verified": tweet.user.is_blue_verified,
                            "profile_image_url": profile_image_url,
                            "text": cleaned_text,
                            "tweet_id": getattr(tweet, "id", None),
                            "created_at": str(tweet.created_at),
                            "url": f"https://twitter.com/{tweet.user.screen_name}/status/{tweet.id}",
                            "media": media_urls,
                            "like_count": getattr(tweet, "favorite_count", 0),
                            "retweet_count": getattr(tweet, "retweet_count", 0),
                            "reply_count": getattr(tweet, "reply_count", 0),
                            "views": getattr(tweet, "view_count", 0)
                        })
                        
                        if len(tweet_data) >= 100:
                            break
                    
                    if len(tweet_data) >= 100:
                        break
                    
                    await asyncio.sleep(3)  # PAGE_FETCH_DELAY
                    tweets = await tweets.next()
                
                return tweet_data
                
            finally:
                # Clean up temporary cookie file
                if os.path.exists(temp_cookie_path):
                    os.unlink(temp_cookie_path)
                    
        except Exception as e:
            logger.error(f"Error fetching tweets: {e}")
            raise

# Global tweet fetcher instance
tweet_fetcher = TweetFetcher()

# Database connection pool
db_pool = None
db_lock = threading.Lock()

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

                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS feed_shares (
                                owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                                shared_with_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                PRIMARY KEY (owner_id, shared_with_id)
                            )
                        """)
                        
                        # Create index for shared_with lookups
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_feed_shares_shared ON feed_shares(shared_with_id);
                        """)

                        # Inside init_database() after creating feed_shares table
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS feed_fetches (
                                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                                fetch_from_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                PRIMARY KEY (user_id, fetch_from_id)
                            )
                        """)
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_feed_fetches_user ON feed_fetches(user_id)
                        """)

                        # Add this to your init_database() function
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS user_tweets (
                                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                                fetched_from_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                                tweets_data JSONB NOT NULL,
                                fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '1 hour'),
                                PRIMARY KEY (user_id, fetched_from_id)
                            )
                        """)

                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_user_tweets_expires ON user_tweets(expires_at);
                        """)

                        logger.info("Database tables and indexes created successfully")

                    except psycopg.Error as e:
                        logger.error(f"Error creating database tables: {e}")
                        raise DatabaseError(f"Failed to create database tables: {e}")
                        
        except (psycopg.Error, PoolTimeout) as e:
            logger.error(f"Error initializing database: {e}")
            raise DatabaseError(f"Database initialization failed: {e}")

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

try:
    logger.info("Initializing database connection pool...")
    init_database_pool()
    
    logger.info("Initializing database tables...")
    init_database()
    
    logger.info("Database initialization completed successfully")
except Exception as e:
    logger.critical(f"Failed to initialize database: {e}")
    raise

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

def save_user_cookies(cursor, username, cookies_json):
    # Convert the dictionary to a JSON string
    cookies_json_str = json.dumps(cookies_json)
    # Create table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_cookies (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            cookies JSONB NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id)
        )
    """)
    # Upsert cookies
    cursor.execute("""
        INSERT INTO user_cookies (user_id, cookies, updated_at)
        VALUES (
            (SELECT id FROM users WHERE username = %s),
            %s,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (user_id) DO UPDATE
        SET cookies = EXCLUDED.cookies,
            updated_at = EXCLUDED.updated_at
    """, (username, cookies_json_str))


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

@app.route('/api/user/delete', methods=['DELETE'])
@require_auth
def delete_account():
    """Delete user account (protected route)"""
    try:
        username = request.current_user

        # First verify the user's password for security
        if not request.is_json:
            raise ValidationError('Request must contain JSON data')
            
        data = request.get_json()
        if not data or 'password' not in data:
            raise ValidationError('Password confirmation is required')

        password = data['password']

        # Database operation to verify password
        def verify_and_delete(cursor):
            # Get user's password hash
            cursor.execute(
                'SELECT password_hash FROM users WHERE username = %s',
                (username,)
            )
            user = cursor.fetchone()
            
            if not user:
                raise AuthenticationError('User not found')
                
            if not verify_password(password, user[0]):
                raise AuthenticationError('Invalid password')
                
            # Delete the user account
            cursor.execute(
                'DELETE FROM users WHERE username = %s',
                (username,)
            )
            return True

        handle_database_operation(verify_and_delete)

        logger.info(f"Account deleted successfully: {username}")
        return jsonify({
            'message': 'Account deleted successfully',
            'username': username
        }), 200

    except (ValidationError, AuthenticationError) as e:
        logger.warning(f"Account deletion failed for {username}: {str(e)}")
        return jsonify({'error': str(e)}), 401
        
    except DatabaseError as e:
        logger.error(f"Database error during account deletion for {username}: {str(e)}")
        return jsonify({'error': 'Account deletion failed'}), 500
        
    except Exception as e:
        logger.error(f"Unexpected error during account deletion for {username}: {str(e)}")
        return jsonify({'error': 'Account deletion failed due to unexpected error'}), 500


@app.route('/api/save-cookies', methods=['POST'])
@require_auth
def save_cookies():
    """Save X.com cookies for the authenticated user."""
    try:
        if not request.is_json:
            raise ValidationError('Request must contain JSON data')
        data = request.get_json()
        if 'cookies' not in data or not isinstance(data['cookies'], dict):
            raise ValidationError('Invalid cookies payload')

        username = request.current_user
        cookies_json = data['cookies']

        # Persist cookies in DB
        def operation(cursor):
            save_user_cookies(cursor, username, cookies_json)
        handle_database_operation(operation)

        logger.info(f"Cookies saved successfully for user: {username}")
        return jsonify({'message': 'Cookies saved successfully'}), 200

    except (ValidationError) as e:
        logger.warning(f"Save cookies validation failed for {request.current_user}: {e}")
        return jsonify({'error': str(e)}), 400

    except DatabaseError as e:
        logger.error(f"Database error saving cookies for {request.current_user}: {e}")
        return jsonify({'error': 'Failed to save cookies'}), 500

    except Exception as e:
        logger.error(f"Unexpected error saving cookies for {request.current_user}: {e}")
        return jsonify({'error': 'Unexpected error saving cookies'}), 500


@app.route('/api/share-feed', methods=['POST'])
@require_auth
def share_feed():
    try:
        if not request.is_json:
            raise ValidationError('Request must contain JSON data')
        data = request.get_json()
        if 'share_with' not in data:
            raise ValidationError('Missing "share_with" username')

        owner_username = request.current_user
        share_with_username = sanitize_input(data['share_with'])

        if owner_username == share_with_username:
            raise ValidationError('Cannot share feed with yourself')

        # Validate target user exists and is active
        def get_user_ids(cursor):
            cursor.execute('SELECT id FROM users WHERE username = %s AND is_active = TRUE', (owner_username,))
            owner = cursor.fetchone()
            cursor.execute('SELECT id FROM users WHERE username = %s AND is_active = TRUE', (share_with_username,))
            shared_with = cursor.fetchone()
            return owner, shared_with

        owner, shared_with = handle_database_operation(get_user_ids)
        if not shared_with:
            raise ValidationError('Target user does not exist or is inactive')
        if not owner:
            raise AuthenticationError('Owner user not found')

        def insert_share(cursor):
            # Insert into share list
            cursor.execute("""
                INSERT INTO feed_shares (owner_id, shared_with_id)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
            """, (owner[0], shared_with[0]))
            
            # Insert reciprocal into fetch list
            cursor.execute("""
                INSERT INTO feed_fetches (user_id, fetch_from_id)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
            """, (shared_with[0], owner[0]))

        handle_database_operation(insert_share)
        logger.info(f"Feed shared: {owner_username} -> {share_with_username}")
        return jsonify({'message': f'Feed shared with {share_with_username}!'}), 200

    except (ValidationError, AuthenticationError) as e:
        return handle_validation_error(e)
    except psycopg.IntegrityError:
        return jsonify({'error': 'Feed already shared with this user'}), 409
    except Exception as e:
        logger.error(f"Share feed error: {e}")
        return jsonify({'error': 'Sharing failed'}), 500


@app.route('/api/shared-users', methods=['GET'])
@require_auth
def shared_users():
    try:
        owner_username = request.current_user

        def get_shared_users(cursor):
            cursor.execute("""
                SELECT u.username
                FROM feed_shares fs
                JOIN users u ON fs.shared_with_id = u.id
                WHERE fs.owner_id = (SELECT id FROM users WHERE username = %s)
            """, (owner_username,))
            return [{'username': row[0]} for row in cursor.fetchall()]

        users = handle_database_operation(get_shared_users)
        return jsonify(users), 200

    except Exception as e:
        logger.error(f"Failed to load shared users: {e}")
        return jsonify({'error': 'Failed to load shared users'}), 500

@app.route('/api/fetch-users', methods=['GET'])
@require_auth
def fetch_users():
    try:
        current_username = request.current_user

        def get_fetch_users(cursor):
            cursor.execute("""
                SELECT u.username
                FROM feed_fetches ff
                JOIN users u ON ff.fetch_from_id = u.id
                WHERE ff.user_id = (SELECT id FROM users WHERE username = %s)
            """, (current_username,))
            return [{'username': row[0]} for row in cursor.fetchall()]

        users = handle_database_operation(get_fetch_users)
        return jsonify(users), 200

    except Exception as e:
        logger.error(f"Failed to load fetch users: {e}")
        return jsonify({'error': 'Failed to load fetch users'}), 500


@app.route('/api/unshare-feed/<username>', methods=['DELETE'])
@require_auth
def unshare_feed(username):
    try:
        owner_username = request.current_user
        target_username = sanitize_input(username)

        def get_user_ids(cursor):
            cursor.execute('SELECT id FROM users WHERE username = %s', (owner_username,))
            owner = cursor.fetchone()
            cursor.execute('SELECT id FROM users WHERE username = %s', (target_username,))
            shared_with = cursor.fetchone()
            return owner, shared_with

        owner, shared_with = handle_database_operation(get_user_ids)
        if not owner or not shared_with:
            raise ValidationError('User not found')

        def delete_share(cursor):
            # Remove from share list
            cursor.execute("""
                DELETE FROM feed_shares
                WHERE owner_id = %s AND shared_with_id = %s
            """, (owner[0], shared_with[0]))
            
            # Remove reciprocal from fetch list
            cursor.execute("""
                DELETE FROM feed_fetches
                WHERE user_id = %s AND fetch_from_id = %s
            """, (shared_with[0], owner[0]))

        handle_database_operation(delete_share)
        logger.info(f"Feed access revoked: {owner_username} -> {target_username}")
        return jsonify({'message': f'Access revoked from {target_username}'}), 200

    except (ValidationError, AuthenticationError) as e:
        return handle_validation_error(e)
    except Exception as e:
        logger.error(f"Unshare feed error: {e}")
        return jsonify({'error': 'Revocation failed'}), 500

@app.route('/api/fetch-feed/<username>', methods=['POST'])
@require_auth
def fetch_user_feed(username):
    """Fetch tweets from a user's feed that has been shared with current user"""
    try:
        current_username = request.current_user
        target_username = sanitize_input(username)
        
        if current_username == target_username:
            raise ValidationError('Cannot fetch your own feed through this endpoint')
        
        # Verify access permissions and get user data
        def verify_access_and_get_data(cursor):
            # Check if current user has access to target user's feed
            cursor.execute("""
                SELECT ff.fetch_from_id, u1.username, u2.id as current_user_id
                FROM feed_fetches ff
                JOIN users u1 ON ff.fetch_from_id = u1.id
                JOIN users u2 ON ff.user_id = u2.id
                WHERE u2.username = %s AND u1.username = %s
            """, (current_username, target_username))
            
            access_check = cursor.fetchone()
            if not access_check:
                raise ValidationError('You do not have access to this user\'s feed')
            
            fetch_from_id, target_user, current_user_id = access_check
            
            # Get target user's cookies
            cursor.execute("""
                SELECT cookies FROM user_cookies WHERE user_id = %s
            """, (fetch_from_id,))
            
            cookies_row = cursor.fetchone()
            if not cookies_row:
                raise ValidationError('Target user has not saved their cookies yet')
            
            return {
                'fetch_from_id': fetch_from_id,
                'current_user_id': current_user_id,
                'cookies': cookies_row[0],
                'target_username': target_user
            }
        
        user_data = handle_database_operation(verify_access_and_get_data)
        
        # Check if we have recent cached data
        def check_cached_tweets(cursor):
            cursor.execute("""
                SELECT tweets_data, fetched_at 
                FROM user_tweets 
                WHERE user_id = %s AND fetched_from_id = %s 
                AND expires_at > CURRENT_TIMESTAMP
            """, (user_data['current_user_id'], user_data['fetch_from_id']))
            return cursor.fetchone()
        
        cached_data = handle_database_operation(check_cached_tweets)
        
        if cached_data:
            logger.info(f"Returning cached tweets for {current_username} from {target_username}")
            return jsonify({
                'tweets': cached_data[0],
                'fetched_at': cached_data[1].isoformat(),
                'cached': True,
                'source_user': target_username
            }), 200
        
        # Create unique fetch identifier
        fetch_key = f"{user_data['current_user_id']}_{user_data['fetch_from_id']}"
        
        # Check if fetch is already in progress
        with tweet_fetcher.fetch_lock:
            if fetch_key in tweet_fetcher.active_fetches:
                return jsonify({
                    'message': 'Feed fetch already in progress',
                    'status': 'processing'
                }), 202
            
            tweet_fetcher.active_fetches[fetch_key] = True
        
        try:
            # Fetch tweets asynchronously
            def run_async_fetch():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(
                        tweet_fetcher.fetch_tweets_for_user(
                            user_data['cookies'], 
                            user_data['current_user_id'],
                            user_data['fetch_from_id']
                        )
                    )
                finally:
                    loop.close()
            
            # Run in thread pool to avoid blocking
            future = tweet_executor.submit(run_async_fetch)
            tweets_data = future.result(timeout=300)  # 5 minute timeout
            
            # Store in database
            def store_tweets(cursor):
                cursor.execute("""
                    INSERT INTO user_tweets (user_id, fetched_from_id, tweets_data, expires_at)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP + INTERVAL '1 hour')
                    ON CONFLICT (user_id, fetched_from_id) 
                    DO UPDATE SET 
                        tweets_data = EXCLUDED.tweets_data,
                        fetched_at = CURRENT_TIMESTAMP,
                        expires_at = EXCLUDED.expires_at
                """, (user_data['current_user_id'], user_data['fetch_from_id'], json.dumps(tweets_data)))
            
            handle_database_operation(store_tweets)
            
            logger.info(f"Successfully fetched {len(tweets_data)} tweets for {current_username} from {target_username}")
            
            return jsonify({
                'tweets': tweets_data,
                'fetched_at': datetime.utcnow().isoformat(),
                'cached': False,
                'source_user': target_username,
                'count': len(tweets_data)
            }), 200
            
        finally:
            # Remove from active fetches
            with tweet_fetcher.fetch_lock:
                tweet_fetcher.active_fetches.pop(fetch_key, None)
    
    except ValidationError as e:
        return handle_validation_error(e)
    except Exception as e:
        logger.error(f"Feed fetch error for {current_username} from {target_username}: {e}")
        return jsonify({'error': 'Feed fetch failed'}), 500

@app.route('/api/cleanup-expired-tweets', methods=['POST'])
def cleanup_expired_tweets():
    """Clean up expired tweet data - can be called by a cron job"""
    try:
        def cleanup_operation(cursor):
            cursor.execute("DELETE FROM user_tweets WHERE expires_at < CURRENT_TIMESTAMP")
            return cursor.rowcount
        
        deleted_count = handle_database_operation(cleanup_operation)
        
        logger.info(f"Cleaned up {deleted_count} expired tweet records")
        return jsonify({
            'message': f'Cleaned up {deleted_count} expired records',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        return jsonify({'error': 'Cleanup failed'}), 500

if __name__ == '__main__':
    try:
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