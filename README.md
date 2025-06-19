File: init_db.py - Database Initialization
<br>This optional script creates a fresh SQLite database with the users table . It's useful for development and testing but not required for production since the main app initializes the database automatically.

# Chrome Extension Backend

This is the backend API for the Chrome extension authentication system.

## Features

- User registration and login
- JWT token-based authentication
- SQLite database with thread-safe operations
- Password hashing with bcrypt
- CORS enabled for Chrome extension communication
- Ready for deployment on Render.com

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
python server.py
```

The server will run on `http://localhost:5000`

## API Endpoints

- `POST /api/register` - Register a new user
- `POST /api/login` - Login user
- `POST /api/logout` - Logout user
- `GET /api/verify` - Verify JWT token
- `GET /api/user/profile` - Get user profile (protected)
- `GET /health` - Health check

## Deployment on Render.com

1. Push this code to GitHub repository
2. Create new Web Service on Render.com
3. Connect your GitHub repository
4. Set the following:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn server:app`
   - **Environment Variables**: 
     - `SECRET_KEY`: Generate a secure random key
     - `FLASK_ENV`: `production`

## Database

Uses SQLite for simplicity. The database file (`users.db`) will be created automatically when the server starts.

## Security Features

- Password hashing with bcrypt
- JWT tokens with expiration
- Thread-safe database operations
- Input validation
- CORS properly configured for Chrome extensions
