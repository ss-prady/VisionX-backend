# Twitter Feed Sharing Chrome Extension Backend

A secure Flask-based backend API that powers a Chrome extension for sharing and accessing Twitter/X feeds among users. Built with enterprise-grade security, comprehensive error handling, and scalable architecture.

## Features

- **Secure Authentication**: JWT-based auth with bcrypt password hashing
- **Feed Sharing**: Share your Twitter feed with specific users
- **Tweet Fetching**: Asynchronous tweet retrieval with media support
- **Cookie Management**: Secure storage of X.com authentication cookies
- **Caching System**: 1-hour tweet caching for improved performance
- **Database Pooling**: PostgreSQL connection pooling for scalability
- **Comprehensive Logging**: Detailed logging for monitoring and debugging
- **CORS Support**: Full Chrome extension compatibility

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: PostgreSQL with psycopg3
- **Authentication**: JWT tokens with bcrypt
- **Twitter API**: twikit library
- **Async Processing**: asyncio with ThreadPoolExecutor
- **Security**: Input validation, XSS protection, rate limiting

## Prerequisites

- Python 3.8+
- PostgreSQL 12+
- X.com account cookies (for tweet fetching)

## Deployment

### Render.com (Recommended)
1. Connect your GitHub repository to Render
2. Set environment variables in Render dashboard
3. Deploy with automatic builds

### Local Development

python server.py


## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/logout` - User logout
- `GET /api/verify` - Verify JWT token

### User Management
- `GET /api/user/profile` - Get user profile
- `DELETE /api/user/delete` - Delete user account

### Feed Sharing
- `POST /api/share-feed` - Share feed with another user
- `GET /api/shared-users` - Get users you've shared with
- `GET /api/fetch-users` - Get users who shared with you
- `DELETE /api/unshare-feed/<username>` - Revoke feed access

### Tweet Operations
- `POST /api/save-cookies` - Save X.com cookies
- `POST /api/fetch-feed/<username>` - Fetch tweets from shared feed

### System
- `GET /health` - Health check endpoint
- `POST /api/cleanup-expired-tweets` - Clean expired cache

## Security Features

- **Password Security**: Bcrypt hashing with salt rounds
- **JWT Tokens**: Secure token-based authentication
- **Input Validation**: Comprehensive input sanitization
- **Database Security**: Parameterized queries prevent SQL injection
- **CORS Configuration**: Secure cross-origin resource sharing
- **Error Handling**: Detailed error logging without information leakage

## Database Schema

-- Users table
users (id, username, password_hash, email, created_at, last_login, is_active)
-- Feed sharing relationships
feed_shares (owner_id, shared_with_id, created_at)
feed_fetches (user_id, fetch_from_id, created_at)
-- Cookie storage
user_cookies (user_id, cookies, updated_at)
-- Tweet caching
user_tweets (user_id, fetched_from_id, tweets_data, fetched_at, expires_at)


## Configuration

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: JWT signing secret
- `PORT`: Server port (default: 5000)

### Chrome Extension Integration
The API is designed to work with a Chrome extension that:
1. Captures X.com cookies
2. Sends authentication requests
3. Manages feed sharing
4. Displays fetched tweets

## Performance Features

- **Connection Pooling**: Efficient database connections
- **Async Processing**: Non-blocking tweet fetching
- **Caching System**: 1-hour tweet cache reduces API calls
- **Thread Pool**: Concurrent request handling
- **Automatic Cleanup**: Expired data removal

## Error Handling

- Custom exception classes for different error types
- Comprehensive logging with rotation
- Graceful degradation for external API failures
- Database retry logic with exponential backoff

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes. Ensure compliance with Twitter's Terms of Service and applicable laws when using this software.

## Support

For issues and questions:
1. Check the GitHub Issues page
2. Review the API documentation
3. Check application logs for error details

---

**Note**: This backend requires a corresponding Chrome extension frontend to function as intended.
