# Complete Authentication System

A production-ready authentication system built with NestJS, Prisma, and PostgreSQL featuring JWT tokens with rotation, multi-device support, and security best practices.

## Features

- ✅ Email/Password Authentication
- ✅ JWT Access Tokens (short-lived, 15 minutes)
- ✅ JWT Refresh Tokens (long-lived, 7-30 days)
- ✅ Token Rotation on Refresh
- ✅ Multi-Device Session Support
- ✅ HTTP-Only Secure Cookies
- ✅ Password Hashing with Bcrypt
- ✅ Role-Based Access Control (RBAC)
- ✅ Global Authentication Guard
- ✅ Logout & Logout All Devices
- ✅ Swagger API Documentation
- ✅ Environment Validation
- ✅ Error Handling & Logging

## Tech Stack

- **Backend:** NestJS 10.x
- **Database:** PostgreSQL
- **ORM:** Prisma 5.x
- **Authentication:** Passport JWT
- **Validation:** class-validator
- **Documentation:** Swagger/OpenAPI

## Prerequisites

- Node.js 18+ and npm/yarn
- PostgreSQL 14+
- Git

## Installation

### 1. Clone or Initialize Project

```bash
mkdir auth-system && cd auth-system
npm init -y
```

### 2. Install Dependencies

```bash
npm install @nestjs/common@^10.3.0 @nestjs/core@^10.3.0 @nestjs/platform-express@^10.3.0 @nestjs/config@^3.1.1 @nestjs/jwt@^10.2.0 @nestjs/passport@^10.0.3 @nestjs/swagger@^7.1.17 @prisma/client@^5.7.1 bcrypt@^5.1.1 class-transformer@^0.5.1 class-validator@^0.14.0 cookie-parser@^1.4.6 helmet@^7.1.0 joi@^17.11.0 passport@^0.7.0 passport-jwt@^4.0.1 reflect-metadata@^0.1.14 rimraf@^5.0.5 rxjs@^7.8.1

npm install -D @nestjs/cli@^10.2.1 @nestjs/schematics@^10.0.3 @nestjs/testing@^10.3.0 @types/bcrypt@^5.0.2 @types/cookie-parser@^1.4.6 @types/express@^4.17.21 @types/jest@^29.5.11 @types/node@^20.10.6 @types/passport-jwt@^4.0.0 @types/supertest@^6.0.2 @typescript-eslint/eslint-plugin@^6.17.0 @typescript-eslint/parser@^6.17.0 eslint@^8.56.0 eslint-config-prettier@^9.1.0 eslint-plugin-prettier@^5.1.2 jest@^29.7.0 prettier@^3.1.1 prisma@^5.7.1 source-map-support@^0.5.21 supertest@^6.3.3 ts-jest@^29.1.1 ts-loader@^9.5.1 ts-node@^10.9.2 tsconfig-paths@^4.2.0 typescript@^5.3.3
```

### 3. Setup Environment Variables

Create `.env` file in root:

```bash
cp .env.example .env
```

Update with your values:

```env
NODE_ENV=development
PORT=3000
API_PREFIX=api/v1

DATABASE_URL="postgresql://username:password@localhost:5432/auth_db?schema=public"

JWT_ACCESS_SECRET=your-super-secret-access-key-min-32-chars
JWT_REFRESH_SECRET=your-super-secret-refresh-key-min-32-chars
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

BCRYPT_ROUNDS=10

CORS_ORIGIN=http://localhost:3000
COOKIE_SECRET=your-cookie-secret-min-32-chars
```

### 4. Initialize Prisma

```bash
npx prisma init
```

### 5. Run Migrations

```bash
npx prisma migrate dev --name init
```

### 6. Generate Prisma Client

```bash
npx prisma generate
```

### 7. Start Development Server

```bash
npm run start:dev
```

The API will be available at:
- **API:** http://localhost:3000/api/v1
- **Swagger Docs:** http://localhost:3000/api/docs

## API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register new user | No |
| POST | `/auth/login` | Login with credentials | No |
| POST | `/auth/refresh` | Refresh access token | Refresh Token |
| POST | `/auth/logout` | Logout current session | Yes |
| POST | `/auth/logout-all` | Logout all sessions | Yes |

### Users

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/users/me` | Get current user profile | Yes |
| GET | `/users` | Get all users | Yes |

## Usage Examples

### Register

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Login

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### Access Protected Route

```bash
curl -X GET http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh Token

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Cookie: refreshToken=YOUR_REFRESH_TOKEN"
```

## Security Features

1. **Password Hashing:** Bcrypt with configurable rounds
2. **JWT Tokens:** Separate access and refresh tokens
3. **Token Rotation:** New refresh token on each refresh
4. **HTTP-Only Cookies:** Secure refresh token storage
5. **Token Revocation:** Database-backed token invalidation
6. **Multi-Device Support:** Track and manage sessions per device
7. **Global Auth Guard:** Protected by default, opt-out with `@Public()`
8. **Role-Based Access:** Support for USER, ADMIN, MODERATOR roles
9. **Environment Validation:** Joi schema validation
10. **Security Headers:** Helmet middleware

## Project Structure

```
src/
├── auth/           # Authentication module
├── user/           # User management module
├── prisma/         # Database service
├── common/         # Shared utilities
├── config/         # Configuration files
└── main.ts         # Application entry point
```

## Database Schema

### Users Table
- id (UUID)
- email (unique)
- password (hashed)
- firstName, lastName
- role (enum: USER, ADMIN, MODERATOR)
- isActive (boolean)
- timestamps

### RefreshTokens Table
- id (UUID)
- token (unique)
- userId (FK to users)
- deviceId (optional)
- userAgent, ipAddress
- expiresAt
- isRevoked
- timestamps

## Development

### Run Prisma Studio

```bash
npm run prisma:studio
```

### Run Tests

```bash
npm run test
npm run test:watch
npm run test:cov
```

### Lint & Format

```bash
npm run lint
npm run format
```

### Build for Production

```bash
npm run build
npm run start:prod
```

## Deployment Checklist

- [ ] Update environment variables for production
- [ ] Change JWT secrets to strong random values
- [ ] Enable HTTPS
- [ ] Set `NODE_ENV=production`
- [ ] Configure proper CORS origins
- [ ] Set up database backups
- [ ] Enable rate limiting
- [ ] Configure logging service
- [ ] Set up monitoring (e.g., Sentry)
- [ ] Review and adjust token expiration times

## License

MIT

## Author

Yoko Hailemariam (@yokohailemariam)