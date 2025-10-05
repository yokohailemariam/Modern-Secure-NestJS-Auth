export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  apiPrefix: process.env.API_PREFIX || 'api/v1',
  environment: process.env.NODE_ENV || 'development',

  database: {
    url: process.env.DATABASE_URL,
  },

  jwt: {
    access: {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: process.env.JWT_ACCESS_EXPIRATION || '15m',
    },
    refresh: {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d',
    },
  },

  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 10,

    // Account Lockout Configuration
    accountLockout: {
      maxAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5,
      lockDuration: parseInt(process.env.ACCOUNT_LOCK_DURATION, 10) || 15, // minutes
      attemptWindow: parseInt(process.env.LOGIN_ATTEMPT_WINDOW, 10) || 15, // minutes
      progressiveLockout: process.env.PROGRESSIVE_LOCKOUT === 'true', // Enable progressive lockout
    },
  },

  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  },

  cookie: {
    secret: process.env.COOKIE_SECRET,
  },

  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackUrl: process.env.GOOGLE_CALLBACK_URL,
    },

    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackUrl: process.env.FACEBOOK_CALLBACK_URL,
    },
  },
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3001',

  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10) || 587,
    user: process.env.EMAIL_USER,
    password: process.env.EMAIL_PASSWORD,
    from: process.env.EMAIL_FROM || '<noreply@example.com>',
  },
});
