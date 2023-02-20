const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const express = require('express');
const xss = require('xss-clean');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');
const hpp = require('hpp');
const cookieSession = require("cookie-session");
const passport = require("passport");
const passportSetup = require("./passport");


const globalErrorHandler = require('./controllers/error.controller');
const apiV1Router = require('./routes/api.v1.router');
const AppError = require('./services/AppError');

const app = express();

// Set security HTTP headers
app.use(helmet());

// Allowing cross origin resource sharing
app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  })
);

app.use(
  cookieSession({ name: "session", keys: ["lama"], maxAge: 24 * 60 * 60 * 100 })
);

app.use(passport.initialize());
app.use(passport.session());


// Limit requests from same IP
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many request from this IP, please try again in an hour!',
});
app.use('/api', limiter);

// Development logging
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against NoSQL query injection
app.use(xss());

// Prevent parameter pollution
app.use(
  hpp({
    whitelist: ['userNumber'],
  })
);

// Api routes
app.use('/api/v1', apiV1Router);

// Handling unhandled routes
app.all('*', (req, res, next) =>
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404))
);

app.use(globalErrorHandler);

module.exports = app;
