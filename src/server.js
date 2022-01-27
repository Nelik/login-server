const fs = require('fs');
const morgan = require('morgan');
const AWS = require('aws-sdk');
const express = require('express');
// use JWT for session token
const jwt = require('express-jwt');
const jsonwebtoken = require('jsonwebtoken');
// Use CORS mechanism
const cors = require('cors');
const cookieParser = require('cookie-parser');
// Use csurf to protect against CSRF
const csrf = require('csurf');
// Use b-crypt to hash passwords
const bcrypt = require('bcrypt');
const redis = require('redis');
const logger = require('./utils/logger');
const httpStatusCodes = require('./utils/httpStatusCodes');

const bCryptSaltRounds = 10;
const jwtTimeLimitSeconds = 15 * 60;
const sessionExpiryTime = 15 * 60;
let jwtSecret = '';

AWS.config.update({
  region: 'us-west-2',
});
const ddbClient = new AWS.DynamoDB();
const secretsManagerClient = new AWS.SecretsManager();

var secretsManagerRequest = {
  SecretId: 'jwtKey',
};
secretsManagerClient.getSecretValue(secretsManagerRequest, function (err, data) {
  if (err) {
    logger.error(`AWS Secret Manager Client error. Stack: ${err.stack}`);
  } else {
    jwtSecret = data.SecretString;
  }
});

const app = express();
app.use(express.json());

// Setting up cookie and CSRF protection
app.use(cookieParser());
const csrfProtection = csrf({
  cookie: true,
});
app.use(csrfProtection);
app.use(cors());

// Configure redis client
const redisClient = redis.createClient({
  host: 'localhost',
  port: 6379,
});
redisClient.connect();
redisClient.on('error', function (err) {
  logger.error('Could not establish a connection with redis. ' + err);
});
redisClient.on('connect', function (err) {
  logger.info('Connected to redis successfully');
});

// Set morgan to log HTTP requests
morgan.token('jwt', function (req, res, param) {
  return req.cookies?.token ?? '';
});
morgan.token('csrfToken', function (req, res, param) {
  return req.csrfToken();
});
app.use(
  morgan('common', {
    stream: fs.createWriteStream('./logs/access.log', { flags: 'a' }),
  })
);
app.use(
  morgan(
    ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :csrfToken :jwt'
  )
);

// Catching uncaught exceptions
process.on('uncaughtException', function (err) {
  console.log('Caught exception: ' + err);
  logger.error('Caught exception: ' + err);
});

/**
 * Create a token to protect against cross site request forgery.
 */
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

/**
 * Verify that the session token is valid and which user it belongs to.
 */
app.get('/is-logged-in', async (req, res) => {
  const token = req.cookies.token;
  //If there's no session cookie, the user is not logged in.
  if (token === undefined) {
    logger.debug('Called is-logged-in without providing token.');
    res.json({ message: "User isn't logged in.", isLoggedIn: false });
    return;
  }

  // When a token is present, verify that it exists in Redis.
  result = await redisClient.exists(token);

  // If token is present, user is considered logged in.
  if (result === 1) {
    logger.debug('is logged in');
    res.json({ message: 'User is logged in.', isLoggedIn: true });
  } else {
    logger.debug('is not logged in');
    res.json({ message: "User isn't logged in.", isLoggedIn: false });
  }
});

/**
 * Invalidate cookie in a storage
 */
app.get('/log-out', async (req, res) => {
  const token = req.cookies.token;
  await redisClient.del(token);
  logger.info(`Logging out. Token ${token} has been invalidated.`);
  res.json({ message: 'User has been successfully logged out.' });
});

/**
 * Log in with username and password and generate jwt token
 */
app.post('/log-in', (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    logger.info('Login unsuccessfull. Some information is missing.');
    res.status(httpStatusCodes.BAD_REQUEST).json({ error: 'Log-in error. Username  and password are requiered.' });
    return;
  }

  logger.info('Logging in with user: ' + username);
  var params = {
    Key: {
      username: {
        S: username,
      },
    },
    TableName: 'InterviewProjectUsers',
  };

  ddbClient.getItem(params, async function (err, data) {
    if (err) {
      logger.error(`Log in: Unable to query. Error: ${JSON.stringify(err, null, 2)}`);
      res
        .status(httpStatusCodes.INTERNAL_SERVER)
        .json({ error: 'There was an unexpected error. Please, try to log in again.' });
    } else if (data.Item) {
      // Compare password with the hash in DB
      const isCorrectPswd = await bcrypt.compare(password, data.Item.password.S);
      if (isCorrectPswd) {
        logger.info(`Generating token for user ${username}`);
        // Generate jwtToken, set a cookie with expire time and send a response
        createSession(username, req, res);
      } else {
        logger.info(`${username} provided wrong password.`);
        res.status(httpStatusCodes.UNAUTHORIZED).json({ error: 'User or password is not valid.' });
      }
    } else {
      logger.info(`${username} doesn't exist in DB.`);
      res.status(httpStatusCodes.UNAUTHORIZED).json({ error: 'User or password is not valid.' });
    }
  });
});

/**
 * Sign-up with username, email and password and generate JWT token. After signup generate session
 * and store it in Redis.
 */
app.post('/sign-up', (req, res, next) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) {
    logger.info('Sign up unsuccessfull. Some information is missing.');
    res
      .status(httpStatusCodes.BAD_REQUEST)
      .json({ error: 'Sign-un error. Username, password and email are requiered.' });
    return;
  }
  const getUserParams = {
    Key: {
      username: {
        S: username,
      },
    },
    TableName: 'InterviewProjectUsers',
  };

  // First check if user already exists
  ddbClient.getItem(getUserParams, async function (err, data) {
    if (err) {
      logger.error('Sign up: Unable to query. Error:', JSON.stringify(err, null, 2));
      res
        .status(httpStatusCodes.INTERNAL_SERVER)
        .json({ error: 'An unexpected error happened, please try to sign up again.' });
    } else if (data.Item) {
      logger.info('User already exists.');
      res.status(httpStatusCodes.FORBIDDEN).json({ error: `User ${username} already exists.` });
    } else {
      // Create parameters to insert a new user to DB
      const encryptedPassword = await bcrypt.hash(password, bCryptSaltRounds);

      const newUserParams = {
        Item: {
          username: {
            S: username,
          },
          email: {
            S: email,
          },
          password: {
            S: encryptedPassword,
          },
        },
        ReturnConsumedCapacity: 'TOTAL',
        TableName: 'InterviewProjectUsers',
      };

      // Create a new user in DB and generate JWT token
      ddbClient.putItem(newUserParams, function (err, data) {
        if (err) {
          logger.info('Sign up: unable to add. Error:', JSON.stringify(err, null, 2));
          res
            .status(httpStatusCodes.INTERNAL_SERVER)
            .json({ error: `Failed to add user ${username}. Please, try again later.` });
        } else {
          // Generate and send a cookie and a jwtToken for the user with expire time
          createSession(username, req, res);
        }
      });
    }
  });
});

/**
 * Send a response to an invalid endpoint called for GET method.
 */
app.get('*', function (req, res) {
  res.status(httpStatusCodes.NOT_FOUND).json({ error: 'An invalid endpoint has been called.' });
});

/**
 * Send a response to an invalid endpoint called for POST method.
 */
app.post('*', function (req, res) {
  res.status(httpStatusCodes.NOT_FOUND).json({ error: 'An invalid endpoint has been called.' });
});

/**
 * Error handler for unexpected method which trigger and error
 */
app.use(function (err, req, res, next) {
  logger.error(`Request: ${req.url}.\nStack Trace:\n${err.stack}`);
  res.status(500).send('Something went wrong!');
});

/**
 * Create a session for a user after login or signup.
 *
 * @param {*} username username for which we want to create a session
 * @param {*} req Request coming from frontend
 * @param {*} res Rsponse going back to frontend
 */
function createSession(username, req, res) {
  const token = jsonwebtoken.sign({ user: username }, jwtSecret, { expiresIn: jwtTimeLimitSeconds });

  redisClient.set(token, username);
  redisClient.expire(token, sessionExpiryTime);

  res.cookie('token', token, { httpOnly: true }, { expire: new Date() + jwtTimeLimitSeconds * 1000 });
  res.json({ message: 'User is logged in.' });
  logger.info(`User ${username} has been successfully logged in.`);
  app.use(
    jwt({
      secret: jwtSecret,
      getToken: (req) => req.cookies.token,
      algorithms: ['HS256'],
    })
  );
}

// Start the server
const server = app.listen(8080, () => logger.info('Listening on port 8080'));

/**
 * Shutdown server and exit process if a shutdown signal was received.
 * @param {*} name of the signal
 */
function shutdown(signal) {
  logger.info(`Received ${signal} signal. Closing HTTP server...`);
  server.close(() => {
    logger.info('HTTP server closed.');
  });
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
