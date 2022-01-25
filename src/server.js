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
const dateTimeUtils = require('./utils/dateTimeUtils');

const bCryptSaltRounds = 10;
const jwtTimeLimitSeconds = 15 * 60;
const sessionExpiryTime = 15 * 60;
let jwtToken = '';

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
    console.log(err, err.stack);
  } else {
    jwtToken = data.SecretString;
  }
});

const app = express();
app.use(express.json());
app.use(cors());
// Setting up cookie and CSRF protection
app.use(cookieParser());
const csrfProtection = csrf({
  cookie: true,
});
app.use(csrfProtection);
// enable this if you run behind a proxy (e.g. nginx)
app.set('trust proxy', 1);

//Configure redis client
const redisClient = redis.createClient({
  host: 'localhost',
  port: 6379,
});
redisClient.connect();
redisClient.on('error', function (err) {
  console.log('Could not establish a connection with redis. ' + err);
});
redisClient.on('connect', function (err) {
  console.log('Connected to redis successfully');
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
    stream: fs.createWriteStream('./access.log', { flags: 'a' }),
  })
);
app.use(
  morgan(
    ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :csrfToken :jwt'
  )
);

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
  console.log('Is logged in called.');
  console.log(token);

  //If there's no session cookie, the user is not logged in.
  if (token === undefined) {
    res.json({ message: "User isn't logged in.", isLoggedIn: false });
    return;
  }

  //When a token is present, verify that it exists in Redis.
  result = await redisClient.exists(token);

  //If token is present, user is considered logged in.
  if (result === 1) {
    console.log('is logged in');
    res.json({ message: 'User is logged in.', isLoggedIn: true });
  } else {
    console.log('is not logged in');
    res.json({ message: "User isn't logged in.", isLoggedIn: false });
  }
});

/**
 * Invalidate cookie in a storage
 */
app.get('/log-out', async (req, res) => {
  console.log('Cookies: ', req.cookies.token);
  const token = req.cookies.token;
  console.log('Token: ', token);

  function deleteToken(token) {
    return new Promise((resolve, reject) => {
      redisClient.del(token, (err, reply) => {
        resolve(reply);
      });
    });
  }

  //const result = await deleteToken(token);
  console.log(`Deleting user session.`);
  a = await redisClient.del(token);
  console.log(a);
  res.json({ message: 'User has been successfully logged out.' });
});

/**
 * Log in with username and password and generate jwt token
 */
app.post('/log-in', (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.status(400).json({ error: 'Log-in error. Username  and password are requiered.' });
    return;
  }
  console.log('Logging in with user: ' + username);
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
      console.log('Unable to query. Error:', JSON.stringify(err, null, 2));
      res.status(500).json({ error: 'DB error.' });
    } else if (data.Item) {
      console.log(data);
      // Compare password with the hash in DB
      const isCorrectPswd = await bcrypt.compare(password, data.Item.password.S);
      console.log(isCorrectPswd);
      console.log(data.Item.password.S);
      // Password is correct => procceed with log in
      if (isCorrectPswd) {
        console.log(`Generating token for user ${username}`);
        // Generate and send a cookie and a jwtToken for the user with expire time

        createSession(username, req, res);
      } else {
        // Incorrect password => send an error back
        res.status(401).json({ error: 'User or password is not valid.' });
      }
    }
  });
});

/**
 * Sign-up with username, email and password and generate JWT token. After signup generate session
 * and store it in Redis.
 */
app.post('/sign-up', (req, res, next) => {
  const { username, password, email } = req.body;
  console.log('Signing up user' + username);
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
      console.log('Unable to query. Error:', JSON.stringify(err, null, 2));
      res.status(403).json({ error: 'DB error.' });
    } else if (data.Item) {
      res.status(403).json({ error: `User ${username} already exists.` });
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
        console.log(data);
        if (err) {
          res.status(500).json({ error: `Failed to add user ${username}. Please, try again later.` });
        } else {
          // Generate and send a cookie and a jwtToken for the user with expire time

          createSession(username, req, res);
        }
      });
    }
  });
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

  app.use(
    jwt({
      secret: jwtSecret,
      getToken: (req) => req.cookies.token,
      algorithms: ['HS256'],
    })
  );
}

app.listen(8080, () => console.log('Listening on port 8080'));
