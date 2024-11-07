const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: 'arnav3414', // Change this to a more secure secret in production
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/Exp4' }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day session expiry
}));

// Setup view engine
app.set('view engine', 'ejs');

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/Exp4', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User schema and model
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: { type: String, default: 'user' }
});

const User = mongoose.model('User', userSchema, 'data');

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) {
    return next(); // Continue if authenticated
  } else {
    console.log('User not authenticated, redirecting to login');
    res.redirect('/login'); // Redirect to login if not authenticated
  }
};

// Middleware for role-based authorization
const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.session.user && req.session.user.role === role) {
      return next();
    }
    res.status(403).send('Forbidden');
  };
};

// Disable caching to prevent showing old pages after logout
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// Home Route (Protected)
app.get('/', isAuthenticated, (req, res) => {
  res.render('index'); // Render index.ejs if authenticated
});

// Admin Page Route (Protected for admin users only)
app.get('/admin', isAuthenticated, authorizeRole('admin'), (req, res) => {
  res.render('admin'); // Render admin.ejs for admin users
});

// Login Page Route
app.get('/login', (req, res) => {
  res.render('form'); // Render login form
});

// Sign Up Page Route
app.get('/signup', (req, res) => {
  res.render('form'); // Render the sign-up form here
});

// Sign Up Route
app.post('/signup', async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.send('Email already registered.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, role: role || 'user' });
    await newUser.save();
    res.send('User registered successfully!');
  } catch (error) {
    res.status(500).send('Error registering user.');
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send('Invalid email or password.');
    }

    req.session.user = user; // Save user info in session
    console.log('User authenticated, redirecting to home');
    res.redirect('/'); // Redirect to the home page (index.ejs)
  } catch (error) {
    res.status(500).send('Error logging in.');
  }
});

// Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Failed to log out.');
    }
    res.clearCookie('connect.sid'); // Clear the session cookie
    console.log('Session destroyed, redirecting to login');
    res.redirect('/login'); // Redirect to login after logging out
  });
});

// Start the server
app.listen(3000, () => {
  console.log('Auth server is running on port 3000');
});
