const express = require('express');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const { router: authRoutes } = require('./routes/auth');
const checkoutRoutes = require('./routes/checkout');
const transactionsRoutes = require('./routes/transactions');
const products = require('./routes/product');
const cookieParser = require('cookie-parser');
const db = require('./backend/db');
// Load environment variables
dotenv.config();

const app = express();
app.use(cookieParser());
app.set('view engine', 'ejs')
const PORT = process.env.PORT || 3000;

// AES-256 encryption and decryption utilities
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 characters
const IV_LENGTH = 16; // For AES, this is always 16

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware to encrypt sensitive data before saving
app.use((req, res, next) => {
  if (req.body && req.body.sensitiveData) {
    req.body.sensitiveData = encrypt(req.body.sensitiveData);
  }
  next();
});

// Serve static files from the views folder
app.use(express.static(path.join(__dirname, 'views')));

// Routes
app.use('/auth', authRoutes);
app.use('/checkout', checkoutRoutes);
app.use('/transactions', transactionsRoutes);
app.use('/products', products);

// Route to serve specific HTML files
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', token: null });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Register', token: null });
});

app.get('/checkout', (req, res) => {
  res.render('checkout', { title: 'Checkout', token: null });
});

app.get('/transactions', (req, res) => {
  res.render('transactions', { title: 'Transactions', token: null });
});

// Example route to demonstrate decryption
app.post('/process-payment', (req, res) => {
  if (req.body && req.body.sensitiveData) {
    const decryptedData = decrypt(req.body.sensitiveData);
    // Process the decrypted data (e.g., payment processing)
    res.send(`Processed data: ${decryptedData}`);
  } else {
    res.status(400).send('No sensitive data provided');
  }
});

// Root endpoint
app.get('/', (req, res) => {
   // Get token from cookies
  const token = req.cookies.token || null;
  console.log('Token:', token);
  

  db.query('SELECT * FROM products', (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('dashboard', {
      title: 'Dashboard',
      products: results || [], // Make sure products is always defined
      token
    });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});