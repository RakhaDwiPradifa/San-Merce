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
app.set('view engine', 'ejs');
const PORT = process.env.PORT || 3000;

// AES-256 encryption and decryption utilities
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 characters
const IV_LENGTH = 16;

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

// Serve static files from views folder
app.use(express.static(path.join(__dirname, 'views')));

// Routes
app.use('/auth', authRoutes);
app.use('/checkout', checkoutRoutes);
app.use('/transactions', transactionsRoutes);
app.use('/products', products);

// Middleware: protect route if not logged in
function requireLogin(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login');
  }
  next();
}

// Route to serve HTML views
app.get('/login', (req, res) => {
  const showAlert = req.query.showAlert === 'true';
  res.render('login', { title: 'Login', token: null, showAlert });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Register', token: null });
});

// Checkout route (protected)
app.get('/checkout', requireLogin, (req, res) => {
  const token = req.cookies.token;
  const productId = req.query.productId;

  if (!productId) {
    return res.status(400).send('Product ID is required');
  }

  db.query('SELECT * FROM products WHERE id = ?', [productId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 0) {
      return res.status(404).send('Product not found');
    }

    res.render('checkout', {
      title: 'Checkout',
      token,
      product: results[0]
    });
  });
});

// Example encrypted data handler
app.post('/process-payment', (req, res) => {
  if (req.body && req.body.sensitiveData) {
    const decryptedData = decrypt(req.body.sensitiveData);
    res.send(`Processed data: ${decryptedData}`);
  } else {
    res.status(400).send('No sensitive data provided');
  }
});

// Root route
app.get('/', (req, res) => {
  const token = req.cookies.token || null;
  const showAlert = req.query.showAlert === 'true';
  db.query('SELECT * FROM products', (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('dashboard', {
      title: 'Dashboard',
      products: results || [],
      token,
      showAlert,
    });
  });
}); 

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
