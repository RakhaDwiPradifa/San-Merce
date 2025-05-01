const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const router = express.Router();
const db = require('../backend/db');

const ENCRYPTION_KEY = "12345678901234567890123456789012"; // Must be 32 characters
const IV_LENGTH = 16; // For AES, this is always 16

// import {encrypt} from '../utils/encript.js';
// import {decrypt} from '../utils/decript.js';

// Improved encryption and decryption functions
function encrypt(text) {
    if (!text || typeof text !== 'string') {
        console.error('Invalid data for encryption:', text);
        return null;
    }
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}


function decrypt(encryptedText) {
    if (!encryptedText || typeof encryptedText !== 'string') {
        console.error('Invalid data for decryption:', encryptedText);
        return null;
    }

    try {
        const textParts = encryptedText.split(':');
        const iv = Buffer.from(textParts[0], 'hex');
        const encryptedData = textParts[1];

        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (err) {
        console.error('Decryption error:', err.message);
        return null;
    }
}

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).send('<script>alert("Access denied. Please login first."); window.location.href="/login";</script>');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send('<script>alert("Invalid or expired token. Please login again."); window.location.href="/login";</script>');
        }
        req.user = user;
        next();
    });
};

// Register
router.post('/register', async (req, res) => {
    const { name, email, password, address, phone } = req.body;

    console.log('Register request received:', req.body);

    if (!name || !email || !password || !address || !phone) {
        return res.status(400).send('<script>alert("All fields are required"); window.location.href="/register";</script>');
    }

    try {
        console.log('Encrypting name:', name);
        console.log('Encrypting address:', address);
        console.log('Encrypting phone:', phone);

        const hashedPassword = await bcrypt.hash(password, 10);
        const encryptedName = encrypt(name);
        const encryptedAddress = encrypt(address);
        const encryptedPhone = encrypt(phone);

        if (!encryptedName || !encryptedAddress || !encryptedPhone) {
            console.error('Encryption failed for one or more fields:', {
                name: encryptedName,
                address: encryptedAddress,
                phone: encryptedPhone
            });
            return res.status(500).send('<script>alert("Error encrypting data"); window.location.href="/register";</script>');
        }

        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) {
                console.error('Error during user registration:', err);
                return res.status(500).send('<script>alert("Error checking user"); window.location.href="/register";</script>');
            }
            if (results.length > 0) {
                return res.status(400).send('<script>alert("Email already registered"); window.location.href="/register";</script>');
            }

            // If email is unique, proceed with registration
            db.query('INSERT INTO users (name, email, password, address, phone) VALUES (?, ?, ?, ?, ?)', [encryptedName, email, hashedPassword, encryptedAddress, encryptedPhone], (err) => {
                if (err) throw err;
                res.status(201).send('<script>alert("User registered successfully"); window.location.href="/login";</script>');
            });
        });
    } catch (err) {
        res.status(500).send('<script>alert("Error registering user"); window.location.href="/register";</script>');
    }
});

// Login
router.post('/login', (req, res) => {
    const { email, password } = req.body;
    

    db.query('SELECT id, name, email, password, address, phone FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Error during user login:', err);
            return res.status(500).send('<script>alert("Internal server error"); window.location.href="/login";</script>');
        }

        if (results.length === 0) {
            console.log('No user found with email:', email);
            return res.status(401).send('<script>alert("Invalid credentials"); window.location.href="/login";</script>');
        }

        const user = results[0];
        // console.log('User found:', results); // Log user data before decryption
        // user.name = decrypt(user.name);
        // user.address = decrypt(user.address);
        // user.phone = decrypt(user.phone); 
        console.log('Decrypted user data:', decrypt(user.name)); // Log decrypted user data
        

        // console.log('User found:', user); // Log user data after decryption

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).send('<script>alert("Internal server error"); window.location.href="/login";</script>');
            }

            if (!isMatch) {
                console.log('Password mismatch for user:', email);
                return res.status(401).send('<script>alert("Invalid credentials"); window.location.href="/login";</script>');
            }

            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

            // redirect to dashboard with token
            res.cookie('token', token);
            res.redirect('/');
        });
    });
});

router.get('/logout', (req, res) => {
    res.clearCookie('token'); // Clear the token cookie
    res.redirect('/login'); // Redirect to login page
});

// Protect checkout and transactions routes
router.get('/checkout', authenticateToken, (req, res) => {
    res.send('<h1>Checkout Page</h1>');
});

router.get('/transactions', authenticateToken, (req, res) => {
    res.send('<h1>Transactions Page</h1>');
});

// Use token for transactions
router.post('/transactions', authenticateToken, (req, res) => {
    const { productId, quantity } = req.body;
    const userId = req.user.id;

    db.query('INSERT INTO transactions (user_id, product_id, quantity) VALUES (?, ?, ?)', [userId, productId, quantity], (err) => {
        if (err) {
            return res.status(500).send('<script>alert("Error processing transaction"); window.location.href="/checkout";</script>');
        }
        res.status(201).send('<script>alert("Transaction successful"); window.location.href="/transactions";</script>');
    });
});

// Decrypt user data when retrieving from the database
router.get('/profile', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send('<script>alert("User not found"); window.location.href="/dashboard";</script>');
        }

        const user = results[0];
        user.name = decrypt(user.name);
        user.address = decrypt(user.address);
        user.phone = decrypt(user.phone);

        res.json(user);
    });
});

module.exports = { router, authenticateToken };