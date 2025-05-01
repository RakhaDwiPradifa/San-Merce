const express = require('express');
const router = express.Router();
const db = require('../backend/db');
const crypto = require('crypto');
const { authenticateToken } = require('./auth');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 characters
const IV_LENGTH = 16; // For AES, this is always 16

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

function decrypt(text) {
    try {
        if (!text || typeof text !== 'string') {
            console.error('Invalid data for decryption:', text);
            return null;
        }
        const textParts = text.split(':');
        if (textParts.length !== 2) {
            console.error('Invalid encrypted data format:', text);
            return null;
        }
        const iv = Buffer.from(textParts[0], 'hex');
        const encryptedText = Buffer.from(textParts[1], 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error.message);
        return null;
    }
}

// Middleware to encrypt sensitive data before saving to the database
router.post('/transactions', authenticateToken, (req, res) => {
    const { productId, quantity } = req.body;
    const userId = req.user.id;

    const encryptedProductId = encrypt(productId.toString());
    const encryptedQuantity = encrypt(quantity.toString());

    db.query('INSERT INTO transactions (user_id, product_id, quantity) VALUES (?, ?, ?)', [userId, encryptedProductId, encryptedQuantity], (err) => {
        if (err) {
            return res.status(500).send('<script>alert("Error processing transaction"); window.location.href="/checkout";</script>');
        }
        res.status(201).send('<script>alert("Transaction successful"); window.location.href="/transactions";</script>');
    });
});

// Middleware to decrypt sensitive data when retrieving from the database
router.get('/transactions', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT * FROM transactions WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            return res.status(500).send('<script>alert("Error fetching transactions"); window.location.href="/dashboard";</script>');
        }

        const decryptedResults = results.map(transaction => ({
            ...transaction,
            product_id: decrypt(transaction.product_id),
            quantity: decrypt(transaction.quantity)
        }));

        res.json(decryptedResults);
    });
});

// Transaction history
router.get('/:userId', (req, res) => {
    const { userId } = req.params;

    db.query('SELECT * FROM transactions WHERE user_id = ?', [userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching transactions');
        res.json(results);
    });
});

module.exports = router;