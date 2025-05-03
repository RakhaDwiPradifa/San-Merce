const express = require('express');
const router = express.Router();
const db = require('../backend/db');
const crypto = require('crypto');
const { authenticateToken } = require('./auth');
const { join } = require('path');

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

// Middleware to save transactions without encryption for product_id and quantity
// Added validation to ensure productId is provided
router.post('/', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send('<script>alert("Unauthorized"); window.location.href="/login";</script>');
    }
    const { productId, userId } = req.body;

    let currentDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

    if (!productId || !userId) {
        return res.status(400).send('<script>alert("All fields are required"); window.location.href="/checkout";</script>');
    }

    db.query('INSERT INTO transactions (user_id, product_id, transaction_date) VALUES (?, ?, ?)', [userId, productId, currentDate], (err) => {
        if (err) {
            return res.status(500).send('<script>alert("Error processing transaction"); window.location.href="/checkout";</script>');
        }
        res.status(201).send('<script>alert("Transaction successful"); window.location.href="/transactions";</script>');
    });
});

// Middleware to retrieve transactions without decryption
router.get('/', (req, res) => {
    const userId = req.cookies.user.id;
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send('<script>alert("Unauthorized"); window.location.href="/login";</script>');
    }
    db.query(`
        SELECT 
            transactions.id,
            transactions.user_id,
            transactions.product_id,
            transactions.transaction_date,
            users.name AS user_name,
            products.name AS product_name,
            products.price AS product_price
        FROM transactions
        JOIN users ON users.id = transactions.user_id
        JOIN products ON products.id = transactions.product_id
        WHERE transactions.user_id = ?
    `, [userId], (err, results) => {
        if (err) {
            return res.status(500).send('<script>alert("Error fetching transactions"); window.location.href="/dashboard";</script>');
        }
        const response = {
            title: 'Transaction History',
            transactions: results.map(transaction => ({
                ...transaction,
                transaction_date: new Date(transaction.transaction_date).toLocaleString(),
                product_price: parseFloat(transaction.product_price).toFixed(2),
                userId: userId,
                userName: decrypt(req.cookies.user.name)
            })),
        };
        let transactions = response.transactions;
        res.render('transactions', {transactions});
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