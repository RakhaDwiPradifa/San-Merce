const express = require('express');
const router = express.Router();
const db = require('../backend/db');

const crypto = require('crypto');
const ENCRYPTION_KEY = "12345678901234567890123456789012"; // Must be 32 characters
const IV_LENGTH = 16; // For AES, this is always 16
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


// Updated to fetch user data and pre-fill checkout fields
router.get('/', (req, res) => {
    const user = req.cookies.user;
    user.name = decrypt(user.name);
    user.email = decrypt(user.email);
    user.phone = decrypt(user.phone);
    user.address = decrypt(user.address);
    user.cardNumber = decrypt(user.cardNumber);
    user.cvv = decrypt(user.cvv);

    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send('<script>alert("Unauthorized"); window.location.href="/login";</script>');
    }
    const { productId } = req.query;

    if (!productId) {
        return res.status(400).send('<script>alert("Product ID is required"); window.location.href="/products";</script>');
    }

    db.query('SELECT * FROM products WHERE id = ?', [productId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(500).send('<script>alert("Error fetching user data"); window.location.href="/dashboard";</script>');
        }

        const product = results[0];
        res.render('checkout', { user, product });
    });
});

// Checkout
router.post('/', (req, res) => {
    const { userId, productId, amount } = req.body;
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send('<script>alert("Unauthorized"); window.location.href="/login";</script>');
    }

    if (!productId) {
        return res.status(400).send('<script>alert("Product ID is required"); window.location.href="/checkout";</script>');
    }

    // Save transaction to the database
    db.query('INSERT INTO transactions (user_id, product_id) VALUES (?, ?)', 
        [userId, productId], (err) => {
            if (err) {
                console.error('Error processing checkout:', err);
                return res.status(500).send('Error processing checkout');
            }
            // After successful transaction
            res.status(201).send('Checkout successful');
        });
});

module.exports = router;