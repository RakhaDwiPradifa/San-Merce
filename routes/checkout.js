const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const db = require('../backend/db');

const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// Checkout
router.post('/', (req, res) => {
    const { cardNumber, expiryDate, cvv, userId, productId, amount } = req.body;

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encryptedCard = cipher.update(cardNumber, 'utf8', 'hex');
    encryptedCard += cipher.final('hex');

    db.query('INSERT INTO transactions (user_id, product_id, amount, card_encrypted) VALUES (?, ?, ?, ?)', [userId, productId, amount, encryptedCard], (err) => {
        if (err) return res.status(500).send('Error processing checkout');
        res.status(201).send('Checkout successful');
    });
});

module.exports = router;