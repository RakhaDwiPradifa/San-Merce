const express = require('express');
const router = express.Router();
const db = require('../backend/db');

// Transaction history
router.get('/:userId', (req, res) => {
    const { userId } = req.params;

    db.query('SELECT * FROM transactions WHERE user_id = ?', [userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching transactions');
        res.json(results);
    });
});

module.exports = router;