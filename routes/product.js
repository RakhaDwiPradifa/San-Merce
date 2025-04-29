const express = require('express');
const router = express.Router();
const db = require('../backend/db');
const path = require('path');

router.get('/data', (req, res) => {
    db.query('SELECT * FROM products', (err, results) => {
        res.json(results);    
    })

})

router.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'dashboard.html'));
});


module.exports = router;