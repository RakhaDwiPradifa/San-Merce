const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();
const db = require('../backend/db');

// Register
router.post('/register', async (req, res) => {
    const {name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword)
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).send('Error checking user');
        if (results.length > 0) {
            return res.status(400).send('<script>alert("Email already registered"); window.location.href="/register";</script>');
        }

        // If email is unique, proceed with registration
        try {
            db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], (err) => {
                if (err) throw err;
                res.status(201).send('<script>alert("User registered successfully"); window.location.href="/login";</script>');
            });
        } catch (err) {
            res.status(500).send('<script>alert("Error registering user"); window.location.href="/register";</script>');
        }
    });
});

// Login
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).send('<script>alert("Invalid credentials"); window.location.href="/login";</script>');
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).send('<script>alert("Invalid credentials"); window.location.href="/login";</script>');
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.send(`
            <script>
                localStorage.setItem('authToken', '${token}');
                alert('Login successful');
                window.location.href = '/dashboard';
            </script>
        `);
    });
});

module.exports = router;