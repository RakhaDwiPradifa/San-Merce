const crypto = require('crypto');
require('dotenv').config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-32-byte-long-encryption-key';
const IV_LENGTH = 16; // Must be 16 for AES

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

module.exports = { decrypt };