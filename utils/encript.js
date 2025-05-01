const crypto = require('crypto');
require('dotenv').config();

dotenv.config();
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 characters
const IV_LENGTH = 16; // For AES, this is always 16

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


module.exports = { encrypt };