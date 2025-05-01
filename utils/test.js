const crypto = require('crypto');
const ENCRYPTION_KEY = "12345678901234567890123456789012"; // Must be 32 characters
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

let testEncrypt = encrypt("Rakha Dwi Pradifa");
let testDecrypt = decrypt("ab7445547dbdc8ba56a2b92a8b67ef2d:a0264e60e7cf057eb");
console.log('Encrypted:', testEncrypt);
console.log('Decrypted:', testDecrypt);
