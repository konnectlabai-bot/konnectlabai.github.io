// api/verify.js — Verify code against signed token
const crypto = require('crypto');

const VERIFY_EXPIRY_MINUTES = 30;
const SECRET = process.env.VERIFY_SECRET || 'kyniskis-dev-secret-change-me';

function hash(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, code, token } = req.body || {};

    if (!email || !code || !token) {
      return res.status(400).json({ error: 'Email, code, and token required' });
    }

    // Decode token
    let tokenData;
    try {
      tokenData = JSON.parse(Buffer.from(token, 'base64url').toString());
    } catch {
      return res.status(400).json({ error: 'Invalid token' });
    }

    const { p: payload, s: sig } = tokenData;
    if (!payload || !sig) {
      return res.status(400).json({ error: 'Invalid token format' });
    }

    // Verify signature
    const expectedSig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    if (sig !== expectedSig) {
      return res.status(400).json({ error: 'Token verification failed' });
    }

    // Parse payload
    const parts = payload.split('|');
    if (parts.length !== 3) {
      return res.status(400).json({ error: 'Invalid payload' });
    }

    const [tokenEmail, tokenCodeHash, expiresAt] = parts;

    // Check email match
    if (tokenEmail.toLowerCase() !== email.toLowerCase()) {
      return res.status(400).json({ error: 'Email mismatch' });
    }

    // Check expiry
    if (Date.now() > parseInt(expiresAt)) {
      return res.status(410).json({ error: 'Verification code expired. Please register again.' });
    }

    // Check code
    if (hash(code) !== tokenCodeHash) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    console.log(`✓ Email verified: ${email}`);
    return res.status(200).json({ status: 'ok', message: 'Email verified successfully. Welcome!' });
  } catch (err) {
    console.error('verify error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
};
