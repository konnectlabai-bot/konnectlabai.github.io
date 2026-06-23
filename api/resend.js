// api/resend.js — Resend verification code
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const SENDER = 'konnectlabai@gmail.com';
const VERIFY_EXPIRY_MINUTES = 30;
const SECRET = process.env.VERIFY_SECRET || 'kyniskis-dev-secret-change-me';

function hash(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function createToken(email, code) {
  const expiresAt = Date.now() + VERIFY_EXPIRY_MINUTES * 60 * 1000;
  const payload = `${email}|${hash(code)}|${expiresAt}`;
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return Buffer.from(JSON.stringify({ p: payload, s: sig })).toString('base64url');
}

function emailHTML(code) {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:40px 0;">
<tr><td align="center">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:440px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
    <tr><td style="padding:32px 32px 0;text-align:center;">
      <p style="margin:0;font-size:15px;font-weight:700;letter-spacing:1px;color:#0a0a0a;">
        Konnect<span style="color:#3b82f6;">LAB</span>
      </p>
    </td></tr>
    <tr><td style="padding:28px 36px 4px;text-align:center;">
      <p style="margin:0;font-size:20px;font-weight:700;color:#0a0a0a;">Your verification code</p>
      <p style="margin:10px 0 0;font-size:14px;color:#64748b;line-height:1.6;">Here's a new code for your KYNISKIS registration.</p>
    </td></tr>
    <tr><td style="padding:28px 36px;text-align:center;">
      <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
        <tr>
          <td style="padding:16px 20px;background:#0f172a;border-radius:12px;font-family:'SF Mono',Menlo,Monaco,monospace;font-size:36px;font-weight:800;letter-spacing:8px;color:#3b82f6;text-align:center;">
            ${code}
          </td>
        </tr>
      </table>
      <p style="margin:16px 0 0;font-size:12px;color:#94a3b8;">This code expires in ${VERIFY_EXPIRY_MINUTES} minutes.</p>
    </td></tr>
    <tr><td style="padding:0 36px;"><hr style="border:none;border-top:1px solid #e2e8f0;margin:0;"></td></tr>
    <tr><td style="padding:24px 36px 36px;text-align:center;">
      <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.6;">
        If you didn't create a KYNISKIS account, you can safely ignore this email.<br><br>
        <a href="https://konnectlabai.com/privacy.html" style="color:#3b82f6;text-decoration:none;">Privacy</a>
        &nbsp;·&nbsp;
        <a href="https://konnectlabai.com/terms.html" style="color:#3b82f6;text-decoration:none;">Terms</a>
      </p>
    </td></tr>
  </table>
</td></tr>
</table>
</body>
</html>`;
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
    const { email, token: oldToken } = req.body || {};
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    // Verify old token (must have a valid pending verification)
    if (oldToken) {
      try {
        const tokenData = JSON.parse(Buffer.from(oldToken, 'base64url').toString());
        const { p: payload, s: sig } = tokenData;
        const expectedSig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
        if (sig !== expectedSig) {
          return res.status(400).json({ error: 'Invalid token' });
        }
      } catch {
        return res.status(400).json({ error: 'Invalid token' });
      }
    }

    // Generate new code
    const code = Array.from(crypto.randomBytes(4))
      .map(b => b % 10).join('').slice(0, 6).padEnd(6, '0');
    const newToken = createToken(email, code);

    const appPassword = process.env.GMAIL_APP_PASSWORD || process.env.GMAIL_APP_PASS || '';
    if (!appPassword) {
      return res.status(500).json({ error: 'Email service not configured' });
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: SENDER, pass: appPassword }
    });

    await transporter.sendMail({
      from: `KonnectLAB <${SENDER}>`,
      to: email,
      subject: `${code} is your new KYNISKIS verification code`,
      text: `Your new KYNISKIS verification code: ${code}\n\nThis code expires in ${VERIFY_EXPIRY_MINUTES} minutes.\n\nhttps://konnectlabai.com`,
      html: emailHTML(code)
    });

    console.log(`✓ Verification code re-sent to ${email}`);
    return res.status(200).json({ status: 'ok', token: newToken });
  } catch (err) {
    console.error('resend error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
};
