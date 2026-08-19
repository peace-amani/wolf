
// api/repo.js
const axios = require('axios');
const AdmZip = require('adm-zip');
const crypto = require('crypto');

module.exports = async (req, res) => {
  // === Config ===
  const ACCESS_KEY = process.env.ACCESS_KEY || 'Silent906';
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
  const REPO_OWNER = process.env.REPO_OWNER || 'peace-amani';
  const REPO_NAME = process.env.REPO_NAME || 'v7';
  const BRANCH = process.env.REPO_BRANCH || 'main';
  const ALLOWED_IPS = process.env.ALLOWED_IPS ? process.env.ALLOWED_IPS.split(',') : [];

  // === Only allow GET ===
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  // === Validate env vars are set ===
  if (!ACCESS_KEY || !GITHUB_TOKEN) {
    console.error('Missing required environment variables');
    res.status(500).json({ error: 'Server misconfiguration' });
    return;
  }

  // === IP allowlist (optional but recommended) ===
  if (ALLOWED_IPS.length > 0) {
    const clientIP =
      req.headers['x-forwarded-for']?.split(',')[0].trim() ||
      req.socket?.remoteAddress;
    if (!ALLOWED_IPS.includes(clientIP)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
  }

  // === Constant-time key comparison (prevents timing attacks) ===
  const providedKey = req.headers['x-access-key'];
  if (!providedKey) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  const keyA = Buffer.from(providedKey.padEnd(64));
  const keyB = Buffer.from(ACCESS_KEY.padEnd(64));
  const keysMatch =
    keyA.length === keyB.length &&
    crypto.timingSafeEqual(keyA, keyB);

  if (!keysMatch) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  // === Sanitize branch name (prevent path injection) ===
  if (!/^[a-zA-Z0-9._/-]{1,100}$/.test(BRANCH)) {
    res.status(400).json({ error: 'Invalid branch name' });
    return;
  }

  try {
    const archiveUrl = `https://api.github.com/repos/${encodeURIComponent(REPO_OWNER)}/${encodeURIComponent(REPO_NAME)}/zipball/${BRANCH}`;

    const response = await axios.get(archiveUrl, {
      responseType: 'arraybuffer',
      headers: {
        Authorization: `token ${GITHUB_TOKEN}`,
        'User-Agent': 'Vercel-Relay/1.0',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      },
      maxContentLength: 50 * 1024 * 1024, // 50MB cap
      timeout: 30000
    });

    const zip = new AdmZip(Buffer.from(response.data));
    zip.addFile('relay_marker.txt', Buffer.from('Synced via Vercel relay'));
    const buffer = zip.toBuffer();

    // === Security headers ===
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${REPO_NAME}.zip"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Length', buffer.length);
    res.status(200).send(buffer);

  } catch (err) {
    // Don't leak internal error details
    console.error('Relay error:', err.message);
    if (err.response?.status === 404) {
      res.status(404).json({ error: 'Repository not found' });
    } else if (err.response?.status === 401) {
      res.status(500).json({ error: 'GitHub auth failed' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
};
