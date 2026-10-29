// REALEARNINGSNOW - Secure Backend
// File 2: api/index.js
const crypto = require('crypto');
const BOT_TOKEN = process.env.BOT_TOKEN || 'YOUR_BOT_TOKEN_HERE';

// Simple memory DB - use Vercel KV in production
let usersDB = {};
let withdrawQueue = [];

// Telegram Auth Check
function checkTelegramAuth(initData) {
  try {
    if (!initData) {
      console.log('No initData provided');
      return false;
    }
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    if (!hash) {
      console.log('No hash in initData');
      return false;
    }
    urlParams.delete('hash');
    const entries = Array.from(urlParams.entries());
    entries.sort((a, b) => {
      return a[0].localeCompare(b[0]);
    });
    const dataCheckString = entries.map(([k, v]) => {
      return `${k}=${v}`;
    }).join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData')
      .update(BOT_TOKEN)
      .digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');
    const isValid = calculatedHash === hash;
    console.log(`Auth check: ${isValid}`);
    return isValid;
  } catch (e) {
    console.log('Auth error:', e.message);
    return false;
  }
}

function isValidTonAddress(address) {
  if (!address) {
    return false;
  }
  const trimmed = address.trim();
  if (trimmed.length === 0) {
    return false;
  }
  if (!trimmed.startsWith('UQ') && !trimmed.startsWith('EQ')) {
    console.log('TON address must start with UQ or EQ');
    return false;
  }
  if (trimmed.length < 46) {
    console.log('TON address too short');
    return false;
  }
  if (trimmed.length > 50) {
    console.log('TON address too long');
    return false;
  }
  const validChars = /^[a-zA-Z0-9_\-]+$/;
  if (!validChars.test(trimmed)) {
    console.log('TON address has invalid chars');
    return false;
  }
  return true;
}

function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return input;
  }
  return input.replace(/[<>]/g, '').trim();
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  if (req.headers['x-real-ip']) {
    return req.headers['x-real-ip'];
  }
  if (req.connection && req.connection.remoteAddress) {
    return req.connection.remoteAddress;
  }
  return 'unknown';
}

function logEvent(type, data) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${type}:`, JSON.stringify(data));
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Cache-Control', 'no-cache');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch (err) {
      console.log('Failed to parse body:', err.message);
      body = {};
    }
  }

  if (!body) {
    body = {};
  }

  const query = req.query || {};
  const userId = sanitizeInput(body.userId || query.userId || '');
  const merges = body.merges || query.merges || 0;
  const usd = body.usd || query.usd || 0;
  const tonAddr = sanitizeInput(body.tonAddr || query.tonAddr || '');
  const initData = body.initData || query.initData || '';
  const action = sanitizeInput(body.action || query.action || '');
  const username = sanitizeInput(body.username || query.username || '');

  const clientIp = getClientIp(req);
  logEvent('REQUEST', { action, userId, ip: clientIp });

  if (!action) {
    return res.status(200).json({
      ok: true,
      project: 'REALEARNINGSNOW',
      status: 'Backend running',
      version: '1.0.0',
      endpoints: ['verify', 'save', 'withdraw', 'get', 'stats'],
      timestamp: Date.now(),
      ip: clientIp
    });
  }

  if (action === 'verify') {
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId', ok: false });
    }
    const isValid = checkTelegramAuth(initData);
    logEvent('VERIFY', { userId, isValid });
    return res.status(200).json({
      valid: isValid,
      userId: userId,
      username: username,
      timestamp: Date.now(),
      message: isValid ? 'User verified via Telegram' : 'Invalid Telegram data'
    });
  }

  if (action === 'save') {
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId', ok: false });
    }
    const parsedMerges = parseInt(merges);
    const parsedUsd = parseFloat(usd);
    if (isNaN(parsedMerges) || parsedMerges < 0) {
      return res.status(400).json({ error: 'Invalid merges value' });
    }
    if (isNaN(parsedUsd) || parsedUsd < 0) {
      return res.status(400).json({ error: 'Invalid usd value' });
    }
    if (parsedMerges > 1000000) {
      return res.status(400).json({ error: 'Merges too high - possible cheat' });
    }
    const existing = usersDB[userId] || {};
    usersDB[userId] = {
      userId: userId,
      merges: parsedMerges,
      usd: parsedUsd,
      tonAddr: tonAddr || existing.tonAddr || '',
      username: username || existing.username || '',
      lastSave: Date.now(),
      lastIp: clientIp,
      saveCount: (existing.saveCount || 0) + 1
    };
    logEvent('SAVE', { userId, merges: parsedMerges, usd: parsedUsd });
    return res.status(200).json({
      ok: true,
      saved: true,
      user: usersDB[userId],
      message: 'Progress saved securely'
    });
  }

  if (action === 'withdraw') {
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId', ok: false });
    }
    if (!isValidTonAddress(tonAddr)) {
      return res.status(400).json({
        error: 'Invalid TON address',
        details: 'Address must start with UQ or EQ and be 48 chars',
        received: tonAddr
      });
    }
    const amount = parseFloat(usd);
    if (isNaN(amount)) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (amount < 1) {
      return res.status(400).json({ error: 'Minimum $1 to withdraw', current: amount });
    }
    if (amount > 1000) {
      return res.status(400).json({ error: 'Max $1000 per withdraw', current: amount });
    }
    const user = usersDB[userId];
    if (!user) {
      return res.status(404).json({ error: 'User not found, save first' });
    }
    if (user.usd < amount) {
      return res.status(400).json({ error: 'Insufficient balance', balance: user.usd, requested: amount });
    }
    const withdrawId = `WD_${userId}_${Date.now()}`;
    const request = {
      id: withdrawId,
      userId: userId,
      amount: amount,
      to: tonAddr,
      username: username,
      ip: clientIp,
      timestamp: Date.now(),
      status: 'pending'
    };
    withdrawQueue.push(request);
    logEvent('WITHDRAW_REQUEST', request);
    return res.status(200).json({
      ok: true,
      status: 'pending',
      userId: userId,
      amount: amount,
      to: tonAddr,
      message: 'Withdraw request received. Payout in 24h after review.',
      txId: withdrawId,
      queuePosition: withdrawQueue.length
    });
  }

  if (action === 'get') {
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId' });
    }
    const user = usersDB[userId];
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.status(200).json({ ok: true, user: user });
  }

  if (action === 'stats') {
    return res.status(200).json({
      ok: true,
      totalUsers: Object.keys(usersDB).length,
      totalWithdraws: withdrawQueue.length,
      timestamp: Date.now()
    });
  }

  return res.status(400).json({ error: 'Unknown action', action: action });
};