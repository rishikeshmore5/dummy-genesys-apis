const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Dummy Credentials
const DUMMY_CLIENT_ID = 'genesys-dummy-client-id-123';
const DUMMY_CLIENT_SECRET = 'genesys-dummy-secret-456';

// In-memory store for issued tokens (token -> expiry timestamp)
const activeTokens = new Map();

// Dummy allowlist of ANIs that will return TRUE
const VALID_ANIS = new Set([
  '+918208443448',
  '918208443448',
  '8208443448'
]);


app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

/**
 * 1) TOKEN API: POST /oauth/token
 * Supports:
 *  - Basic Auth header: Authorization: Basic base64(client_id:client_secret) [Genesys Cloud default]
 *  - JSON or x-www-form-urlencoded body: { client_id, client_secret }
 */
app.post('/oauth/token', (req, res) => {
  let clientId = req.body?.client_id;
  let clientSecret = req.body?.client_secret;

  // Check Basic Auth Header (Standard for Genesys Cloud Custom Auth Data Actions)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Basic ')) {
    const base64Credentials = authHeader.split(' ')[1];
    const decoded = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const [id, secret] = decoded.split(':');
    clientId = id;
    clientSecret = secret;
  }

  if (clientId !== DUMMY_CLIENT_ID || clientSecret !== DUMMY_CLIENT_SECRET) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid dummy client_id or client_secret'
    });
  }

  const accessToken = `dummy_tok_${crypto.randomBytes(16).toString('hex')}`;
  const expiresIn = 3600; // 1 hour
  activeTokens.set(accessToken, Date.now() + expiresIn * 1000);

  return res.status(200).json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn
  });
});

/**
 * 2) ANI CHECK API: POST /api/check-ani
 * Header: Authorization: Bearer <access_token>
 * Body: { "ani": "+918208443448" }
 */


app.post('/api/check-ani', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Missing or malformed Bearer token'
    });
  }

  const token = authHeader.split(' ')[1];
  const expiry = activeTokens.get(token);

  if (!expiry || Date.now() > expiry) {
    activeTokens.delete(token);
    return res.status(401).json({
      error: 'invalid_token',
      message: 'Token is invalid or expired'
    });
  }

  const { ani } = req.body;
  if (!ani) {
    return res.status(400).json({
      error: 'bad_request',
      message: 'Field "ani" is required in JSON body'
    });
  }

  // Normalize spaces/dashes just in case Genesys passes tel:+918208443448 or spaces
  const cleanedAni = String(ani).replace(/^tel:/i, '').replace(/[\s-]/g, '');
  const isMatch = VALID_ANIS.has(cleanedAni);

  return res.status(200).json({
    ani: cleanedAni,
    isValid: isMatch,
    status: isMatch ? 'TRUE' : 'FALSE'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Dummy API server running on http://localhost:${PORT}`);
});
