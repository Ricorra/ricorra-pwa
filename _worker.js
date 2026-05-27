const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function generateToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) {
    token += chars[array[i] % chars.length];
  }
  return token;
}

// ── Session middleware ───────────────────────────────
async function getEmailFromSession(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const sessionToken = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : null;

  if (!sessionToken) return null;

  try {
    const raw = await env.DB.get(`session:${sessionToken}`);
    if (!raw) return null;
    const record = JSON.parse(raw);
    return record.email || null;
  } catch {
    return null;
  }
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, { headers: CORS });
  }

  // ── Health check ────────────────────────────────────
  if (method === 'GET' && url.pathname === '/health') {
    return json({ status: 'ok', service: 'ricorra-api' });
  }

  // ── POST /auth/request ───────────────────────────────
  if (method === 'POST' && url.pathname === '/auth/request') {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }

    const email = (body.email || '').toLowerCase().trim();
    if (!email || !email.includes('@')) {
      return json({ error: 'Valid email required' }, 400);
    }

    const token = generateToken(32);
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

    const raw = await env.DB.get(`magiclink:${token}`);
    if (raw) return json({ error: 'Token collision, please try again' }, 500);

    await env.DB.put(
      `magiclink:${token}`,
      JSON.stringify({ email, expires }),
      { expirationTtl: 900 }
    );

    const magicLink = `https://ricorra.com/auth/verify?token=${token}`;

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: 'Ricorra <hello@ricorra.com>',
        to: email,
        subject: 'Your Ricorra sign-in link',
        html: `
          <div style="font-family: Georgia, serif; max-width: 480px; margin: 0 auto; padding: 2rem; color: #1C1C1A;">
            <h2 style="font-size: 24px; font-weight: 500; margin-bottom: 0.5rem;">Sign in to Ricorra</h2>
            <p style="color: #6B6860; margin-bottom: 2rem;">Click the link below to sign in. This link expires in 15 minutes.</p>
            <a href="${magicLink}" style="display: inline-block; background: #C49A3C; color: #FAF8F4; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-family: sans-serif; font-size: 14px;">Sign in to Ricorra</a>
            <p style="margin-top: 2rem; font-size: 12px; color: #6B6860;">If you didn't request this, you can safely ignore this email.</p>
          </div>
        `,
      }),
    });

    if (!resendRes.ok) {
      const err = await resendRes.text();
      return json({ error: 'Failed to send email', detail: err }, 500);
    }

    return json({ success: true, message: 'Magic link sent' });
  }

  // ── GET /auth/verify ─────────────────────────────────
  if (method === 'GET' && url.pathname === '/auth/verify') {
    const token = url.searchParams.get('token');
    if (!token) return json({ error: 'Token required' }, 400);

    let record;
    try {
      const raw = await env.DB.get(`magiclink:${token}`);
      if (!raw) return json({ error: 'Invalid or expired token' }, 401);
      record = JSON.parse(raw);
    } catch {
      return json({ error: 'Invalid token data' }, 500);
    }

    if (Date.now() > record.expires) {
      await env.DB.delete(`magiclink:${token}`);
      return json({ error: 'Token expired' }, 401);
    }

    await env.DB.delete(`magiclink:${token}`);

    const sessionToken = generateToken(48);
    await env.DB.put(
      `session:${sessionToken}`,
      JSON.stringify({ email: record.email, created: Date.now() }),
      { expirationTtl: 60 * 60 * 24 * 30 }
    );

    return json({ success: true, sessionToken, email: record.email });
  }

  // ── POST /auth/logout ────────────────────────────────
  if (method === 'POST' && url.pathname === '/auth/logout') {
    const authHeader = request.headers.get('Authorization') || '';
    const sessionToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : null;

    if (sessionToken) {
      await env.DB.delete(`session:${sessionToken}`);
    }

    return json({ success: true, message: 'Logged out' });
  }

  // ── GET /merchant/dashboard ──────────────────────────
  if (method === 'GET' && url.pathname === '/merchant/dashboard') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    // Load wallet address if set
    let walletAddress = null;
    try {
      const raw = await env.DB.get(`merchant:${email}:wallet`);
      if (raw) walletAddress = JSON.parse(raw).address;
    } catch {
      walletAddress = null;
    }

    return json({
      success: true,
      email,
      walletAddress,
    });
  }

  // ── POST /merchant/wallet ────────────────────────────
  if (method === 'POST' && url.pathname === '/merchant/wallet') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }

    const address = (body.address || '').trim();
    if (!address) {
      return json({ error: 'Wallet address required' }, 400);
    }

    // Basic Bitcoin address sanity check (starts with 1, 3, or bc1)
    if (!/^(1|3|bc1)[a-zA-Z0-9]{8,}$/.test(address)) {
      return json({ error: 'Invalid Bitcoin wallet address' }, 400);
    }

    await env.DB.put(
      `merchant:${email}:wallet`,
      JSON.stringify({ address, updatedAt: Date.now() })
    );

    return json({ success: true, address });
  }

  // ── 404 ──────────────────────────────────────────────
  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      return json({ error: 'Internal server error', detail: err.message }, 500);
    }
  },
};
