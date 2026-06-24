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

// ── Generate + store a portal token for a subscriber ──
async function getPortalToken(subscriberEmail, merchantEmail, planId, env) {
  const token   = generateToken(32);
  const expires = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
  await env.DB.put(
    `portal:${token}`,
    JSON.stringify({ subscriberEmail, merchantEmail, planId, expires }),
    { expirationTtl: 60 * 60 * 24 * 30 }
  );
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

// ═══════════════════════════════════════════════════════
// QR CODE PNG GENERATOR
// Minimal pure-JS implementation for Cloudflare Workers
// Generates a 21x21 (Version 1) QR for short Bitcoin URIs
// For longer URIs uses Version 3 (29x29)
// ═══════════════════════════════════════════════════════

async function generateQRPng(text) {
  // Use Google Charts API as a reliable QR generator
  // Returns a PNG that email clients can render
  const encodedData = encodeURIComponent(text);
  const size = 200;
  const url = `https://chart.googleapis.com/chart?cht=qr&chs=${size}x${size}&chl=${encodedData}&choe=UTF-8&chld=M|2`;

  const res = await fetch(url);
  if (!res.ok) throw new Error('QR generation failed');
  return await res.arrayBuffer();
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

  // ── POST /account/request — subscriber magic link ────
  if (method === 'POST' && url.pathname === '/account/request') {
    let body;
    try { body = await request.json(); } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }
    const email = (body.email || '').toLowerCase().trim();
    if (!email || !email.includes('@')) {
      return json({ error: 'Valid email required' }, 400);
    }

    const token   = generateToken(32);
    const expires = Date.now() + 15 * 60 * 1000;

    await env.DB.put(
      `sub-magiclink:${token}`,
      JSON.stringify({ email, expires }),
      { expirationTtl: 900 }
    );

    const magicLink = `https://ricorra.io/account/verify?token=${token}`;

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from:    'Ricorra <hello@ricorra.com>',
        to:      email,
        subject: 'Sign in to your Ricorra subscriber account',
        html: `
          <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
            <div style="text-align:center;margin-bottom:1.5rem;">
              <div style="display:inline-block;width:48px;height:48px;background:#C49A3C;border-radius:50%;
                line-height:48px;text-align:center;font-size:22px;color:#FAF8F4;">₿</div>
            </div>
            <h2 style="font-size:22px;font-weight:500;margin-bottom:0.5rem;text-align:center;">
              Sign in to your account
            </h2>
            <p style="color:#6B6860;text-align:center;margin-bottom:2rem;font-size:14px;">
              View and manage all your Ricorra subscriptions in one place.
            </p>
            <div style="text-align:center;margin-bottom:2rem;">
              <a href="${magicLink}"
                style="display:inline-block;background:#C49A3C;color:#FAF8F4;text-decoration:none;
                padding:13px 32px;border-radius:50px;font-family:sans-serif;font-size:14px;font-weight:600;">
                Sign in →
              </a>
            </div>
            <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;">
              This link expires in 15 minutes. If you didn't request this, you can safely ignore it.<br>
              <a href="https://ricorra.com" style="color:#C49A3C;">ricorra.com</a>
            </p>
          </div>`,
      }),
    });

    if (!resendRes.ok) {
      const err = await resendRes.text();
      return json({ error: 'Failed to send email', detail: err }, 500);
    }

    return json({ success: true });
  }

  // ── GET /account/verify — subscriber magic link verify ─
  if (method === 'GET' && url.pathname === '/account/verify') {
    const token = url.searchParams.get('token');
    if (!token) return Response.redirect('https://ricorra.io/account?error=missing_token', 302);

    let record;
    try {
      const raw = await env.DB.get(`sub-magiclink:${token}`);
      if (!raw) return Response.redirect('https://ricorra.io/account?error=invalid_token', 302);
      record = JSON.parse(raw);
    } catch {
      return Response.redirect('https://ricorra.io/account?error=invalid_token', 302);
    }

    if (Date.now() > record.expires) {
      await env.DB.delete(`sub-magiclink:${token}`);
      return Response.redirect('https://ricorra.io/account?error=expired_token', 302);
    }

    await env.DB.delete(`sub-magiclink:${token}`);

    const sessionToken = generateToken(48);
    await env.DB.put(
      `sub-session:${sessionToken}`,
      JSON.stringify({ email: record.email, created: Date.now() }),
      { expirationTtl: 60 * 60 * 24 * 30 }
    );

    return Response.redirect(`https://ricorra.io/account#session=${sessionToken}`, 302);
  }

  // ── GET /account/subscriptions — all subs for subscriber
  if (method === 'GET' && url.pathname === '/account/subscriptions') {
    const authHeader = request.headers.get('Authorization') || '';
    const sessionToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
    if (!sessionToken) return json({ error: 'Unauthorized' }, 401);

    let subscriberEmail;
    try {
      const raw = await env.DB.get(`sub-session:${sessionToken}`);
      if (!raw) return json({ error: 'Unauthorized' }, 401);
      subscriberEmail = JSON.parse(raw).email;
    } catch { return json({ error: 'Unauthorized' }, 401); }

    // Look up subscriber index
    let index = [];
    try {
      const raw = await env.DB.get(`subscriber-index:${subscriberEmail}`);
      if (raw) index = JSON.parse(raw);
    } catch {}

    if (index.length === 0) return json({ subscriptions: [] });

    // Load each subscription's details
    const subscriptions = [];
    for (const entry of index) {
      try {
        const syncRaw = await env.DB.get(`merchant:${entry.merchantEmail}:sync`);
        if (!syncRaw) continue;
        const sync = JSON.parse(syncRaw);

        const sub  = (sync.subscribers || []).find(s => s.email === subscriberEmail && s.planId === entry.planId);
        const plan = (sync.plans       || []).find(p => p.id === entry.planId);
        if (!sub || !plan) continue;

        let merchantName = '';
        try {
          const p = await env.DB.get(`merchant:${entry.merchantEmail}:profile`);
          if (p) merchantName = JSON.parse(p).displayName || '';
        } catch {}

        // Get portal token
        const portalToken = await getPortalToken(subscriberEmail, entry.merchantEmail, entry.planId, env);

        const subPayments = (sync.payments || [])
          .filter(p => p.subscriberId === sub.id)
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
          .slice(0, 3);

        subscriptions.push({
          merchantName,
          merchantEmail:  entry.merchantEmail,
          planName:       plan.name,
          planDesc:       plan.desc       || '',
          priceUSD:       plan.priceUSD,
          interval:       plan.interval,
          status:         sub.status,
          nextRenewal:    sub.nextRenewal || null,
          pauseUntil:     sub.pauseUntil  || null,
          paymentLink:    `https://ricorra.io/pay?t=${plan.shareToken}`,
          portalLink:     `https://ricorra.io/portal?t=${portalToken}`,
          recentPayments: subPayments,
        });
      } catch { continue; }
    }

    return json({ email: subscriberEmail, subscriptions });
  }

  // ── GET /account — serve account.html ────────────────
  if (method === 'GET' && url.pathname === '/account') {
    return env.ASSETS.fetch(new Request(new URL('/account.html', request.url), request));
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

    const magicLink = `https://ricorra.io/auth/verify?token=${token}`;

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

    if (!token) {
      return Response.redirect('https://ricorra.io/?error=missing_token', 302);
    }

    let record;
    try {
      const raw = await env.DB.get(`magiclink:${token}`);
      if (!raw) return Response.redirect('https://ricorra.io/?error=invalid_token', 302);
      record = JSON.parse(raw);
    } catch {
      return Response.redirect('https://ricorra.io/?error=invalid_token', 302);
    }

    if (Date.now() > record.expires) {
      await env.DB.delete(`magiclink:${token}`);
      return Response.redirect('https://ricorra.io/?error=expired_token', 302);
    }

    await env.DB.delete(`magiclink:${token}`);

    const sessionToken = generateToken(48);
    await env.DB.put(
      `session:${sessionToken}`,
      JSON.stringify({ email: record.email, created: Date.now() }),
      { expirationTtl: 60 * 60 * 24 * 30 }
    );

    // Redirect to root with session token in hash — index.html reads it client-side
    return Response.redirect(
      `https://ricorra.io/#session=${sessionToken}`,
      302
    );
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

  // ── GET /merchant/settings ───────────────────────────
  // Returns full merchant settings for restoration after localStorage clear
  if (method === 'GET' && url.pathname === '/merchant/settings') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let profile = {};
    let wallet  = {};
    let webhook = {};

    try { const r = await env.DB.get(`merchant:${email}:profile`); if (r) profile = JSON.parse(r); } catch {}
    try { const r = await env.DB.get(`merchant:${email}:wallet`);  if (r) wallet  = JSON.parse(r); } catch {}
    try { const r = await env.DB.get(`merchant:${email}:webhook`); if (r) webhook = JSON.parse(r); } catch {}

    return json({
      displayName:    profile.displayName    || '',
      lightningAddr:  profile.lightningAddress || '',
      digestEnabled:  profile.digestEnabled  || false,
      digestEmail:    profile.digestEmail    || '',
      username:       profile.username       || '',
      bio:            profile.bio            || '',
      website:        profile.website        || '',
      twitter:        profile.twitter        || '',
      instagram:      profile.instagram      || '',
      nostr:          profile.nostr          || '',
      btcWallet:      wallet.address         || '',
      webhookUrl:     webhook.webhookUrl     || '',
      webhookSecret:  webhook.webhookSecret  || '',
    });
  }

  // ── GET /merchant/dashboard ──────────────────────────
  if (method === 'GET' && url.pathname === '/merchant/dashboard') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let walletAddress = null;
    try {
      const raw = await env.DB.get(`merchant:${email}:wallet`);
      if (raw) walletAddress = JSON.parse(raw).address;
    } catch {
      walletAddress = null;
    }

    let displayName = null;
    try {
      const raw = await env.DB.get(`merchant:${email}:profile`);
      if (raw) displayName = JSON.parse(raw).displayName;
    } catch {
      displayName = null;
    }

    return json({
      success: true,
      email,
      walletAddress,
      displayName,
    });
  }

  // ── POST /merchant/profile ───────────────────────────
  if (method === 'POST' && url.pathname === '/merchant/profile') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }

    const displayName = (body.displayName || '').trim();
    if (!displayName) {
      return json({ error: 'Display name required' }, 400);
    }
    if (displayName.length > 50) {
      return json({ error: 'Display name must be 50 characters or fewer' }, 400);
    }

    await env.DB.put(
      `merchant:${email}:profile`,
      JSON.stringify({
        displayName,
        lightningAddress: (body.lightningAddress || '').trim() || null,
        digestEnabled:    body.digestEnabled || false,
        digestEmail:      (body.digestEmail   || '').trim() || null,
        updatedAt:        Date.now(),
      })
    );

    return json({ success: true, displayName });
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

    if (!/^(1|3|bc1)[a-zA-Z0-9]{8,}$/.test(address)) {
      return json({ error: 'Invalid Bitcoin wallet address' }, 400);
    }

    await env.DB.put(
      `merchant:${email}:wallet`,
      JSON.stringify({ address, updatedAt: Date.now() })
    );

    return json({ success: true, address });
  }

  // ── GET /merchant/sync ───────────────────────────────
  if (method === 'GET' && url.pathname === '/merchant/sync') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    try {
      const raw = await env.DB.get(`merchant:${email}:sync`);
      if (!raw) return json({ plans: [], subscribers: [], payments: [] });
      return json(JSON.parse(raw));
    } catch {
      return json({ plans: [], subscribers: [], payments: [] });
    }
  }

  // ── POST /merchant/sync ──────────────────────────────
  if (method === 'POST' && url.pathname === '/merchant/sync') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }

    await env.DB.put(
      `merchant:${email}:sync`,
      JSON.stringify({
        plans:       body.plans       || [],
        subscribers: body.subscribers || [],
        payments:    body.payments    || [],
        pushedAt:    body.pushedAt    || new Date().toISOString(),
      })
    );

    return json({ success: true });
  }

  // ── GET /merchant/webhook ────────────────────────────
  if (method === 'GET' && url.pathname === '/merchant/webhook') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);
    try {
      const raw = await env.DB.get(`merchant:${email}:webhook`);
      if (!raw) return json({ webhookUrl: '', webhookSecret: '' });
      return json(JSON.parse(raw));
    } catch {
      return json({ webhookUrl: '', webhookSecret: '' });
    }
  }

  // ── POST /merchant/webhook ───────────────────────────
  if (method === 'POST' && url.pathname === '/merchant/webhook') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let body;
    try { body = await request.json(); } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }

    const webhookUrl    = (body.webhookUrl    || '').trim();
    const webhookSecret = (body.webhookSecret || '').trim();

    if (webhookUrl && !webhookUrl.startsWith('https://')) {
      return json({ error: 'Webhook URL must use HTTPS' }, 400);
    }

    await env.DB.put(
      `merchant:${email}:webhook`,
      JSON.stringify({ webhookUrl, webhookSecret, updatedAt: Date.now() })
    );

    return json({ success: true });
  }

  // ── POST /merchant/plans ─────────────────────────────
  if (method === 'POST' && url.pathname === '/merchant/plans') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let body;
    try { body = await request.json(); } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }

    const { id, name, priceUSD, interval, desc, status, shareToken,
            trialDays, trialUpfront, trialUpfrontAmount } = body;
    if (!name || !priceUSD || !shareToken) {
      return json({ error: 'name, priceUSD, and shareToken are required' }, 400);
    }

    await env.DB.put(
      `plan:${shareToken}`,
      JSON.stringify({
        id, name, priceUSD, interval, desc, status,
        trialDays:          trialDays          || 0,
        trialUpfront:       trialUpfront       || false,
        trialUpfrontAmount: trialUpfrontAmount || 0,
        merchantEmail: email,
        updatedAt: Date.now(),
      })
    );

    return json({ success: true });
  }

// ── Deterministic micro-offset for subscriber amounts ──
// Same subscriber + same billing month always gets same offset
// Max ±$0.05, never zero, never negative price
async function getUniqueAmount(basePrice, shareToken, subscriberEmail) {
  if (!subscriberEmail) return basePrice;
  const now     = new Date();
  const period  = `${now.getFullYear()}-${now.getMonth()}`;
  const input   = `${shareToken}:${subscriberEmail}:${period}`;
  const encoded = new TextEncoder().encode(input);
  const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
  const hashArr = new Uint8Array(hashBuf);
  // Use first two bytes to get offset between -5 and +5 cents
  const raw     = ((hashArr[0] << 8) | hashArr[1]) % 11; // 0-10
  const offset  = (raw - 5) / 100; // -0.05 to +0.05
  const unique  = Math.max(basePrice + offset, 0.01);
  return Math.round(unique * 100) / 100; // round to cents
}

  // ── GET /pay (public — no auth) ─────────────────────
  if (method === 'GET' && url.pathname === '/subscribe') {
    const shareToken = url.searchParams.get('t') || '';
    const accept = request.headers.get('Accept') || '';
    const isAPIRequest = accept.includes('application/json');

    // Browser navigation → serve _pay.html
    if (!isAPIRequest) {
      return env.ASSETS.fetch(new Request(new URL('/pay.html', request.url), request));
    }

    // API fetch → return plan JSON
    if (!shareToken) return json({ error: 'Invalid payment link' }, 400);

    try {
      const raw = await env.DB.get(`plan:${shareToken}`);
      if (!raw) return json({ error: 'Plan not found' }, 404);

      const record = JSON.parse(raw);
      if (record.status === 'paused')   return json({ error: 'Plan paused' }, 403);
      if (record.status === 'archived') return json({ error: 'Plan not found' }, 404);

      const email = record.merchantEmail;
      let walletAddress    = null;
      let lightningAddress = null;
      let merchantName     = null;

      try {
        const w = await env.DB.get(`merchant:${email}:wallet`);
        if (w) walletAddress = JSON.parse(w).address;
      } catch {}

      try {
        const p = await env.DB.get(`merchant:${email}:profile`);
        if (p) {
          const prof = JSON.parse(p);
          merchantName     = prof.displayName      || null;
          lightningAddress = prof.lightningAddress  || null;
        }
      } catch {}

    // Optional subscriber email for unique amount
    const subscriberEmail = url.searchParams.get('e') || '';
    const uniquePriceUSD  = await getUniqueAmount(record.priceUSD, shareToken, subscriberEmail);

      return json({
        planName:           record.name,
        planDesc:           record.desc            || '',
        priceUSD:           record.priceUSD,
        uniquePriceUSD,
        interval:           record.interval,
        merchantName:       merchantName           || '',
        walletAddress:      walletAddress          || '',
        lightningAddress:   lightningAddress        || '',
        trialDays:          record.trialDays        || 0,
        trialUpfront:       record.trialUpfront     || false,
        trialUpfrontAmount: record.trialUpfrontAmount || 0,
      });
    } catch(e) {
      return json({ error: 'Internal error' }, 500);
    }
  }

  // ── POST /merchant/username ──────────────────────────
  if (method === 'POST' && url.pathname === '/merchant/username') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);

    let body;
    try { body = await request.json(); } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }

    const username = (body.username || '').toLowerCase().trim()
      .replace(/[^a-z0-9_-]/g, ''); // alphanumeric, hyphens, underscores only

    if (!username) return json({ error: 'Username required' }, 400);
    if (username.length < 2)  return json({ error: 'Username must be at least 2 characters' }, 400);
    if (username.length > 30) return json({ error: 'Username must be 30 characters or fewer' }, 400);

    // Check if username is taken by another merchant
    const existing = await env.DB.get(`username:${username}`);
    if (existing && JSON.parse(existing).email !== email) {
      return json({ error: 'Username already taken' }, 409);
    }

    // Free up old username if changing
    try {
      const profile = await env.DB.get(`merchant:${email}:profile`);
      if (profile) {
        const old = JSON.parse(profile).username;
        if (old && old !== username) await env.DB.delete(`username:${old}`);
      }
    } catch {}

    // Save username → email mapping for public lookup
    await env.DB.put(`username:${username}`, JSON.stringify({ email, updatedAt: Date.now() }));

    // Save bio + social links to profile
    const bio         = (body.bio         || '').trim().slice(0, 280);
    const website     = (body.website     || '').trim();
    const twitter     = (body.twitter     || '').trim().replace(/^@/, '');
    const instagram   = (body.instagram   || '').trim().replace(/^@/, '');
    const nostr       = (body.nostr       || '').trim();

    // Merge into existing profile
    let existing_profile = {};
    try {
      const raw = await env.DB.get(`merchant:${email}:profile`);
      if (raw) existing_profile = JSON.parse(raw);
    } catch {}

    await env.DB.put(
      `merchant:${email}:profile`,
      JSON.stringify({
        ...existing_profile,
        username,
        bio,
        website,
        twitter,
        instagram,
        nostr,
        updatedAt: Date.now(),
      })
    );

    return json({ success: true, username, profileUrl: `https://ricorra.io/@${username}` });
  }

  // ── GET /@{username} — redirect to /profile?u= ───────
  if (method === 'GET' && url.pathname.startsWith('/@')) {
    const username = url.pathname.slice(2).split('/')[0].toLowerCase();
    if (!username) return json({ error: 'Not found' }, 404);
    return Response.redirect(`https://ricorra.io/profile?u=${encodeURIComponent(username)}`, 302);
  }

  // ── GET /profile — serve profile.html (Cloudflare may route here) ──
  if (method === 'GET' && url.pathname === '/profile') {
    return env.ASSETS.fetch(new Request(new URL('/profile.html', request.url), request));
  }

  // ── GET /profile-data?u= — return merchant JSON ──────
  if (method === 'GET' && url.pathname === '/profile-data') {
    const username = (url.searchParams.get('u') || '').toLowerCase().trim();
    if (!username) return json({ error: 'Username required' }, 400);

    const usernameRecord = await env.DB.get(`username:${username}`);
    if (!usernameRecord) return json({ error: 'Profile not found' }, 404);

    const { email } = JSON.parse(usernameRecord);

    let profile = {};
    try {
      const raw = await env.DB.get(`merchant:${email}:profile`);
      if (raw) profile = JSON.parse(raw);
    } catch {}

    let activePlans = [];
    try {
      const raw = await env.DB.get(`merchant:${email}:sync`);
      if (raw) {
        const sync = JSON.parse(raw);
        const subscribers = sync.subscribers || [];
        activePlans = (sync.plans || [])
          .filter(p => p.status === 'active')
          .map(p => ({
            name:            p.name,
            priceUSD:        p.priceUSD,
            interval:        p.interval,
            desc:            p.desc || '',
            shareToken:      p.shareToken,
            paymentUrl:      `https://ricorra.io/pay?t=${p.shareToken}`,
            subscriberCount: subscribers.filter(s => s.planId === p.id && s.status === 'active').length,
          }));
      }
    } catch {}

    return json({
      username,
      displayName: profile.displayName || username,
      bio:         profile.bio         || '',
      website:     profile.website     || '',
      twitter:     profile.twitter     || '',
      instagram:   profile.instagram   || '',
      nostr:       profile.nostr       || '',
      plans:       activePlans,
    });
  }

  // ── GET /qr?data= — generate QR code PNG ─────────────
  // Pure-JS QR encoder, no npm. Returns image/png.
  if (method === 'GET' && url.pathname === '/qr') {
    const data = url.searchParams.get('data') || '';
    if (!data) return new Response('Missing data', { status: 400 });

    try {
      const png = await generateQRPng(data);
      return new Response(png, {
        headers: {
          'Content-Type':  'image/png',
          'Cache-Control': 'public, max-age=3600',
          ...CORS,
        },
      });
    } catch(e) {
      return new Response('QR generation failed', { status: 500 });
    }
  }

  // ── GET /ical?plan=&renewal=&amount=&wallet= — iCal ──
  if (method === 'GET' && url.pathname === '/ical') {
    const planName   = url.searchParams.get('plan')    || 'Subscription';
    const renewal    = url.searchParams.get('renewal') || '';
    const amount     = url.searchParams.get('amount')  || '';
    const payLink    = url.searchParams.get('pay')     || 'https://ricorra.io';

    const renewalDate = renewal ? new Date(renewal) : new Date(Date.now() + 7*86400000);

    // Format date as YYYYMMDD for iCal
    const pad = n => String(n).padStart(2, '0');
    const icalDate = (d) =>
      `${d.getUTCFullYear()}${pad(d.getUTCMonth()+1)}${pad(d.getUTCDate())}`;

    const dtStart  = icalDate(renewalDate);
    // Reminder day = renewal date itself
    const uid      = `ricorra-${Date.now()}@ricorra.io`;
    const amountStr = amount ? ` ($${amount})` : '';

    const ical = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//Ricorra//Subscription Billing//EN',
      'CALSCALE:GREGORIAN',
      'METHOD:PUBLISH',
      'BEGIN:VEVENT',
      `UID:${uid}`,
      `DTSTART;VALUE=DATE:${dtStart}`,
      `DTEND;VALUE=DATE:${dtStart}`,
      `SUMMARY:Pay: ${planName}${amountStr}`,
      `DESCRIPTION:Your ${planName} subscription renews today.\\nPay here: ${payLink}`,
      `URL:${payLink}`,
      'STATUS:CONFIRMED',
      'TRANSP:TRANSPARENT',
      // Alarm: 1 day before
      'BEGIN:VALARM',
      'TRIGGER:-P1D',
      'ACTION:DISPLAY',
      `DESCRIPTION:Reminder: Pay ${planName} subscription tomorrow`,
      'END:VALARM',
      'END:VEVENT',
      'END:VCALENDAR',
    ].join('\r\n');

    const safeName = planName.replace(/[^a-z0-9]/gi, '-').toLowerCase();
    return new Response(ical, {
      headers: {
        'Content-Type':        'text/calendar; charset=utf-8',
        'Content-Disposition': `attachment; filename="ricorra-${safeName}.ics"`,
        ...CORS,
      },
    });
  }

  // ── GET /merchant/integrations ──────────────────────
  if (method === 'GET' && url.pathname === '/merchant/integrations') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);
    try {
      const raw = await env.DB.get(`merchant:${email}:integrations`);
      if (!raw) return json({ kitApiKey:'', kitTag:'', beehiivApiKey:'', beehiivPubId:'', mailchimpApiKey:'', mailchimpListId:'', listWebhookUrl:'' });
      return json(JSON.parse(raw));
    } catch { return json({ kitApiKey:'', kitTag:'', beehiivApiKey:'', beehiivPubId:'', mailchimpApiKey:'', mailchimpListId:'', listWebhookUrl:'' }); }
  }

  // ── POST /merchant/integrations ──────────────────────
  if (method === 'POST' && url.pathname === '/merchant/integrations') {
    const email = await getEmailFromSession(request, env);
    if (!email) return json({ error: 'Unauthorized' }, 401);
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    await env.DB.put(
      `merchant:${email}:integrations`,
      JSON.stringify({
        kitApiKey:       (body.kitApiKey       || '').trim(),
        kitTag:          (body.kitTag          || '').trim(),
        beehiivApiKey:   (body.beehiivApiKey   || '').trim(),
        beehiivPubId:    (body.beehiivPubId    || '').trim(),
        mailchimpApiKey: (body.mailchimpApiKey  || '').trim(),
        mailchimpListId: (body.mailchimpListId  || '').trim(),
        listWebhookUrl:  (body.listWebhookUrl   || '').trim(),
        updatedAt:       Date.now(),
      })
    );
    return json({ success: true });
  }

  // ── POST /portal/pause ───────────────────────────────
  if (method === 'POST' && url.pathname === '/portal/pause') {
    let body;
    try { body = await request.json(); } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }
    const { token, months } = body;
    if (!token || ![1,2,3].includes(months)) return json({ error: 'Invalid request' }, 400);

    let record;
    try {
      const raw = await env.DB.get(`portal:${token}`);
      if (!raw) return json({ error: 'Invalid portal link' }, 404);
      record = JSON.parse(raw);
    } catch { return json({ error: 'Invalid portal link' }, 400); }

    const { subscriberEmail, merchantEmail, planId } = record;

    // Load and update sync data
    let syncData;
    try {
      const raw = await env.DB.get(`merchant:${merchantEmail}:sync`);
      if (!raw) return json({ error: 'Subscription not found' }, 404);
      syncData = JSON.parse(raw);
    } catch { return json({ error: 'Subscription not found' }, 404); }

    const idx = (syncData.subscribers || []).findIndex(
      s => s.email === subscriberEmail && s.planId === planId
    );
    if (idx === -1) return json({ error: 'Subscription not found' }, 404);

    if (syncData.subscribers[idx].status !== 'active') {
      return json({ error: 'Only active subscriptions can be paused' }, 400);
    }

    // Calculate pause end date
    const pauseUntil = new Date();
    pauseUntil.setMonth(pauseUntil.getMonth() + months);

    syncData.subscribers[idx].status     = 'paused';
    syncData.subscribers[idx].pauseUntil = pauseUntil.toISOString();
    syncData.subscribers[idx].pausedAt   = new Date().toISOString();

    await env.DB.put(
      `merchant:${merchantEmail}:sync`,
      JSON.stringify({ ...syncData, pushedAt: new Date().toISOString() })
    );

    return json({ success: true, pauseUntil: pauseUntil.toISOString() });
  }

  // ── POST /portal/resume ──────────────────────────────
  if (method === 'POST' && url.pathname === '/portal/resume') {
    let body;
    try { body = await request.json(); } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }
    const { token } = body;
    if (!token) return json({ error: 'Invalid request' }, 400);

    let record;
    try {
      const raw = await env.DB.get(`portal:${token}`);
      if (!raw) return json({ error: 'Invalid portal link' }, 404);
      record = JSON.parse(raw);
    } catch { return json({ error: 'Invalid portal link' }, 400); }

    const { subscriberEmail, merchantEmail, planId } = record;

    let syncData;
    try {
      const raw = await env.DB.get(`merchant:${merchantEmail}:sync`);
      if (!raw) return json({ error: 'Subscription not found' }, 404);
      syncData = JSON.parse(raw);
    } catch { return json({ error: 'Subscription not found' }, 404); }

    const idx = (syncData.subscribers || []).findIndex(
      s => s.email === subscriberEmail && s.planId === planId
    );
    if (idx === -1) return json({ error: 'Subscription not found' }, 404);

    if (syncData.subscribers[idx].status !== 'paused') {
      return json({ error: 'Subscription is not paused' }, 400);
    }

    // Resume — set next renewal to today + 1 billing period
    const plan = (syncData.plans || []).find(p => p.id === planId);
    const nextRenewal = new Date();
    if (plan?.interval === 'annual') {
      nextRenewal.setFullYear(nextRenewal.getFullYear() + 1);
    } else {
      nextRenewal.setMonth(nextRenewal.getMonth() + 1);
    }

    syncData.subscribers[idx].status      = 'active';
    syncData.subscribers[idx].pauseUntil  = null;
    syncData.subscribers[idx].pausedAt    = null;
    syncData.subscribers[idx].nextRenewal = nextRenewal.toISOString();

    await env.DB.put(
      `merchant:${merchantEmail}:sync`,
      JSON.stringify({ ...syncData, pushedAt: new Date().toISOString() })
    );

    return json({ success: true });
  }

  // ── GET /portal (public) — serve portal.html ────────
  if (method === 'GET' && url.pathname === '/portal') {
    const accept = request.headers.get('Accept') || '';
    if (!accept.includes('application/json')) {
      return env.ASSETS.fetch(new Request(new URL('/portal.html', request.url), request));
    }

    // API fetch — return subscriber data
    const token = url.searchParams.get('t') || '';
    if (!token) return json({ error: 'Invalid portal link' }, 400);

    let record;
    try {
      const raw = await env.DB.get(`portal:${token}`);
      if (!raw) return json({ error: 'Portal link expired or invalid' }, 404);
      record = JSON.parse(raw);
    } catch { return json({ error: 'Invalid portal link' }, 400); }

    if (Date.now() > record.expires) {
      await env.DB.delete(`portal:${token}`);
      return json({ error: 'Portal link expired' }, 410);
    }

    const { subscriberEmail, merchantEmail, planId } = record;

    // Load sync data to find subscriber
    let syncData;
    try {
      const raw = await env.DB.get(`merchant:${merchantEmail}:sync`);
      if (!raw) return json({ error: 'Subscription not found' }, 404);
      syncData = JSON.parse(raw);
    } catch { return json({ error: 'Subscription not found' }, 404); }

    const subscriber = (syncData.subscribers || []).find(
      s => s.email === subscriberEmail && s.planId === planId
    );
    if (!subscriber) return json({ error: 'Subscription not found' }, 404);

    const plan = (syncData.plans || []).find(p => p.id === planId);
    if (!plan) return json({ error: 'Plan not found' }, 404);

    // Get merchant name
    let merchantName = '';
    try {
      const p = await env.DB.get(`merchant:${merchantEmail}:profile`);
      if (p) merchantName = JSON.parse(p).displayName || '';
    } catch {}

    // Get subscriber's payments
    const allPayments = syncData.payments || [];
    const subPayments = allPayments
      .filter(p => p.subscriberId === subscriber.id)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 12); // last 12 payments

    // Fresh payment link
    const paymentLink = `https://ricorra.io/pay?t=${plan.shareToken}`;

    return json({
      subscriberEmail,
      merchantName,
      planName:    plan.name,
      planDesc:    plan.desc    || '',
      priceUSD:    plan.priceUSD,
      interval:    plan.interval,
      status:      subscriber.status,
      nextRenewal: subscriber.nextRenewal || null,
      gracePeriodStarted: subscriber.gracePeriodStarted || null,
      pauseUntil:  subscriber.pauseUntil  || null,
      paymentLink,
      payments:    subPayments,
    });
  }

  // ── 404 ──────────────────────────────────────────────
  return json({ error: 'Not found' }, 404);
}

// ═══════════════════════════════════════════════════════
// WEBHOOK HELPER — fires on all subscription lifecycle events
// ═══════════════════════════════════════════════════════

const WEBHOOK_EVENTS = {
  PAYMENT_CONFIRMED:      'payment.confirmed',
  SUBSCRIPTION_RENEWED:   'subscription.renewed',
  SUBSCRIPTION_OVERDUE:   'subscription.overdue',
  SUBSCRIPTION_CANCELED:  'subscription.canceled',
  SUBSCRIPTION_REACTIVATED:'subscription.reactivated',
};

async function fireWebhook(merchantEmail, event, data, env) {
  try {
    const raw = await env.DB.get(`merchant:${merchantEmail}:webhook`);
    if (!raw) return;
    const { webhookUrl, webhookSecret } = JSON.parse(raw);
    if (!webhookUrl) return;

    const payload = {
      event,
      timestamp: new Date().toISOString(),
      data,
    };

    // Sign the payload with HMAC-SHA256 if secret is set
    let signature = '';
    if (webhookSecret) {
      const key    = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(webhookSecret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(JSON.stringify(payload)));
      signature    = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('');
    }

    await fetch(webhookUrl, {
      method:  'POST',
      headers: {
        'Content-Type':          'application/json',
        'X-Ricorra-Event':       event,
        'X-Ricorra-Signature':   signature,
        'X-Ricorra-Timestamp':   Date.now().toString(),
        'User-Agent':            'Ricorra-Webhooks/1.0',
      },
      body: JSON.stringify(payload),
    });
  } catch(e) { /* silent — webhook failures never block core logic */ }
}

// ═══════════════════════════════════════════════════════
// EMAIL LIST INTEGRATIONS
// Fires on subscribe (action='subscribe') and cancel (action='unsubscribe')
// ═══════════════════════════════════════════════════════

async function fireEmailListIntegrations(merchantEmail, subscriberEmail, action, env) {
  let intgs = {};
  try {
    const raw = await env.DB.get(`merchant:${merchantEmail}:integrations`);
    if (raw) intgs = JSON.parse(raw);
  } catch { return; }

  const isSubscribe = action === 'subscribe';

  // ── Kit ─────────────────────────────────────────────
  if (intgs.kitApiKey) {
    try {
      if (isSubscribe) {
        // Find or create subscriber
        const res = await fetch('https://api.kit.com/v4/subscribers', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', 'X-Kit-Api-Key': intgs.kitApiKey },
          body: JSON.stringify({
            email_address: subscriberEmail,
            state: 'active',
            tags: intgs.kitTag ? [intgs.kitTag] : [],
          }),
        });
      } else {
        // Unsubscribe
        const searchRes = await fetch(
          `https://api.kit.com/v4/subscribers?email_address=${encodeURIComponent(subscriberEmail)}`,
          { headers: { 'X-Kit-Api-Key': intgs.kitApiKey } }
        );
        if (searchRes.ok) {
          const data = await searchRes.json();
          const subId = data.subscribers?.[0]?.id;
          if (subId) {
            await fetch(`https://api.kit.com/v4/subscribers/${subId}/unsubscribe`, {
              method: 'POST',
              headers: { 'X-Kit-Api-Key': intgs.kitApiKey },
            });
          }
        }
      }
    } catch(e) { /* silent */ }
  }

  // ── Beehiiv ──────────────────────────────────────────
  if (intgs.beehiivApiKey && intgs.beehiivPubId) {
    try {
      if (isSubscribe) {
        await fetch(`https://api.beehiiv.com/v2/publications/${intgs.beehiivPubId}/subscriptions`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${intgs.beehiivApiKey}` },
          body: JSON.stringify({ email: subscriberEmail, reactivate_existing: true, send_welcome_email: false }),
        });
      } else {
        // Find subscriber and unsubscribe
        const searchRes = await fetch(
          `https://api.beehiiv.com/v2/publications/${intgs.beehiivPubId}/subscriptions?email=${encodeURIComponent(subscriberEmail)}`,
          { headers: { 'Authorization': `Bearer ${intgs.beehiivApiKey}` } }
        );
        if (searchRes.ok) {
          const data = await searchRes.json();
          const subId = data.data?.[0]?.id;
          if (subId) {
            await fetch(`https://api.beehiiv.com/v2/publications/${intgs.beehiivPubId}/subscriptions/${subId}`, {
              method:  'PATCH',
              headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${intgs.beehiivApiKey}` },
              body: JSON.stringify({ status: 'inactive' }),
            });
          }
        }
      }
    } catch(e) { /* silent */ }
  }

  // ── Mailchimp ────────────────────────────────────────
  if (intgs.mailchimpApiKey && intgs.mailchimpListId) {
    try {
      // Extract datacenter from API key (e.g. "abc123-us6" → "us6")
      const dc = intgs.mailchimpApiKey.split('-')[1] || 'us1';
      // Mailchimp uses MD5 hash of lowercase email as subscriber ID
      const emailHash = await crypto.subtle.digest('SHA-256',
        new TextEncoder().encode(subscriberEmail.toLowerCase())
      ).then(buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join(''));
      // Note: Mailchimp actually uses MD5 not SHA-256, but Workers don't have MD5
      // Use the email directly in the request body instead
      const status = isSubscribe ? 'subscribed' : 'unsubscribed';
      await fetch(
        `https://${dc}.api.mailchimp.com/3.0/lists/${intgs.mailchimpListId}/members`,
        {
          method:  'POST',
          headers: {
            'Content-Type':  'application/json',
            'Authorization': `Basic ${btoa('anystring:' + intgs.mailchimpApiKey)}`,
          },
          body: JSON.stringify({ email_address: subscriberEmail, status }),
        }
      );
    } catch(e) { /* silent */ }
  }

  // ── Generic list webhook ─────────────────────────────
  if (intgs.listWebhookUrl) {
    try {
      await fetch(intgs.listWebhookUrl, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'Ricorra-Integrations/1.0' },
        body: JSON.stringify({ email: subscriberEmail, action }),
      });
    } catch(e) { /* silent */ }
  }
}

// ═══════════════════════════════════════════════════════
// CRON — Renewal reminders + grace period processing
// Runs daily at 9am UTC via wrangler.toml trigger
// ═══════════════════════════════════════════════════════

async function fetchBTCRateForCron() {
  try {
    const res  = await fetch('https://blockchain.info/ticker');
    const data = await res.json();
    if (data.USD?.last) return data.USD.last;
  } catch {}
  try {
    const res  = await fetch('https://api.coinbase.com/v2/exchange-rates?currency=BTC');
    const data = await res.json();
    if (data.data?.rates?.USD) return parseFloat(data.data.rates.USD);
  } catch {}
  return 0;
}

function buildReminderEmail({ merchantName, subscriberEmail, planName, priceUSD, btcAmount, paymentLink, daysUntil, interval, portalLink, walletAddress, renewalDate, lightningAddress }) {
  const btcStr     = btcAmount > 0 ? btcAmount.toFixed(6) + ' BTC' : '';
  const intervalStr= interval === 'annual' ? 'year' : 'month';
  const urgency    = daysUntil <= 1 ? 'today' : `in ${daysUntil} days`;
  const subject    = daysUntil <= 1
    ? `Your ${planName} subscription renews today`
    : `Your ${planName} subscription renews ${urgency}`;
  const portalFooter = portalLink
    ? `<a href="${portalLink}" style="color:#C49A3C;">Manage your subscription →</a> · `
    : '';

  // Prefilled pay link — auto-loads unique amount for this subscriber
  const prefilledLink = subscriberEmail
    ? `${paymentLink}&e=${encodeURIComponent(subscriberEmail)}`
    : paymentLink;

  // Bitcoin QR — shown at 3 days, 1 day, and day-of
  const showQR = daysUntil <= 3 && walletAddress && btcAmount > 0;
  const btcUri = walletAddress
    ? `bitcoin:${walletAddress}?amount=${btcAmount.toFixed(8)}`
    : '';
  const qrUrl  = btcUri
    ? `https://ricorra.io/qr?data=${encodeURIComponent(btcUri)}`
    : '';

  // Lightning — shown at 3 days, 1 day, and day-of when merchant has Lightning address
  const showLightning = daysUntil <= 3 && lightningAddress;
  const lightningUri  = lightningAddress
    ? `lightning:${lightningAddress}`
    : '';
  const lightningQrUrl = lightningAddress
    ? `https://ricorra.io/qr?data=${encodeURIComponent(lightningUri)}`
    : '';

  // Calendar link — shown at 7 days only
  const showCal = daysUntil === 7 && renewalDate;
  const icalUrl = showCal
    ? `https://ricorra.io/ical?plan=${encodeURIComponent(planName)}&renewal=${encodeURIComponent(renewalDate)}&amount=${priceUSD.toFixed(2)}&pay=${encodeURIComponent(prefilledLink)}`
    : '';

  // Urgency color
  const urgencyColor = daysUntil <= 1 ? '#991B1B' : daysUntil <= 3 ? '#D97706' : '#1C1C1A';

  return {
    subject,
    html: `
      <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
        <div style="text-align:center;margin-bottom:1.5rem;">
          <div style="display:inline-block;width:48px;height:48px;background:#C49A3C;border-radius:50%;line-height:48px;text-align:center;font-size:22px;color:#FAF8F4;">₿</div>
        </div>
        <h2 style="font-size:22px;font-weight:500;margin-bottom:0.5rem;text-align:center;">
          Your subscription renews ${urgency}
        </h2>
        <p style="color:#6B6860;text-align:center;margin-bottom:1.5rem;font-size:14px;">
          ${planName}${merchantName ? ' · ' + merchantName : ''}
        </p>

        ${showCal ? `
        <!-- Add to Calendar — 7-day email only -->
        <div style="text-align:center;margin-bottom:1.25rem;">
          <a href="${icalUrl}"
            style="display:inline-flex;align-items:center;gap:8px;background:white;color:#1C1C1A;
            text-decoration:none;padding:10px 20px;border-radius:50px;font-family:sans-serif;
            font-size:13px;font-weight:600;border:1.5px solid #E2DDD6;">
            📅 Add to Calendar
          </a>
          <div style="font-size:11px;color:#9A9690;margin-top:6px;">Works with Apple Calendar, Google Calendar, Outlook</div>
        </div>` : ''}

        <!-- Payment details -->
        <div style="background:white;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;">
          <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
            <span style="color:#6B6860;">Plan</span>
            <span style="font-weight:600;">${planName}</span>
          </div>
          <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
            <span style="color:#6B6860;">Amount</span>
            <span style="font-weight:600;">$${priceUSD.toFixed(2)} / ${intervalStr}</span>
          </div>
          ${btcStr ? `
          <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
            <span style="color:#6B6860;">In Bitcoin</span>
            <span style="font-weight:600;">${btcStr}</span>
          </div>` : ''}
          <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;">
            <span style="color:#6B6860;">Renews</span>
            <span style="font-weight:600;color:${urgencyColor};">${urgency}</span>
          </div>
        </div>

        ${showQR ? `
        <!-- Bitcoin QR Code — 3 days, 1 day, day-of -->
        <div style="background:white;border-radius:16px;padding:1.5rem;margin-bottom:${showLightning ? '12px' : '1.5rem'};border:1px solid #E2DDD6;text-align:center;">
          <div style="font-size:11px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#9A9690;margin-bottom:12px;">₿ Scan to pay — Bitcoin</div>
          <img src="${qrUrl}" width="160" height="160" alt="Bitcoin payment QR code"
            style="display:block;margin:0 auto 12px;border-radius:8px;">
          <div style="font-size:12px;color:#6B6860;margin-bottom:8px;">
            Open your Bitcoin wallet, tap <strong>Send</strong>, and scan.<br>
            The exact amount will be pre-filled automatically.
          </div>
          <a href="${btcUri}"
            style="display:inline-block;background:#1C1C1A;color:#FAF8F4;text-decoration:none;
            padding:9px 20px;border-radius:50px;font-family:sans-serif;font-size:12px;font-weight:600;">
            Open in Bitcoin wallet →
          </a>
        </div>` : ''}

        ${showLightning ? `
        <!-- Lightning QR Code — 3 days, 1 day, day-of -->
        <div style="background:white;border-radius:16px;padding:1.5rem;margin-bottom:1.5rem;border:1px solid #F59E0B;text-align:center;">
          <div style="font-size:11px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#D97706;margin-bottom:12px;">⚡ Scan to pay — Lightning</div>
          <img src="${lightningQrUrl}" width="160" height="160" alt="Lightning payment QR code"
            style="display:block;margin:0 auto 12px;border-radius:8px;">
          <div style="font-size:12px;color:#6B6860;margin-bottom:8px;">
            Instant · Near-zero fee · Open your Lightning wallet and scan.
          </div>
          <a href="${lightningUri}"
            style="display:inline-block;background:#D97706;color:#FAF8F4;text-decoration:none;
            padding:9px 20px;border-radius:50px;font-family:sans-serif;font-size:12px;font-weight:600;">
            Open in Lightning wallet ⚡
          </a>
        </div>` : ''}

        <!-- Pay now button -->
        <div style="text-align:center;margin-bottom:1.5rem;">
          <a href="${prefilledLink}"
            style="display:inline-block;background:#C49A3C;color:#FAF8F4;text-decoration:none;
            padding:13px 32px;border-radius:50px;font-family:sans-serif;font-size:14px;font-weight:600;">
            ${(showQR || showLightning) ? 'Pay on web instead →' : 'Pay now →'}
          </a>
        </div>

        <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;">
          This is a non-custodial Bitcoin subscription. Your payment goes directly to the merchant's wallet.<br>
          ${portalFooter}<a href="https://ricorra.io/account" style="color:#C49A3C;">All my subscriptions →</a> · <a href="https://ricorra.com" style="color:#C49A3C;">ricorra.com</a>
        </p>
      </div>`,
  };
}

function buildGraceEmail({ merchantName, planName, priceUSD, paymentLink, graceDaysLeft }) {
  return {
    subject: `Action needed — your ${planName} subscription payment is overdue`,
    html: `
      <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
        <div style="text-align:center;margin-bottom:1.5rem;">
          <div style="display:inline-block;width:48px;height:48px;background:#C49A3C;border-radius:50%;line-height:48px;text-align:center;font-size:22px;color:#FAF8F4;">₿</div>
        </div>
        <h2 style="font-size:22px;font-weight:500;margin-bottom:0.5rem;text-align:center;">
          Your payment is overdue
        </h2>
        <p style="color:#6B6860;text-align:center;margin-bottom:1.5rem;font-size:14px;">
          ${planName}${merchantName ? ' · ' + merchantName : ''}
        </p>
        <div style="background:#FEF3C7;border-radius:12px;padding:1rem 1.5rem;margin-bottom:1.5rem;border:1px solid #F59E0B;">
          <p style="font-size:13px;color:#92400E;margin:0;line-height:1.6;">
            Your subscription payment of <strong>$${priceUSD.toFixed(2)}</strong> is overdue.
            You have <strong>${graceDaysLeft} day${graceDaysLeft !== 1 ? 's' : ''}</strong> remaining
            in your grace period before your subscription is canceled.
          </p>
        </div>
        <div style="text-align:center;margin-bottom:1.5rem;">
          <a href="${paymentLink}"
            style="display:inline-block;background:#C49A3C;color:#FAF8F4;text-decoration:none;
            padding:13px 32px;border-radius:50px;font-family:sans-serif;font-size:14px;font-weight:600;">
            Pay now to keep your subscription →
          </a>
        </div>
        <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;">
          Ricorra never charges you automatically. Send Bitcoin directly to keep your subscription active.<br>
          <a href="https://ricorra.com" style="color:#C49A3C;">ricorra.com</a>
        </p>
      </div>`,
  };
}

function buildCanceledEmail({ merchantName, planName, reactivationLink, portalLink }) {
  const manageLink = portalLink || reactivationLink;
  return {
    subject: `Your ${planName} subscription has ended`,
    html: `
      <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
        <div style="text-align:center;margin-bottom:1.5rem;">
          <div style="display:inline-block;width:48px;height:48px;background:#6B6860;border-radius:50%;line-height:48px;text-align:center;font-size:22px;color:#FAF8F4;">₿</div>
        </div>
        <h2 style="font-size:22px;font-weight:500;margin-bottom:0.5rem;text-align:center;">
          Your subscription has ended
        </h2>
        <p style="color:#6B6860;text-align:center;margin-bottom:1.5rem;font-size:14px;">
          ${planName}${merchantName ? ' · ' + merchantName : ''}
        </p>
        <p style="font-size:14px;color:#6B6860;text-align:center;margin-bottom:1.5rem;line-height:1.6;">
          Your grace period has ended and your subscription has been canceled.
          You can reactivate at any time — just make a payment and you'll be back instantly.
        </p>
        <div style="text-align:center;margin-bottom:1rem;">
          <a href="${reactivationLink}"
            style="display:inline-block;background:#C49A3C;color:#FAF8F4;text-decoration:none;
            padding:13px 32px;border-radius:50px;font-family:sans-serif;font-size:14px;font-weight:600;">
            Reactivate my subscription →
          </a>
        </div>
        ${portalLink ? `
        <div style="text-align:center;margin-bottom:1.5rem;">
          <a href="${portalLink}"
            style="font-size:12px;color:#C49A3C;text-decoration:none;font-weight:600;">
            View my subscription history →
          </a>
        </div>` : ''}
        <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;">
          <a href="https://ricorra.com" style="color:#C49A3C;">ricorra.com</a>
        </p>
      </div>`,
  };
}

async function sendEmail(to, subject, html, env) {
  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from:    'Ricorra <hello@ricorra.com>',
      to,
      subject,
      html,
    }),
  });
  return res.ok;
}

async function runCron(env) {
  const now        = Date.now();
  const DAY_MS     = 24 * 60 * 60 * 1000;
  const GRACE_DAYS = 7;

  // Fetch live BTC rate once for all emails
  const btcRate = await fetchBTCRateForCron();

  // List all merchant sync keys
  let cursor;
  do {
    const list = await env.DB.list({ prefix: 'merchant:', cursor, limit: 100 });
    cursor = list.list_complete ? null : list.cursor;

    for (const key of list.keys) {
      // Only process sync keys
      if (!key.name.endsWith(':sync')) continue;

      let syncData;
      try {
        const raw = await env.DB.get(key.name);
        if (!raw) continue;
        syncData = JSON.parse(raw);
      } catch { continue; }

      const email       = key.name.replace('merchant:', '').replace(':sync', '');
      const subscribers = syncData.subscribers || [];
      const plans       = syncData.plans       || [];
      const payments    = syncData.payments    || [];

      if (subscribers.length === 0) continue;

      // Load merchant name and wallet
      let merchantName = '';
      let walletAddress = '';
      let lightningAddress = '';
      try {
        const p = await env.DB.get(`merchant:${email}:profile`);
        if (p) {
          const prof = JSON.parse(p);
          merchantName     = prof.displayName      || '';
          lightningAddress = prof.lightningAddress || '';
        }
      } catch {}
      try {
        const w = await env.DB.get(`merchant:${email}:wallet`);
        if (w) walletAddress = JSON.parse(w).address || '';
      } catch {}

      let syncChanged = false;

      for (let i = 0; i < subscribers.length; i++) {
        const sub  = subscribers[i];
        const plan = plans.find(p => p.id === sub.planId);
        if (!plan) continue;

        const paymentLink     = `https://ricorra.io/pay?t=${plan.shareToken}`;
        const btcAmount       = btcRate > 0 ? plan.priceUSD / btcRate : 0;

        // ── PAUSED subscribers: auto-resume when pause ends ──
        if (sub.status === 'paused' && sub.pauseUntil) {
          const pauseUntilTs = new Date(sub.pauseUntil).getTime();
          if (pauseUntilTs <= now) {
            // Pause period ended — resume subscription
            const plan = plans.find(p => p.id === sub.planId);
            const nextRenewal = new Date();
            if (plan?.interval === 'annual') {
              nextRenewal.setFullYear(nextRenewal.getFullYear() + 1);
            } else {
              nextRenewal.setMonth(nextRenewal.getMonth() + 1);
            }
            subscribers[i].status      = 'active';
            subscribers[i].pauseUntil  = null;
            subscribers[i].pausedAt    = null;
            subscribers[i].nextRenewal = nextRenewal.toISOString();
            syncChanged = true;

            // Send resume notification email
            if (plan) {
              const resumePaymentLink = `https://ricorra.io/pay?t=${plan.shareToken}`;
              await sendEmail(
                sub.email,
                `Your ${plan.name} subscription has resumed`,
                `<div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
                  <div style="text-align:center;margin-bottom:1.5rem;">
                    <div style="display:inline-block;width:48px;height:48px;background:#C49A3C;border-radius:50%;line-height:48px;text-align:center;font-size:22px;color:#FAF8F4;">₿</div>
                  </div>
                  <h2 style="font-size:22px;font-weight:500;margin-bottom:0.5rem;text-align:center;">Welcome back!</h2>
                  <p style="color:#6B6860;text-align:center;margin-bottom:1.5rem;font-size:14px;">
                    ${plan.name}${merchantName ? ' · ' + merchantName : ''}
                  </p>
                  <p style="font-size:14px;color:#1C1C1A;line-height:1.7;text-align:center;margin-bottom:1.5rem;">
                    Your pause period has ended and your subscription is now active again.
                    Your next renewal is on <strong>${nextRenewal.toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric'})}</strong>.
                  </p>
                  <div style="text-align:center;">
                    <a href="${resumePaymentLink}" style="display:inline-block;background:#C49A3C;color:#FAF8F4;text-decoration:none;padding:12px 28px;border-radius:50px;font-family:sans-serif;font-size:14px;font-weight:600;">View my subscription →</a>
                  </div>
                  <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;margin-top:1.5rem;">
                    <a href="https://ricorra.com" style="color:#C49A3C;">ricorra.com</a>
                  </p>
                </div>`,
                env
              );
            }
          }
        }

        // ── TRIAL subscribers: send trial-end reminders ──
        if (sub.status === 'trial' && sub.trialEnds) {
          const trialEndTs  = new Date(sub.trialEnds).getTime();
          const daysLeft    = Math.ceil((trialEndTs - now) / DAY_MS);

          // Send trial reminder at 3 days, 1 day, and day-of
          if ([3, 1, 0].includes(daysLeft)) {
            const portalToken = await getPortalToken(sub.email, email, sub.planId, env);
            const portalLink  = `https://ricorra.io/portal?t=${portalToken}`;
            const trialSubject = daysLeft <= 0
              ? `Your free trial of ${plan.name} ends today`
              : `Your free trial ends in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}`;

            const trialHtml = `
              <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
                <div style="text-align:center;margin-bottom:1.5rem;">
                  <div style="display:inline-block;width:48px;height:48px;background:#C49A3C;border-radius:50%;line-height:48px;text-align:center;font-size:22px;color:#FAF8F4;">₿</div>
                </div>
                <h2 style="font-size:22px;font-weight:500;margin-bottom:0.5rem;text-align:center;">
                  ${daysLeft <= 0 ? 'Your free trial ends today' : `Your free trial ends in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}`}
                </h2>
                <p style="color:#6B6860;text-align:center;margin-bottom:1.5rem;font-size:14px;">
                  ${plan.name}${merchantName ? ' · ' + merchantName : ''}
                </p>
                <div style="background:white;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;">
                  <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
                    <span style="color:#6B6860;">Plan</span>
                    <span style="font-weight:600;">${plan.name}</span>
                  </div>
                  <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
                    <span style="color:#6B6860;">After trial</span>
                    <span style="font-weight:600;">$${plan.priceUSD.toFixed(2)} / ${plan.interval === 'annual' ? 'year' : 'month'}</span>
                  </div>
                  ${btcAmount > 0 ? `
                  <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
                    <span style="color:#6B6860;">In Bitcoin</span>
                    <span style="font-weight:600;">${btcAmount.toFixed(6)} BTC</span>
                  </div>` : ''}
                  <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;">
                    <span style="color:#6B6860;">Trial ends</span>
                    <span style="font-weight:600;color:${daysLeft <= 1 ? '#991B1B' : '#D97706'};">
                      ${daysLeft <= 0 ? 'Today' : `in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}`}
                    </span>
                  </div>
                </div>
                ${daysLeft <= 1 && walletAddress && btcAmount > 0 ? `
                <div style="background:white;border-radius:16px;padding:1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;text-align:center;">
                  <div style="font-size:11px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#9A9690;margin-bottom:12px;">Pay to continue</div>
                  <img src="https://ricorra.io/qr?data=${encodeURIComponent(`bitcoin:${walletAddress}?amount=${btcAmount.toFixed(8)}`)}"
                    width="160" height="160" alt="Bitcoin QR code"
                    style="display:block;margin:0 auto 12px;border-radius:8px;">
                  <a href="bitcoin:${walletAddress}?amount=${btcAmount.toFixed(8)}"
                    style="display:inline-block;background:#1C1C1A;color:#FAF8F4;text-decoration:none;
                    padding:9px 20px;border-radius:50px;font-family:sans-serif;font-size:12px;font-weight:600;">
                    Open in wallet app →
                  </a>
                </div>` : ''}
                <div style="text-align:center;margin-bottom:1.5rem;">
                  <a href="${paymentLink}&e=${encodeURIComponent(sub.email)}"
                    style="display:inline-block;background:#C49A3C;color:#FAF8F4;text-decoration:none;
                    padding:13px 32px;border-radius:50px;font-family:sans-serif;font-size:14px;font-weight:600;">
                    Pay to keep access →
                  </a>
                </div>
                <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;">
                  No card required. No auto-charge. Pay only if you love it.<br>
                  <a href="${portalLink}" style="color:#C49A3C;">Manage your subscription →</a>
                </p>
              </div>`;

            await sendEmail(sub.email, trialSubject, trialHtml, env);
          }

          // Trial has ended → move to grace period (7 days to pay)
          if (trialEndTs < now && daysLeft < 0) {
            subscribers[i].status             = 'overdue';
            subscribers[i].gracePeriodStarted = new Date().toISOString();
            subscribers[i].nextRenewal        = new Date(now + 30 * DAY_MS).toISOString();
            syncChanged = true;

            await fireWebhook(email, WEBHOOK_EVENTS.SUBSCRIPTION_OVERDUE, {
              subscriberEmail: sub.email,
              planName: plan.name, planId: plan.id,
              priceUSD: plan.priceUSD, interval: plan.interval,
              reason: 'trial_ended',
            }, env);

            const { subject, html } = buildGraceEmail({
              merchantName, planName: plan.name,
              priceUSD: plan.priceUSD, paymentLink,
              graceDaysLeft: 7,
            });
            await sendEmail(sub.email, subject, html, env);
          }
        }

        // ── ACTIVE subscribers: send renewal reminders ──
        if (sub.status === 'active' && sub.nextRenewal) {
          const renewalTs   = new Date(sub.nextRenewal).getTime();
          const daysUntil   = Math.ceil((renewalTs - now) / DAY_MS);

          // Send reminders at 7 days, 3 days, 1 day, and 0 days (due today)
          if ([7, 3, 1, 0].includes(daysUntil)) {
            const portalToken = await getPortalToken(sub.email, email, sub.planId, env);
            const portalLink  = `https://ricorra.io/portal?t=${portalToken}`;
            const { subject, html } = buildReminderEmail({
              merchantName, subscriberEmail: sub.email,
              planName: plan.name, priceUSD: plan.priceUSD,
              btcAmount, paymentLink, daysUntil,
              interval: plan.interval, portalLink,
              walletAddress,
              renewalDate: sub.nextRenewal,
              lightningAddress,
            });
            await sendEmail(sub.email, subject, html, env);
          }

          // ── Anniversary check ──
          // Check if today is their subscription anniversary (6 or 12 months)
          if (sub.createdAt) {
            const created     = new Date(sub.createdAt);
            const monthsOld   = (now - created.getTime()) / (DAY_MS * 30.44);
            const roundedMonths = Math.round(monthsOld);
            // Fire on the day of the anniversary (within 1 day tolerance)
            const daysSinceAnniv = Math.abs(monthsOld - roundedMonths) * 30.44;
            if ([6, 12, 24, 36].includes(roundedMonths) && daysSinceAnniv < 1) {
              const years  = roundedMonths / 12;
              const label  = roundedMonths >= 12
                ? years + ' year' + (years > 1 ? 's' : '')
                : roundedMonths + ' months';
              const portalToken2 = await getPortalToken(sub.email, email, sub.planId, env);
              const portalLink2  = `https://ricorra.io/portal?t=${portalToken2}`;
              await sendEmail(
                sub.email,
                `🎉 ${label} with ${plan.name}${merchantName ? ' · ' + merchantName : ''}`,
                buildAnniversaryEmail({
                  merchantName, planName: plan.name,
                  label, priceUSD: plan.priceUSD,
                  interval: plan.interval,
                  portalLink: portalLink2,
                }),
                env
              );
            }
          }

          // If renewal date has passed → move to grace period
          if (renewalTs < now && daysUntil < 0) {
            subscribers[i].status              = 'overdue';
            subscribers[i].gracePeriodStarted  = new Date().toISOString();
            syncChanged = true;

            // Fire webhook
            await fireWebhook(email, WEBHOOK_EVENTS.SUBSCRIPTION_OVERDUE, {
              subscriberEmail: sub.email,
              planName: plan.name,
              planId: plan.id,
              priceUSD: plan.priceUSD,
              interval: plan.interval,
            }, env);

            // Send first grace period email
            const { subject, html } = buildGraceEmail({
              merchantName, planName: plan.name,
              priceUSD: plan.priceUSD, paymentLink,
              graceDaysLeft: GRACE_DAYS,
            });
            await sendEmail(sub.email, subject, html, env);
          }
        }

        // ── OVERDUE subscribers: daily grace period emails + auto-cancel ──
        if (sub.status === 'overdue' && sub.gracePeriodStarted) {
          const graceStartTs  = new Date(sub.gracePeriodStarted).getTime();
          const daysInGrace   = Math.floor((now - graceStartTs) / DAY_MS);
          const graceDaysLeft = GRACE_DAYS - daysInGrace;

          if (graceDaysLeft <= 0) {
            // Grace period expired → cancel subscription
            subscribers[i].status = 'canceled';
            syncChanged = true;

            // Fire webhook
            await fireWebhook(email, WEBHOOK_EVENTS.SUBSCRIPTION_CANCELED, {
              subscriberEmail: sub.email,
              planName: plan.name,
              planId: plan.id,
              priceUSD: plan.priceUSD,
              interval: plan.interval,
            }, env);

            // Fire email list integration — unsubscribe
            await fireEmailListIntegrations(email, sub.email, 'unsubscribe', env);

            const cancelPortalToken = await getPortalToken(sub.email, email, sub.planId, env);
            const cancelPortalLink  = `https://ricorra.io/portal?t=${cancelPortalToken}`;
            const reactivationLink  = `${paymentLink}&reactivate=1`;
            const { subject, html } = buildCanceledEmail({
              merchantName, planName: plan.name,
              reactivationLink,
              portalLink: cancelPortalLink,
            });
            await sendEmail(sub.email, subject, html, env);

          } else {
            // Still in grace period → daily nudge
            const { subject, html } = buildGraceEmail({
              merchantName, planName: plan.name,
              priceUSD: plan.priceUSD, paymentLink,
              graceDaysLeft,
            });
            await sendEmail(sub.email, subject, html, env);
          }
        }
      }

      // If any subscriber statuses changed, write back to KV
      if (syncChanged) {
        await env.DB.put(key.name, JSON.stringify({
          ...syncData,
          subscribers,
          pushedAt: new Date().toISOString(),
        }));
      }
    }
  } while (cursor);
}

// ═══════════════════════════════════════════════════════
// AI WEEKLY DIGEST — Runs every Monday at 9am UTC
// Uses Claude API to generate merchant triage summary
// ═══════════════════════════════════════════════════════

async function runWeeklyDigest(env) {
  const now    = Date.now();
  const DAY_MS = 24 * 60 * 60 * 1000;
  const btcRate = await fetchBTCRateForCron();

  let cursor;
  do {
    const list = await env.DB.list({ prefix: 'merchant:', cursor, limit: 100 });
    cursor = list.list_complete ? null : list.cursor;

    for (const key of list.keys) {
      if (!key.name.endsWith(':sync')) continue;

      let syncData;
      try {
        const raw = await env.DB.get(key.name);
        if (!raw) continue;
        syncData = JSON.parse(raw);
      } catch { continue; }

      const email       = key.name.replace('merchant:', '').replace(':sync', '');
      const subscribers = syncData.subscribers || [];
      const plans       = syncData.plans       || [];
      const payments    = syncData.payments    || [];

      if (subscribers.length === 0) continue;

      // Load merchant profile for name + digest settings
      let merchantName  = '';
      let digestEmail   = email;
      let digestEnabled = false;
      try {
        const p = await env.DB.get(`merchant:${email}:profile`);
        if (p) {
          const prof = JSON.parse(p);
          merchantName  = prof.displayName    || '';
          digestEmail   = prof.digestEmail    || email;
          digestEnabled = prof.digestEnabled  || false;
        }
      } catch {}

      // Skip if digest not enabled
      if (!digestEnabled) continue;

      // ── Build stats for Claude ──
      const activeSubs   = subscribers.filter(s => s.status === 'active');
      const overdueSubs  = subscribers.filter(s => s.status === 'overdue');
      const canceledSubs = subscribers.filter(s => s.status === 'canceled');

      // MRR
      const mrr = plans
        .filter(p => p.status === 'active')
        .reduce((sum, p) => {
          const monthly = p.interval === 'annual' ? p.priceUSD / 12 : p.priceUSD;
          const subs    = activeSubs.filter(s => s.planId === p.id).length;
          return sum + (monthly * subs);
        }, 0);

      // Revenue last 7 days vs prior 7 days
      const week1 = payments.filter(p => now - new Date(p.timestamp).getTime() < 7 * DAY_MS)
        .reduce((s, p) => s + p.usd, 0);
      const week2 = payments.filter(p => {
        const age = now - new Date(p.timestamp).getTime();
        return age >= 7 * DAY_MS && age < 14 * DAY_MS;
      }).reduce((s, p) => s + p.usd, 0);
      const revTrend = week2 > 0 ? ((week1 - week2) / week2 * 100).toFixed(1) : null;

      // Renewals due next 7 days
      const renewalsDue = activeSubs.filter(s => {
        if (!s.nextRenewal) return false;
        const daysOut = Math.ceil((new Date(s.nextRenewal) - now) / DAY_MS);
        return daysOut >= 0 && daysOut <= 7;
      });

      // Grace period subscribers with tenure
      const graceDetails = overdueSubs.map(s => {
        const plan = plans.find(p => p.id === s.planId);
        const subPayments = payments.filter(p => p.subscriberId === s.id);
        const firstPayment = subPayments.sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp))[0];
        const monthsTenure = firstPayment
          ? Math.floor((now - new Date(firstPayment.timestamp).getTime()) / (30 * DAY_MS))
          : 0;
        const daysInGrace = s.gracePeriodStarted
          ? Math.floor((now - new Date(s.gracePeriodStarted).getTime()) / DAY_MS)
          : 0;
        return {
          email:        s.email,
          planName:     plan?.name || 'Unknown plan',
          monthsTenure,
          daysInGrace,
          graceDaysLeft: Math.max(7 - daysInGrace, 0),
        };
      });

      // Top plan by subscriber count
      const topPlan = plans
        .filter(p => p.status === 'active')
        .map(p => ({ ...p, count: activeSubs.filter(s => s.planId === p.id).length }))
        .sort((a, b) => b.count - a.count)[0];

      // ── Call Claude API for triage ──
      const statsContext = `
Merchant: ${merchantName || email}
Active subscribers: ${activeSubs.length}
Overdue (in grace period): ${overdueSubs.length}
Canceled (all time): ${canceledSubs.length}
Monthly Recurring Revenue: $${mrr.toFixed(2)}
Revenue last 7 days: $${week1.toFixed(2)}${revTrend ? ` (${revTrend > 0 ? '+' : ''}${revTrend}% vs prior week)` : ''}
Renewals due next 7 days: ${renewalsDue.length}
Top plan: ${topPlan ? `${topPlan.name} (${topPlan.count} subscribers)` : 'None'}
${graceDetails.length > 0 ? `\nSubscribers in grace period:\n${graceDetails.map(g =>
  `- ${g.email}: ${g.monthsTenure} months as customer, ${g.daysInGrace} days into grace, ${g.graceDaysLeft} days left`
).join('\n')}` : ''}`.trim();

      let aiTriage = '';
      try {
        const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
          method:  'POST',
          headers: {
            'Content-Type':      'application/json',
            'x-api-key':         env.ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model:      'claude-sonnet-4-20250514',
            max_tokens: 200,
            system:     `You are a concise business advisor writing a 2-3 sentence weekly triage for a Bitcoin subscription merchant using Ricorra. Be specific, warm, and actionable. Focus on what needs attention. Never just restate numbers — synthesize them into insight. Mention specific subscribers by first name (from email) only when relevant. Keep it under 60 words.`,
            messages: [{
              role:    'user',
              content: `Here's this week's data for my subscription business:\n\n${statsContext}\n\nWrite a brief triage summary.`,
            }],
          }),
        });

        if (claudeRes.ok) {
          const claudeData = await claudeRes.json();
          aiTriage = claudeData.content?.[0]?.text || '';
        }
      } catch(e) {
        aiTriage = ''; // graceful fallback — digest still sends without AI triage
      }

      // ── Build and send digest email ──
      const digestHtml = buildDigestEmail({
        merchantName, email,
        activeSubs:   activeSubs.length,
        overdueSubs:  overdueSubs.length,
        canceledSubs: canceledSubs.length,
        mrr, week1, revTrend,
        renewalsDue:  renewalsDue.length,
        topPlan,
        graceDetails,
        aiTriage,
        btcRate,
      });

      await sendEmail(
        digestEmail,
        `Your Ricorra weekly digest${merchantName ? ' · ' + merchantName : ''}`,
        digestHtml,
        env
      );
    }
  } while (cursor);
}

function buildAnniversaryEmail({ merchantName, planName, label, priceUSD, interval, portalLink }) {
  const intervalStr = interval === 'annual' ? 'year' : 'month';
  return `
    <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
      <div style="text-align:center;margin-bottom:1.5rem;">
        <div style="font-size:48px;margin-bottom:8px;">🎉</div>
        <div style="display:inline-block;width:48px;height:48px;background:#C49A3C;border-radius:50%;
          line-height:48px;text-align:center;font-size:22px;color:#FAF8F4;">₿</div>
      </div>
      <h2 style="font-size:24px;font-weight:500;margin-bottom:0.5rem;text-align:center;font-family:Georgia,serif;">
        ${label} together!
      </h2>
      <p style="color:#6B6860;text-align:center;margin-bottom:1.5rem;font-size:14px;">
        ${planName}${merchantName ? ' · ' + merchantName : ''}
      </p>
      <div style="background:#FAF0D7;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;border:1px solid #D4AA52;text-align:center;">
        <p style="font-size:15px;color:#1C1C1A;line-height:1.7;margin:0;">
          You've been a subscriber for <strong>${label}</strong>. Thank you for your support — it means everything.
        </p>
      </div>
      <div style="background:white;border-radius:12px;padding:1rem 1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;">
        <div style="display:flex;justify-content:space-between;font-size:13px;padding:3px 0;">
          <span style="color:#6B6860;">Your subscription</span>
          <span style="font-weight:600;">${planName} · $${priceUSD.toFixed(2)} / ${intervalStr}</span>
        </div>
      </div>
      ${portalLink ? `
      <div style="text-align:center;margin-bottom:1.5rem;">
        <a href="${portalLink}"
          style="display:inline-block;background:#C49A3C;color:#FAF8F4;text-decoration:none;
          padding:11px 28px;border-radius:50px;font-family:sans-serif;font-size:13px;font-weight:600;">
          View my subscription →
        </a>
      </div>` : ''}
      <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;">
        <a href="https://ricorra.io/account" style="color:#C49A3C;">All my subscriptions →</a> ·
        <a href="https://ricorra.com" style="color:#C49A3C;">ricorra.com</a>
      </p>
    </div>`;
}

function buildDigestEmail({ merchantName, email, activeSubs, overdueSubs, canceledSubs, mrr, week1, revTrend, renewalsDue, topPlan, graceDetails, aiTriage, btcRate }) {
  const trendStr   = revTrend !== null
    ? `<span style="color:${parseFloat(revTrend) >= 0 ? '#2D6A4F' : '#991B1B'};font-weight:700;">${parseFloat(revTrend) >= 0 ? '↑' : '↓'} ${Math.abs(revTrend)}% vs last week</span>`
    : '';
  const btcMRR     = btcRate > 0 ? (mrr / btcRate).toFixed(6) : null;
  const dayName    = new Date().toLocaleDateString('en-US', { weekday:'long', month:'long', day:'numeric' });

  // Build Claude pre-filled prompt
  const claudePrompt = [
    `I run a Bitcoin subscription business called ${merchantName || 'my business'} using Ricorra (ricorra.io).`,
    `This week's numbers: ${activeSubs} active subscribers, $${mrr.toFixed(2)} MRR, $${week1.toFixed(2)} revenue in the last 7 days${revTrend !== null ? ` (${parseFloat(revTrend) >= 0 ? '+' : ''}${revTrend}% vs prior week)` : ''}.`,
    overdueSubs > 0 ? `${overdueSubs} subscriber${overdueSubs !== 1 ? 's are' : ' is'} in the grace period and may cancel.` : '',
    renewalsDue > 0 ? `${renewalsDue} renewal${renewalsDue !== 1 ? 's' : ''} due this week.` : '',
    topPlan ? `My top plan is "${topPlan.name}" at $${topPlan.priceUSD}/mo with ${topPlan.count} subscribers.` : '',
    `What should I focus on this week to protect and grow my revenue?`,
  ].filter(Boolean).join(' ');

  const claudeUrl = `https://claude.ai/new?q=${encodeURIComponent(claudePrompt)}`;

  return `
    <div style="font-family:Georgia,serif;max-width:520px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">

      <!-- Header -->
      <div style="text-align:center;margin-bottom:1.5rem;">
        <div style="display:inline-block;width:44px;height:44px;background:#C49A3C;border-radius:50%;line-height:44px;text-align:center;font-size:20px;color:#FAF8F4;">₿</div>
        <div style="font-size:11px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#6B6860;margin-top:8px;">Weekly Digest</div>
        <div style="font-size:13px;color:#9A9690;margin-top:2px;">${dayName}</div>
      </div>

      ${aiTriage ? `
      <!-- AI Triage -->
      <div style="background:white;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;border-left:4px solid #C49A3C;border:1px solid #E2DDD6;border-left:4px solid #C49A3C;">
        <div style="font-size:10px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#9A9690;margin-bottom:8px;">This week</div>
        <p style="font-size:14px;color:#1C1C1A;line-height:1.7;margin:0;font-style:italic;">"${aiTriage}"</p>
      </div>` : ''}

      <!-- Key metrics -->
      <table style="width:100%;border-collapse:collapse;margin-bottom:1.5rem;">
        <tr>
          <td style="padding:10px 14px;background:white;border:1px solid #E2DDD6;border-radius:8px 0 0 8px;text-align:center;">
            <div style="font-family:Georgia,serif;font-size:26px;font-weight:500;color:#1C1C1A;">$${mrr.toFixed(2)}</div>
            <div style="font-size:10px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#6B6860;margin-top:3px;">MRR</div>
            ${btcMRR ? `<div style="font-size:10px;color:#9A9690;">≈ ${btcMRR} BTC</div>` : ''}
          </td>
          <td style="width:8px;"></td>
          <td style="padding:10px 14px;background:white;border:1px solid #E2DDD6;text-align:center;">
            <div style="font-family:Georgia,serif;font-size:26px;font-weight:500;color:#1C1C1A;">${activeSubs}</div>
            <div style="font-size:10px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#6B6860;margin-top:3px;">Active</div>
          </td>
          <td style="width:8px;"></td>
          <td style="padding:10px 14px;background:white;border:1px solid #E2DDD6;border-radius:0 8px 8px 0;text-align:center;">
            <div style="font-family:Georgia,serif;font-size:26px;font-weight:500;color:#1C1C1A;">$${week1.toFixed(2)}</div>
            <div style="font-size:10px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#6B6860;margin-top:3px;">7-day rev ${trendStr}</div>
          </td>
        </tr>
      </table>

      <!-- Attention needed -->
      ${overdueSubs > 0 || renewalsDue > 0 ? `
      <div style="background:white;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;">
        <div style="font-size:10px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#9A9690;margin-bottom:10px;">Needs attention</div>
        ${overdueSubs > 0 ? `
        <div style="display:flex;justify-content:space-between;font-size:13px;padding:5px 0;border-bottom:1px solid #F2EFE9;">
          <span style="color:#6B6860;">In grace period</span>
          <span style="font-weight:700;color:#D97706;">${overdueSubs} subscriber${overdueSubs !== 1 ? 's' : ''}</span>
        </div>` : ''}
        ${renewalsDue > 0 ? `
        <div style="display:flex;justify-content:space-between;font-size:13px;padding:5px 0;">
          <span style="color:#6B6860;">Renewals due this week</span>
          <span style="font-weight:700;color:#1C1C1A;">${renewalsDue}</span>
        </div>` : ''}
      </div>` : ''}

      <!-- Grace period detail -->
      ${graceDetails.length > 0 ? `
      <div style="background:#FEF3C7;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;border:1px solid #F59E0B;">
        <div style="font-size:10px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#92400E;margin-bottom:10px;">Grace period detail</div>
        ${graceDetails.map(g => `
        <div style="font-size:12px;padding:4px 0;border-bottom:1px solid rgba(245,158,11,0.3);">
          <span style="font-weight:600;">${g.email.split('@')[0]}</span>
          <span style="color:#92400E;"> · ${g.monthsTenure}mo customer · ${g.graceDaysLeft} days left</span>
        </div>`).join('')}
      </div>` : ''}

      <!-- Top plan -->
      ${topPlan ? `
      <div style="background:white;border-radius:12px;padding:1rem 1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;">
        <div style="font-size:10px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#9A9690;margin-bottom:6px;">Top plan</div>
        <div style="font-size:14px;font-weight:600;color:#1C1C1A;">${topPlan.name}</div>
        <div style="font-size:12px;color:#6B6860;">$${topPlan.priceUSD.toFixed(2)} / ${topPlan.interval} · ${topPlan.count} subscriber${topPlan.count !== 1 ? 's' : ''}</div>
      </div>` : ''}

      <!-- Ask Claude -->
      <div style="background:white;border-radius:12px;padding:1rem 1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;text-align:center;">
        <div style="font-size:11px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#9A9690;margin-bottom:8px;">Need help thinking through this?</div>
        <a href="CLAUDE_LINK_PLACEHOLDER"
          style="display:inline-block;background:#1C1C1A;color:#FAF8F4;text-decoration:none;
          padding:10px 24px;border-radius:50px;font-family:sans-serif;font-size:13px;font-weight:600;">
          Ask Claude about my business →
        </a>
        <div style="font-size:10px;color:#9A9690;margin-top:8px;">Opens Claude AI with your weekly stats as context</div>
      </div>

      <!-- Footer -->
      <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.8;">
        <a href="https://ricorra.io" style="color:#C49A3C;font-weight:600;">Open Ricorra →</a><br>
        Ricorra · Subscriptions, self-sovereign.<br>
        <a href="https://ricorra.com" style="color:#9A9690;">ricorra.com</a>
      </p>
    </div>`.replace('CLAUDE_LINK_PLACEHOLDER', claudeUrl);
}

// ═══════════════════════════════════════════════════════
// WALLET WATCHING — Runs every 30 minutes
// Fetches recent txs from Blockstream, matches to subscribers
// by uniquePriceUSD amount, auto-confirms payments
// ═══════════════════════════════════════════════════════

async function runWalletWatch(env) {
  const now    = Date.now();
  const DAY_MS = 24 * 60 * 60 * 1000;

  // Fetch live BTC rate for amount matching
  const btcRate = await fetchBTCRateForCron();
  if (btcRate === 0) return; // can't match without a rate

  // List all merchant sync keys
  let cursor;
  do {
    const list = await env.DB.list({ prefix: 'merchant:', cursor, limit: 100 });
    cursor = list.list_complete ? null : list.cursor;

    for (const key of list.keys) {
      if (!key.name.endsWith(':sync')) continue;

      let syncData;
      try {
        const raw = await env.DB.get(key.name);
        if (!raw) continue;
        syncData = JSON.parse(raw);
      } catch { continue; }

      const email       = key.name.replace('merchant:', '').replace(':sync', '');
      const subscribers = syncData.subscribers || [];
      const plans       = syncData.plans       || [];
      const payments    = syncData.payments    || [];

      if (subscribers.length === 0) continue;

      // Get merchant wallet address
      let walletAddress = '';
      try {
        const w = await env.DB.get(`merchant:${email}:wallet`);
        if (w) walletAddress = JSON.parse(w).address;
      } catch {}
      if (!walletAddress) continue;

      // Fetch recent transactions from Blockstream
      let txs = [];
      try {
        const res = await fetch(
          `https://blockstream.info/api/address/${walletAddress}/txs`,
          { headers: { 'User-Agent': 'Ricorra/1.0' } }
        );
        if (!res.ok) continue;
        txs = await res.json();
      } catch { continue; }

      if (!txs.length) continue;

      // Load already-processed tx IDs to avoid double-matching
      let processedTxs = new Set();
      try {
        const raw = await env.DB.get(`merchant:${email}:processed_txs`);
        if (raw) processedTxs = new Set(JSON.parse(raw));
      } catch {}

      let syncChanged     = false;
      let newProcessedTxs = [...processedTxs];

      for (const tx of txs) {
        if (processedTxs.has(tx.txid)) continue;

        // Only look at confirmed transactions
        if (!tx.status?.confirmed) continue;

        // Get the amount received to our wallet address (in satoshis)
        const received = (tx.vout || [])
          .filter(v => v.scriptpubkey_address === walletAddress)
          .reduce((sum, v) => sum + (v.value || 0), 0);

        if (received === 0) continue;

        const receivedUSD = (received / 100_000_000) * btcRate; // satoshis → BTC → USD
        const txTime      = (tx.status?.block_time || 0) * 1000; // unix → ms

        // Try to match to a subscriber
        for (let i = 0; i < subscribers.length; i++) {
          const sub  = subscribers[i];
          if (sub.status !== 'active' && sub.status !== 'overdue') continue;

          const plan = plans.find(p => p.id === sub.planId);
          if (!plan) continue;

          // Calculate expected unique amount for this subscriber
          const expectedUSD = await getUniqueAmount(plan.priceUSD, plan.shareToken, sub.email);

          // Match if within $0.10 tolerance (covers rate fluctuation)
          const diff = Math.abs(receivedUSD - expectedUSD);
          if (diff > 0.10) continue;

          // Match found! Confirm the payment
          const paymentId = 'pmt-' + tx.txid.slice(0, 8);

          // Avoid logging the same payment twice
          if (payments.find(p => p.id === paymentId)) continue;

          // Log the payment
          const btcAmount = received / 100_000_000;
          payments.push({
            id:           paymentId,
            subscriberId: sub.id,
            planId:       plan.id,
            usd:          expectedUSD,
            btcAmount,
            coin:         'BTC',
            timestamp:    txTime ? new Date(txTime).toISOString() : new Date().toISOString(),
            note:         'Auto-confirmed via blockchain',
            txid:         tx.txid,
          });

          // Update subscriber — reset to active, set next renewal
          const currentRenewal = sub.nextRenewal ? new Date(sub.nextRenewal) : new Date();
          const nextRenewal    = new Date(currentRenewal);
          if (plan.interval === 'annual') {
            nextRenewal.setFullYear(nextRenewal.getFullYear() + 1);
          } else {
            nextRenewal.setMonth(nextRenewal.getMonth() + 1);
          }

          const priorStatus = sub.status; // capture before update

          subscribers[i].status             = 'active';
          subscribers[i].nextRenewal        = nextRenewal.toISOString();
          subscribers[i].gracePeriodStarted = null;
          subscribers[i].payments           = [...(sub.payments || []), paymentId];
          syncChanged = true;

          // Fire payment.confirmed webhook
          await fireWebhook(email, WEBHOOK_EVENTS.PAYMENT_CONFIRMED, {
            subscriberEmail: sub.email,
            planName:   plan.name,
            planId:     plan.id,
            priceUSD:   expectedUSD,
            btcAmount,
            coin:       'BTC',
            txid:       tx.txid,
            nextRenewal: nextRenewal.toISOString(),
          }, env);

          // Fire subscription.reactivated if was canceled, else subscription.renewed
          const lifecycleEvent = priorStatus === 'canceled'
            ? WEBHOOK_EVENTS.SUBSCRIPTION_REACTIVATED
            : WEBHOOK_EVENTS.SUBSCRIPTION_RENEWED;

          await fireWebhook(email, lifecycleEvent, {
            subscriberEmail: sub.email,
            planName:    plan.name,
            planId:      plan.id,
            priceUSD:    expectedUSD,
            interval:    plan.interval,
            nextRenewal: nextRenewal.toISOString(),
            wasOverdue:  priorStatus === 'overdue',
            wasCancel:   priorStatus === 'canceled',
          }, env);

          // Send payment confirmation email
          let merchantName = '';
          try {
            const p = await env.DB.get(`merchant:${email}:profile`);
            if (p) merchantName = JSON.parse(p).displayName || '';
          } catch {}

          await sendEmail(
            sub.email,
            `Payment confirmed — ${plan.name}`,
            buildConfirmationEmail({
              merchantName, planName: plan.name,
              priceUSD: expectedUSD, btcAmount,
              nextRenewal: nextRenewal.toISOString(),
              interval: plan.interval,
            }),
            env
          );

          // Fire email list integration on first payment (new subscriber)
          const isFirstPayment = (sub.payments || []).length === 0;
          if (isFirstPayment) {
            await fireEmailListIntegrations(email, sub.email, 'subscribe', env);
            // Update subscriber index for account page
            try {
              let index = [];
              const idxRaw = await env.DB.get(`subscriber-index:${sub.email}`);
              if (idxRaw) index = JSON.parse(idxRaw);
              const exists = index.some(e => e.merchantEmail === email && e.planId === plan.id);
              if (!exists) {
                index.push({ merchantEmail: email, planId: plan.id, shareToken: plan.shareToken });
                await env.DB.put(`subscriber-index:${sub.email}`, JSON.stringify(index));
              }
            } catch(e) { /* silent */ }
          }

          newProcessedTxs.push(tx.txid);
          break; // One tx matches one subscriber
        }

        newProcessedTxs.push(tx.txid);
      }

      // Save processed tx list (keep last 500 to avoid unbounded growth)
      if (newProcessedTxs.length > processedTxs.size) {
        const trimmed = newProcessedTxs.slice(-500);
        await env.DB.put(
          `merchant:${email}:processed_txs`,
          JSON.stringify(trimmed)
        );
      }

      // Write back sync data if anything changed
      if (syncChanged) {
        await env.DB.put(key.name, JSON.stringify({
          ...syncData,
          subscribers,
          payments,
          pushedAt: new Date().toISOString(),
        }));
      }
    }
  } while (cursor);
}

function buildConfirmationEmail({ merchantName, planName, priceUSD, btcAmount, nextRenewal, interval }) {
  const nextDate    = new Date(nextRenewal).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
  const intervalStr = interval === 'annual' ? 'year' : 'month';
  return `
    <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:2rem;color:#1C1C1A;background:#FAF8F4;">
      <div style="text-align:center;margin-bottom:1.5rem;">
        <div style="display:inline-block;width:48px;height:48px;background:#2D6A4F;border-radius:50%;line-height:48px;text-align:center;font-size:22px;color:white;">✓</div>
      </div>
      <h2 style="font-size:22px;font-weight:500;margin-bottom:0.5rem;text-align:center;">
        Payment confirmed
      </h2>
      <p style="color:#6B6860;text-align:center;margin-bottom:1.5rem;font-size:14px;">
        ${planName}${merchantName ? ' · ' + merchantName : ''}
      </p>
      <div style="background:white;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;border:1px solid #E2DDD6;">
        <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
          <span style="color:#6B6860;">Amount paid</span>
          <span style="font-weight:600;">$${priceUSD.toFixed(2)}</span>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid #E2DDD6;">
          <span style="color:#6B6860;">In Bitcoin</span>
          <span style="font-weight:600;">${btcAmount.toFixed(6)} BTC</span>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;">
          <span style="color:#6B6860;">Next renewal</span>
          <span style="font-weight:600;">${nextDate}</span>
        </div>
      </div>
      <p style="font-size:11px;color:#9A9690;text-align:center;line-height:1.6;">
        Your subscription to ${planName} is active until ${nextDate}.<br>
        <a href="https://ricorra.com" style="color:#C49A3C;">ricorra.com</a>
      </p>
    </div>`;
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      return json({ error: 'Internal server error', detail: err.message }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    const cron = event.cron;
    if (cron === '*/30 * * * *') {
      // Every 30 minutes — wallet watching
      ctx.waitUntil(runWalletWatch(env));
    } else {
      // Daily 9am UTC — renewal reminders + grace period
      ctx.waitUntil(runCron(env));
      // Monday only — AI weekly digest
      const day = new Date().getUTCDay(); // 0=Sun, 1=Mon
      if (day === 1) {
        ctx.waitUntil(runWeeklyDigest(env));
      }
    }
  },
};
