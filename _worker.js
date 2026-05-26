const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const method = request.method;

  // Preflight
  if (method === 'OPTIONS') {
    return new Response(null, { headers: CORS_HEADERS });
  }

  // ── Routes ──────────────────────────────────────────

  // Health check
  if (method === 'GET' && url.pathname === '/health') {
    return jsonResponse({ status: 'ok', service: 'ricorra-api' });
  }

  // Magic link — request (coming soon)
  // POST /auth/request  { email }

  // Magic link — verify (coming soon)
  // GET  /auth/verify?token=...

  // ── 404 ─────────────────────────────────────────────
  return jsonResponse({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      return jsonResponse({ error: 'Internal server error', detail: err.message }, 500);
    }
  },
};
