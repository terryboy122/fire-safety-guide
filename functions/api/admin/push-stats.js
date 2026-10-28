// Admin-only push subscription count (GET).
// Auth: Authorization: Bearer <admin password>, compared by SHA-256 hash.
export async function onRequestGet(context) {
  const { request, env } = context;
  try {
    if (!(await checkAuth(request, env))) return json({ ok: false, error: 'auth' }, 401);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)'
    ).run();
    const row = await env.DB.prepare(
      'SELECT COUNT(*) AS c FROM push_subscriptions'
    ).first();
    return json({ ok: true, count: (row && row.c) || 0 });
  } catch (e) {
    return json({ ok: false, error: 'server' }, 500);
  }
}

async function checkAuth(request, env) {
  if (!env.DB) return false;
  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Bearer ')) return false;
  const password = header.slice(7);
  if (!password) return false;
  await env.DB.prepare(
    'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
  ).run();
  const row = await env.DB.prepare(
    "SELECT value FROM settings WHERE key = 'admin_pass_hash'"
  ).first();
  if (!row) return false;
  const hash = await sha256(password);
  return hash === row.value;
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
