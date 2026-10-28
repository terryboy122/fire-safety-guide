// Admin-only message list (GET) and delete (DELETE).
// Auth: Authorization: Bearer <admin password>, compared by SHA-256 hash.
export async function onRequestGet(context) {
  const { request, env } = context;
  try {
    if (!(await checkAuth(request, env))) return json({ ok: false, error: 'auth' }, 401);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL)'
    ).run();
    const res = await env.DB.prepare(
      'SELECT id, name, message, created_at FROM messages ORDER BY created_at DESC LIMIT 200'
    ).all();
    const st = await env.DB.prepare(
      'SELECT COUNT(*) AS c, COALESCE(SUM(LENGTH(CAST(name AS BLOB)) + LENGTH(CAST(message AS BLOB))), 0) AS b FROM messages'
    ).first();
    return json({ ok: true, messages: res.results || [], stats: { count: (st && st.c) || 0, bytes: (st && st.b) || 0 } });
  } catch (e) {
    return json({ ok: false, error: 'server' }, 500);
  }
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  try {
    if (!(await checkAuth(request, env))) return json({ ok: false, error: 'auth' }, 401);
    const url = new URL(request.url);
    const id = parseInt(url.searchParams.get('id') || '', 10);
    if (!id) return json({ ok: false, error: 'id' }, 400);
    await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(id).run();
    return json({ ok: true });
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
