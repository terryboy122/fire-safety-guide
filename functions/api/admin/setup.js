// First-run admin password setup. Only works when no password exists yet.
// The password is stored only as a SHA-256 hash, never in plain text.
export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const body = await request.json();
    const password = body.password || '';
    if (password.length < 8 || password.length > 100) {
      return json({ ok: false, error: 'password' }, 400);
    }
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
    ).run();
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'admin_pass_hash'"
    ).first();
    if (row) return json({ ok: false, error: 'already' }, 403);
    const hash = await sha256(password);
    await env.DB.prepare(
      "INSERT INTO settings (key, value) VALUES ('admin_pass_hash', ?)"
    ).bind(hash).run();
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: 'server' }, 500);
  }
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
