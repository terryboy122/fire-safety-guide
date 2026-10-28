// Admin password change. Requires the current password in the
// Authorization header and the new password in the body.
export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const body = await request.json();
    const newPassword = body.new_password || '';
    if (newPassword.length < 8 || newPassword.length > 100) {
      return json({ ok: false, error: 'password' }, 400);
    }
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
    ).run();
    const header = request.headers.get('Authorization') || '';
    if (!header.startsWith('Bearer ')) return json({ ok: false, error: 'auth' }, 401);
    const oldPassword = header.slice(7);
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'admin_pass_hash'"
    ).first();
    if (!row) return json({ ok: false, error: 'setup' }, 403);
    if ((await sha256(oldPassword)) !== row.value) {
      return json({ ok: false, error: 'auth' }, 401);
    }
    await env.DB.prepare(
      "UPDATE settings SET value = ? WHERE key = 'admin_pass_hash'"
    ).bind(await sha256(newPassword)).run();
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
