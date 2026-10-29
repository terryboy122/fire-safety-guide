// Admin-only: list cloud backups (R2) — at most the latest 3, newest first,
// each with its date (upload time) and size. Read-only: no download, no
// delete here. Pruning of older files happens in the backup POST endpoint.
// Auth: Authorization: Bearer <admin password>, compared by SHA-256 hash.
export async function onRequestGet(context) {
  const { request, env } = context;
  try {
    if (!(await checkAuth(request, env))) return json({ ok: false, error: 'auth' }, 401);
    if (!env.BACKUPS) return json({ ok: false, error: 'not_configured' }, 500);
    const all = await listAll(env.BACKUPS, 'backup-');
    all.sort((a, b) => b.uploaded - a.uploaded);
    const backups = all.slice(0, 3).map((o) => ({
      key: o.key,
      uploaded: o.uploaded.toISOString(),
      size: o.size,
    }));
    return json({ ok: true, backups });
  } catch (e) {
    return json({ ok: false, error: 'server' }, 500);
  }
}

async function listAll(bucket, prefix) {
  let out = [];
  let cursor;
  do {
    const page = await bucket.list({ prefix, cursor });
    out = out.concat(page.objects || []);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return out;
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
