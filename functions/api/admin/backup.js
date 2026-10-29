// Admin-only cloud backup: dump messages, push subscriptions and the
// push dedup table from D1 into the bound R2 bucket (env.BACKUPS) as a
// timestamped JSON file. Old backups are never overwritten.
// Auth: Authorization: Bearer <admin password>, compared by SHA-256 hash.
export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    if (!(await checkAuth(request, env))) return json({ ok: false, error: 'auth' }, 401);
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    if (!env.BACKUPS) return json({ ok: false, error: 'not_configured' }, 500);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL, site TEXT NOT NULL DEFAULT \'fire-safety-guide\')'
    ).run();
    // Unified-admin migration: older tables lack the site column.
    try {
      await env.DB.prepare(
        "ALTER TABLE messages ADD COLUMN site TEXT NOT NULL DEFAULT 'fire-safety-guide'"
      ).run();
    } catch (e) { /* column already exists */ }
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)'
    ).run();
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS push_sent (sha TEXT PRIMARY KEY, sent_at INTEGER NOT NULL)'
    ).run();
    const msgs = await env.DB.prepare(
      'SELECT id, site, name, message, created_at FROM messages ORDER BY created_at ASC'
    ).all();
    const subs = await env.DB.prepare(
      'SELECT endpoint, p256dh, auth, created_at FROM push_subscriptions ORDER BY created_at ASC'
    ).all();
    const sent = await env.DB.prepare(
      'SELECT sha, sent_at FROM push_sent ORDER BY sent_at ASC'
    ).all();
    const data = {
      exported_at: Date.now(),
      site: 'fire-safety-guide',
      messages: msgs.results || [],
      push_subscriptions: subs.results || [],
      push_sent: sent.results || [],
    };
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const key = 'backup-' + stamp + '.json';
    await env.BACKUPS.put(key, JSON.stringify(data), {
      httpMetadata: { contentType: 'application/json' },
    });
    // Keep only the latest 3 backups; delete older files. A pruning
    // failure must not fail the backup itself.
    let deleted = 0;
    try {
      const all = await listAll(env.BACKUPS, 'backup-');
      all.sort((a, b) => b.uploaded - a.uploaded);
      for (const o of all.slice(3)) {
        await env.BACKUPS.delete(o.key);
        deleted++;
      }
    } catch (e) { /* keep the new backup even if pruning fails */ }
    return json({
      ok: true,
      key,
      deleted,
      counts: {
        messages: data.messages.length,
        subscriptions: data.push_subscriptions.length,
        sent: data.push_sent.length,
      },
    });
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
