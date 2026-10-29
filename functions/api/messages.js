// Public message submission for the fire-safety page contact board.
// Messages are stored in D1 and are only readable via the password-protected admin API.
export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const body = await request.json();
    const name = (body.name || '').trim();
    const message = (body.message || '').trim();
    const honeypot = (body.website || '').trim();
    if (honeypot) return json({ ok: false, error: 'spam' }, 400);
    if (!name || name.length > 50) return json({ ok: false, error: 'name' }, 400);
    if (!message || message.length > 2000) return json({ ok: false, error: 'message' }, 400);
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL, site TEXT NOT NULL DEFAULT \'fire-safety-guide\')'
    ).run();
    // Unified-admin migration: older tables lack the site column.
    // Fails silently when the column already exists.
    try {
      await env.DB.prepare(
        "ALTER TABLE messages ADD COLUMN site TEXT NOT NULL DEFAULT 'fire-safety-guide'"
      ).run();
    } catch (e) { /* column already exists */ }
    // Rate limit: same IP at most 1 successful post per 60 seconds.
    // Only successful posts update the timestamp, so failed validation
    // attempts do not consume the budget.
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS msg_rate (ip TEXT PRIMARY KEY, last_at INTEGER NOT NULL)'
    ).run();
    const last = await env.DB.prepare(
      'SELECT last_at FROM msg_rate WHERE ip = ?'
    ).bind(ip).first();
    if (last && Date.now() - last.last_at < 60000) {
      return json({ ok: false, error: 'too_fast' }, 429);
    }
    await env.DB.prepare(
      'INSERT INTO messages (name, message, created_at, site) VALUES (?, ?, ?, ?)'
    ).bind(name, message, Date.now(), 'fire-safety-guide').run();
    await env.DB.prepare(
      'INSERT OR REPLACE INTO msg_rate (ip, last_at) VALUES (?, ?)'
    ).bind(ip, Date.now()).run();
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: 'server' }, 500);
  }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
