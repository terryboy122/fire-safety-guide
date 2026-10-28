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
      'CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL)'
    ).run();
    await env.DB.prepare(
      'INSERT INTO messages (name, message, created_at) VALUES (?, ?, ?)'
    ).bind(name, message, Date.now()).run();
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
