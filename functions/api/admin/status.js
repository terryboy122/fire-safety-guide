// Tells the admin page whether an admin password has been set yet.
// Reveals nothing else.
export async function onRequestGet(context) {
  const { env } = context;
  try {
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
    ).run();
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'admin_pass_hash'"
    ).first();
    return json({ ok: true, setup_needed: !row });
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
