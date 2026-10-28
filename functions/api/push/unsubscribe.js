// Remove a Web Push subscription from D1.
export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    const body = await request.json();
    if (!body || !body.endpoint) return json({ ok: false, error: 'endpoint' }, 400);
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)'
    ).run();
    await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?')
      .bind(body.endpoint)
      .run();
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
