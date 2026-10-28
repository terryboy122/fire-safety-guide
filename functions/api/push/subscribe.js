// Store a Web Push subscription in D1 (public endpoint; stores only the
// push endpoint + keys, no personal data).
export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    const sub = await request.json();
    if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
      return json({ ok: false, error: 'bad subscription' }, 400);
    }
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)'
    ).run();
    await env.DB.prepare(
      'INSERT OR REPLACE INTO push_subscriptions (endpoint, p256dh, auth, created_at) VALUES (?, ?, ?, ?)'
    )
      .bind(sub.endpoint, sub.keys.p256dh, sub.keys.auth, Date.now())
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
