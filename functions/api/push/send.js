// Send a push notification to all subscribers.
// Auth model (no shared secret needed): the caller posts a commit SHA from
// this repo's main branch plus a title that literally appears in the current
// index.html. The endpoint verifies the commit exists on main, refuses to
// send the same commit twice, and only then broadcasts. Only someone who can
// push to the repo can trigger a send.
// Body: { commit_sha, title, body, url? }
// Env: VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY (Cloudflare Pages secrets).
import { sendWebPush } from '../../_lib/webpush.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    const { commit_sha, title, body, url } = await request.json();
    if (!commit_sha || !title || !body) {
      return json({ ok: false, error: 'commit_sha, title and body required' }, 400);
    }
    // 1. Commit must exist on main.
    const commitRes = await fetch(
      'https://api.github.com/repos/terryboy122/fire-safety-guide/commits/' + commit_sha,
      {
        headers: {
          'User-Agent': 'fire-safety-guide-push',
          Accept: 'application/vnd.github+json',
        },
      }
    );
    if (!commitRes.ok) return json({ ok: false, error: 'unknown commit' }, 400);
    // 2. Dedup: never send the same commit twice.
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS push_sent (sha TEXT PRIMARY KEY, sent_at INTEGER NOT NULL)'
    ).run();
    const already = await env.DB.prepare('SELECT sha FROM push_sent WHERE sha = ?')
      .bind(commit_sha)
      .first();
    if (already) return json({ ok: true, already_sent: true, sent: 0, failed: 0 });
    // 3. Title must literally appear in the current index.html (ties the push
    // to real page content).
    const pageRes = await fetch(
      'https://raw.githubusercontent.com/terryboy122/fire-safety-guide/main/index.html'
    );
    if (!pageRes.ok) return json({ ok: false, error: 'page fetch failed' }, 500);
    const page = await pageRes.text();
    if (!page.includes(title)) {
      return json({ ok: false, error: 'title not found in current page' }, 400);
    }
    // 4. VAPID keys must be configured.
    const vapidPublic = env.VAPID_PUBLIC_KEY;
    const vapidPrivate = env.VAPID_PRIVATE_KEY;
    if (!vapidPublic || !vapidPrivate) {
      return json({ ok: false, error: 'push not configured' }, 500);
    }
    // 5. Broadcast.
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)'
    ).run();
    const subs = await env.DB.prepare(
      'SELECT endpoint, p256dh, auth FROM push_subscriptions'
    ).all();
    const list = subs.results || [];
    let sent = 0;
    let failed = 0;
    for (const s of list) {
      const r = await sendWebPush({
        endpoint: s.endpoint,
        p256dh: s.p256dh,
        auth: s.auth,
        payload: { title, body, url: url || '/' },
        vapidPublic,
        vapidPrivate,
      });
      if (r === 'ok') sent++;
      else {
        failed++;
        if (r === 'gone') {
          await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?')
            .bind(s.endpoint)
            .run();
        }
      }
    }
    await env.DB.prepare('INSERT INTO push_sent (sha, sent_at) VALUES (?, ?)')
      .bind(commit_sha, Date.now())
      .run();
    return json({ ok: true, sent, failed, total: list.length });
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
