// ONE-TIME admin password reset. Deletes the stored admin password hash
// (settings.admin_pass_hash) so the admin page returns to first-run setup.
// TEMPORARY: remove this file immediately after one successful use.
// Requires a one-time token (?token=... or JSON body {token}).
const ONE_TIME_TOKEN = '5Il_hLkTDSZ8cCBfhso4ZLsINqCG5aV6';

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const url = new URL(request.url);
    let token = url.searchParams.get('token') || '';
    if (!token) {
      try {
        const body = await request.json();
        token = body.token || '';
      } catch (e) { /* ignore */ }
    }
    if (token !== ONE_TIME_TOKEN) {
      return json({ ok: false, error: 'not_found' }, 404);
    }
    if (!env.DB) return json({ ok: false, error: 'db' }, 500);
    await env.DB.prepare(
      "DELETE FROM settings WHERE key = 'admin_pass_hash'"
    ).run();
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'admin_pass_hash'"
    ).first();
    return json({ ok: true, deleted: !row, setup_needed: !row });
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
