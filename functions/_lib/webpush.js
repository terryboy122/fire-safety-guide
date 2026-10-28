// Minimal Web Push sender (RFC 8030, aes128gcm) using Web Crypto.
// No dependencies. Returns 'ok', 'gone' (410/404: delete the subscription)
// or 'fail'.

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function u16be(n) {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

async function hmacSha256(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

async function importEcPublic(raw65) {
  const x = b64urlEncode(raw65.slice(1, 33));
  const y = b64urlEncode(raw65.slice(33, 65));
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x, y, ext: true },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );
}

async function vapidAuthHeader(endpoint, vapidPublicB64, vapidPrivateB64) {
  const aud = new URL(endpoint).origin;
  const exp = Math.floor(Date.now() / 1000) + 12 * 3600;
  const header = b64urlEncode(
    new TextEncoder().encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' }))
  );
  const payload = b64urlEncode(
    new TextEncoder().encode(
      JSON.stringify({ aud, exp, sub: 'https://fire-safety-guide.pages.dev/' })
    )
  );
  const signingInput = new TextEncoder().encode(header + '.' + payload);
  const pub = b64urlDecode(vapidPublicB64);
  const key = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      x: b64urlEncode(pub.slice(1, 33)),
      y: b64urlEncode(pub.slice(33, 65)),
      d: vapidPrivateB64,
      ext: true,
    },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, signingInput);
  return 'vapid t=' + header + '.' + payload + '.' + b64urlEncode(sig) + ', k=' + vapidPublicB64;
}

async function encryptPayload(sub, plaintext) {
  const uaPublic = b64urlDecode(sub.p256dh);
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const uaKey = await importEcPublic(uaPublic);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, ephemeral.privateKey, 256)
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // HKDF-Extract: PRK = HMAC(salt, shared secret)
  const prk = await hmacSha256(salt, shared);
  // HKDF-Expand (first block is enough for 16/12-byte outputs)
  const context = concat(
    new Uint8Array([0]),
    u16be(uaPublic.length),
    uaPublic,
    u16be(asPublic.length),
    asPublic
  );
  const cekInfo = concat(
    new TextEncoder().encode('Content-Encoding: aes128gcm'),
    new Uint8Array([0]),
    context
  );
  const nonceInfo = concat(
    new TextEncoder().encode('Content-Encoding: nonce'),
    new Uint8Array([0]),
    context
  );
  const cek = (await hmacSha256(prk, concat(cekInfo, new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmacSha256(prk, concat(nonceInfo, new Uint8Array([1])))).slice(0, 12);
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const data = concat(new TextEncoder().encode(plaintext), new Uint8Array([2]));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cekKey, data)
  );
  const rs = new Uint8Array([0, 0, 0x10, 0x00]); // record size 4096
  const body = concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ciphertext);
  return { body, salt, asPublic };
}

export async function sendWebPush({ endpoint, p256dh, auth, payload, vapidPublic, vapidPrivate }) {
  try {
    const { body, salt, asPublic } = await encryptPayload(
      { p256dh, auth },
      JSON.stringify(payload)
    );
    const authHeader = await vapidAuthHeader(endpoint, vapidPublic, vapidPrivate);
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Encoding': 'aes128gcm',
        Encryption: 'salt=' + b64urlEncode(salt),
        'Crypto-Key': 'dh=' + b64urlEncode(asPublic),
        Authorization: authHeader,
        TTL: '86400',
        'Content-Type': 'application/octet-stream',
      },
      body,
    });
    if (res.status === 404 || res.status === 410) return { status: 'gone', detail: '' };
    if (res.ok) return { status: 'ok', detail: '' };
    let detail = '';
    try {
      detail = (await res.text()).slice(0, 200);
    } catch (_) {
      detail = '';
    }
    return { status: 'fail', detail: 'http ' + res.status + ' ' + detail };
  } catch (e) {
    return { status: 'fail', detail: 'exception ' + String((e && e.message) || e).slice(0, 200) };
  }
}
