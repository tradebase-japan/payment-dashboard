/**
 * Zaim OAuth 1.0a Worker for Cloudflare Workers
 *
 * 環境変数（Cloudflare Dashboardで設定）:
 *   CONSUMER_KEY     - Zaim コンシューマ ID
 *   CONSUMER_SECRET  - Zaim コンシューマシークレット
 *
 * KV Namespace バインディング:
 *   ZAIM_KV          - アクセストークン保管用
 */

const ZAIM_BASE      = 'https://api.zaim.net/v2';
const REQ_TOKEN_URL  = 'https://api.zaim.net/v2/auth/request';
const AUTHORIZE_URL  = 'https://auth.zaim.net/users/auth';
const ACC_TOKEN_URL  = 'https://api.zaim.net/v2/auth/access';

export default {
  async fetch(request, env) {
    const url        = new URL(request.url);
    const workerBase = `${url.protocol}//${url.host}`;

    if (request.method === 'OPTIONS') return cors(null, 204);

    switch (url.pathname) {
      case '/auth':          return handleAuth(env, workerBase);
      case '/callback':      return handleCallback(request, env);
      case '/api/status':    return handleStatus(env);
      case '/api/accounts':  return handleAccounts(env);
      case '/api/money':     return handleMoney(request, env);
      default:               return cors({ error: 'Not found' }, 404);
    }
  },
};

// ─── OAuth 1.0a ────────────────────────────────────────────────

async function hmacSha1(message, key) {
  const enc = new TextEncoder();
  const k   = await crypto.subtle.importKey(
    'raw', enc.encode(key),
    { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

const pct = s => encodeURIComponent(String(s ?? ''));

async function oauthHeader(method, url, extra, env, tokenSecret = '') {
  const p = {
    oauth_consumer_key:     env.CONSUMER_KEY,
    oauth_nonce:            Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp:        String(Math.floor(Date.now() / 1000)),
    oauth_version:          '1.0',
    ...extra,
  };

  const sorted = Object.entries(p)
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([k, v]) => `${pct(k)}=${pct(v)}`)
    .join('&');

  const base = `${method}&${pct(url)}&${pct(sorted)}`;
  const key  = `${pct(env.CONSUMER_SECRET)}&${pct(tokenSecret)}`;

  p.oauth_signature = await hmacSha1(base, key);

  return 'OAuth ' + Object.entries(p)
    .map(([k, v]) => `${k}="${pct(v)}"`)
    .join(', ');
}

// ─── STEP 1: OAuth 開始 (/auth) ────────────────────────────────

async function handleAuth(env, workerBase) {
  const callbackUrl = `${workerBase}/callback`;
  const header      = await oauthHeader('POST', REQ_TOKEN_URL, { oauth_callback: callbackUrl }, env);

  const res  = await fetch(REQ_TOKEN_URL, { method: 'POST', headers: { Authorization: header } });
  const text = await res.text();
  const p    = new URLSearchParams(text);

  const reqToken  = p.get('oauth_token');
  const reqSecret = p.get('oauth_token_secret');

  if (!reqToken) {
    return cors({ error: 'リクエストトークンの取得に失敗', detail: text }, 500);
  }

  await env.ZAIM_KV.put('req_token',  reqToken);
  await env.ZAIM_KV.put('req_secret', reqSecret);

  return Response.redirect(`${AUTHORIZE_URL}?oauth_token=${reqToken}`, 302);
}

// ─── STEP 2: OAuth コールバック (/callback) ───────────────────

async function handleCallback(request, env) {
  const u        = new URL(request.url);
  const token    = u.searchParams.get('oauth_token');
  const verifier = u.searchParams.get('oauth_verifier');

  if (!token || !verifier) {
    return new Response('認証パラメータが不足しています', { status: 400 });
  }

  const reqSecret = (await env.ZAIM_KV.get('req_secret')) || '';
  const header    = await oauthHeader(
    'POST', ACC_TOKEN_URL,
    { oauth_token: token, oauth_verifier: verifier },
    env, reqSecret
  );

  const res  = await fetch(ACC_TOKEN_URL, { method: 'POST', headers: { Authorization: header } });
  const text = await res.text();
  const p    = new URLSearchParams(text);

  const accToken  = p.get('oauth_token');
  const accSecret = p.get('oauth_token_secret');

  if (!accToken) {
    return new Response(`アクセストークン取得失敗: ${text}`, { status: 500 });
  }

  await env.ZAIM_KV.put('access_token',  accToken);
  await env.ZAIM_KV.put('access_secret', accSecret);

  return new Response(`
    <!DOCTYPE html>
    <html lang="ja">
    <head><meta charset="UTF-8"><title>Zaim連携完了</title></head>
    <body style="font-family:sans-serif;text-align:center;padding:60px;background:#f0fdf4">
      <div style="font-size:3rem">✅</div>
      <h2 style="color:#16a34a">Zaim連携が完了しました！</h2>
      <p style="color:#555">このページを閉じてダッシュボードを開いてください。</p>
    </body>
    </html>
  `, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

// ─── API: 連携状態確認 (/api/status) ──────────────────────────

async function handleStatus(env) {
  const token = await env.ZAIM_KV.get('access_token');
  return cors({ connected: !!token });
}

// ─── API: 口座残高一覧 (/api/accounts) ────────────────────────

async function handleAccounts(env) {
  const { token, secret } = await getTokens(env);
  if (!token) return cors({ error: '未認証。/auth にアクセスしてください。' }, 401);

  const apiUrl = `${ZAIM_BASE}/home/account`;
  const header = await oauthHeader('GET', apiUrl, { oauth_token: token }, env, secret);

  const res  = await fetch(apiUrl, { headers: { Authorization: header } });
  const data = await res.json();
  return cors(data);
}

// ─── API: 明細一覧 (/api/money?month=2026-04) ─────────────────

async function handleMoney(request, env) {
  const { token, secret } = await getTokens(env);
  if (!token) return cors({ error: '未認証。/auth にアクセスしてください。' }, 401);

  const u     = new URL(request.url);
  const month = u.searchParams.get('month') || new Date().toISOString().slice(0, 7);
  const [y, m] = month.split('-');
  const lastDay = new Date(Number(y), Number(m), 0).getDate();

  const apiUrl = `${ZAIM_BASE}/home/money?mapping=1&start_date=${y}-${m}-01&end_date=${y}-${m}-${lastDay}`;
  const header = await oauthHeader('GET', apiUrl, { oauth_token: token }, env, secret);

  const res  = await fetch(apiUrl, { headers: { Authorization: header } });
  const data = await res.json();
  return cors(data);
}

// ─── ヘルパー ──────────────────────────────────────────────────

async function getTokens(env) {
  const token  = await env.ZAIM_KV.get('access_token');
  const secret = await env.ZAIM_KV.get('access_secret');
  return { token, secret };
}

function cors(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type':                'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
    },
  });
}
