/**
 * AKxST Meta Connector — Cloudflare Worker + D1
 * OAuth v1: Facebook Page discovery and encrypted Page token storage.
 * Authentication: Cloudflare Access (verified by Cloudflare via ctx.access).
 * IMPORTANT: Protect the entire Worker with a Cloudflare Access policy.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const COOKIE_NAME = '__Host-akxst_meta_nonce';
const ROLE_ORDER = { viewer: 0, editor: 1, admin: 2, owner: 3 };
const SCOPES = ['pages_show_list', 'pages_read_engagement', 'pages_manage_posts', 'read_insights'];

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' }
  });
}
function html(markup, status = 200) {
  return new Response(markup, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; script-src 'sha256-qfGC84YuLdDr4GeQqliA6BkC5uVWWeqWoD29f1gx3U8='; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'", 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' }
  });
}
function redirect(url, cookie) {
  const headers = new Headers({ location: url, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
  if (cookie) headers.set('set-cookie', cookie);
  return new Response(null, { status: 302, headers });
}
function error(status, message) { return json({ error: message }, status); }
function isoNow() { return new Date().toISOString(); }
function randomString(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return toBase64Url(data);
}
function toBase64Url(bytes) {
  let binary = ''; for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function fromBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
async function sha256(value) {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}
async function encrypt(value, env) {
  if (!env.TOKEN_ENCRYPTION_KEY || env.TOKEN_ENCRYPTION_KEY.length < 32) throw new Error('TOKEN_ENCRYPTION_KEY must be >=32 random characters');
  const rawKey = await crypto.subtle.digest('SHA-256', encoder.encode(env.TOKEN_ENCRYPTION_KEY));
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(value)));
  return `${toBase64Url(iv)}.${toBase64Url(encrypted)}`;
}
function getCookie(request, key) {
  const entry = (request.headers.get('cookie') || '').split(';').map(s => s.trim()).find(x => x.startsWith(key + '='));
  return entry ? entry.slice(key.length + 1) : null;
}
function clearCookie() { return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`; }
function csrfSafe(request, env) {
  // API writes require JSON and a matching browser Origin, not just an Access session.
  if (request.method === 'GET' || request.method === 'HEAD') return true;
  const origin = request.headers.get('origin');
  const expected = env.PUBLIC_BASE_URL && new URL(env.PUBLIC_BASE_URL).origin;
  return !!expected && origin === expected && (request.headers.get('content-type') || '').toLowerCase().startsWith('application/json');
}
function normalizedBaseUrl(env) {
  if (!env.PUBLIC_BASE_URL) throw new Error('Set PUBLIC_BASE_URL to your deployed HTTPS Worker origin');
  const url = new URL(env.PUBLIC_BASE_URL);
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new Error('PUBLIC_BASE_URL must be HTTPS origin only');
  return url.origin;
}
function configReady(env) {
  return !!(env.DB && env.META_APP_ID && env.META_APP_SECRET && env.TOKEN_ENCRYPTION_KEY && env.ADMIN_EMAIL && env.PUBLIC_BASE_URL);
}
async function accessUser(ctx) {
  // ctx.access exists only for requests authenticated by Cloudflare Access.
  if (!ctx?.access) return null;
  const identity = await ctx.access.getIdentity();
  const email = typeof identity?.email === 'string' ? identity.email.trim().toLowerCase() : '';
  return email.includes('@') ? email : null;
}
async function getRole(db, workspaceId, email) {
  const membership = await db.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND email = ?').bind(workspaceId, email).first();
  return membership?.role || null;
}
async function requireRole(db, workspaceId, email, minRole = 'viewer') {
  const role = await getRole(db, workspaceId, email);
  if (!role || ROLE_ORDER[role] < ROLE_ORDER[minRole]) return null;
  return role;
}
function isAgencyAdmin(email, env) { return email === (env.ADMIN_EMAIL || '').trim().toLowerCase(); }
async function bodyJson(request) {
  if (Number(request.headers.get('content-length') || 0) > 8192) throw new Error('Body too large');
  const raw = await request.text();
  if (raw.length > 8192) throw new Error('Body too large');
  return JSON.parse(raw);
}
async function metaGet(path, params, env) {
  const url = new URL(`https://graph.facebook.com/${env.META_API_VERSION || 'v27.0'}/${path.replace(/^\//, '')}`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, String(value));
  const response = await fetch(url.toString(), { method: 'GET', headers: { accept: 'application/json' }, redirect: 'error' });
  const payload = await response.json();
  if (!response.ok || payload.error) {
    const code = payload?.error?.code || response.status;
    throw new Error(`Meta Graph API error (${code}). Check permissions, account role and OAuth setup.`);
  }
  return payload;
}
async function tokenExchange(code, env) {
  const redirectUri = `${normalizedBaseUrl(env)}/auth/meta/callback`;
  const token = await metaGet('oauth/access_token', { client_id: env.META_APP_ID, client_secret: env.META_APP_SECRET, redirect_uri: redirectUri, code }, env);
  if (!token.access_token) throw new Error('Meta did not return a user access token');
  // Optional best-effort long-lived user token exchange. We only persist Page tokens.
  try {
    const longLived = await metaGet('oauth/access_token', { grant_type: 'fb_exchange_token', client_id: env.META_APP_ID, client_secret: env.META_APP_SECRET, fb_exchange_token: token.access_token }, env);
    return longLived.access_token || token.access_token;
  } catch { return token.access_token; }
}
async function getPages(userToken, env) {
  const pages = [];
  let cursor = null;
  for (let batch = 0; batch < 5; batch++) {
    const params = { fields: 'id,name,access_token,tasks', limit: '100', access_token: userToken };
    if (cursor) params.after = cursor;
    const response = await metaGet('me/accounts', params, env);
    if (!Array.isArray(response.data)) throw new Error('Unexpected Meta Pages response');
    pages.push(...response.data.filter(p => p?.id && p?.access_token));
    const next = response.paging?.cursors?.after;
    if (!response.paging?.next || !next || next === cursor) break;
    cursor = next;
  }
  return pages;
}
function callbackPage(success, message) {
  const title = success ? 'Facebook Pages connected' : 'Meta connection unsuccessful';
  const safeMessage = String(message).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} - AKxST</title><body style="font:16px system-ui;max-width:600px;margin:12vh auto;padding:20px"><h1>${title}</h1><p>${safeMessage}</p><p><a href="/">Return to AKxST Connector</a></p></body></html>`;
}
async function startOAuth(request, env, user) {
  const url = new URL(request.url);
  const workspaceId = url.searchParams.get('workspace_id');
  if (!workspaceId || !await requireRole(env.DB, workspaceId, user, 'admin')) return error(403, 'Workspace admin access required');
  const state = randomString(32);
  const nonce = randomString(32);
  await env.DB.prepare('INSERT INTO oauth_states (id_hash,nonce_hash,workspace_id,email,expires_at) VALUES (?,?,?,?,?)')
    .bind(await sha256(state), await sha256(nonce), workspaceId, user, Math.floor(Date.now() / 1000) + 600).run();
  const auth = new URL(`https://www.facebook.com/${env.META_API_VERSION || 'v27.0'}/dialog/oauth`);
  auth.searchParams.set('client_id', env.META_APP_ID);
  auth.searchParams.set('redirect_uri', `${normalizedBaseUrl(env)}/auth/meta/callback`);
  auth.searchParams.set('state', state);
  auth.searchParams.set('response_type', 'code');
  if (env.META_LOGIN_CONFIG_ID) {
    auth.searchParams.set('config_id', env.META_LOGIN_CONFIG_ID);
    auth.searchParams.set('override_default_response_type', 'true');
  } else {
    auth.searchParams.set('scope', SCOPES.join(','));
  }
  return redirect(auth.toString(), `${COOKIE_NAME}=${nonce}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);
}
async function metaCallback(request, env, user) {
  const url = new URL(request.url);
  const state = url.searchParams.get('state');
  const nonce = getCookie(request, COOKIE_NAME);
  if (!state || !nonce || state.length > 128 || nonce.length > 128) return html(callbackPage(false, 'Authorization session expired. Start again from your workspace.'), 400);
  const idHash = await sha256(state);
  const stateRow = await env.DB.prepare('SELECT * FROM oauth_states WHERE id_hash=?').bind(idHash).first();
  if (!stateRow || stateRow.used_at || stateRow.expires_at < Date.now() / 1000 || stateRow.nonce_hash !== await sha256(nonce) || stateRow.email !== user) {
    return html(callbackPage(false, 'OAuth state invalid, expired, or associated with another user.'), 403);
  }
  const consume = await env.DB.prepare('UPDATE oauth_states SET used_at=? WHERE id_hash=? AND used_at IS NULL').bind(Math.floor(Date.now() / 1000), idHash).run();
  if ((consume.meta?.changes || 0) !== 1) return html(callbackPage(false, 'OAuth state has already been used.'), 403);
  if (!await requireRole(env.DB, stateRow.workspace_id, user, 'admin')) return html(callbackPage(false, 'Workspace access is no longer valid.'), 403);
  const cookie = clearCookie();
  if (url.searchParams.get('error')) {
    return new Response(callbackPage(false, 'Permission request was declined or cancelled.'), { status: 400, headers: { 'content-type': 'text/html; charset=utf-8', 'set-cookie': cookie, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });
  }
  const code = url.searchParams.get('code');
  if (!code || code.length > 8192) return html(callbackPage(false, 'Meta did not return a valid authorization code.'), 400);
  try {
    const userToken = await tokenExchange(code, env);
    const pages = await getPages(userToken, env);
    for (const page of pages) {
      const cipher = await encrypt(page.access_token, env);
      await env.DB.prepare(`INSERT INTO social_connections (id,workspace_id,provider,page_id,page_name,encrypted_page_token,page_tasks,connected_by)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(workspace_id,provider,page_id) DO UPDATE SET
          page_name=excluded.page_name, encrypted_page_token=excluded.encrypted_page_token,
          page_tasks=excluded.page_tasks, connected_by=excluded.connected_by, updated_at=CURRENT_TIMESTAMP`)
        .bind(crypto.randomUUID(), stateRow.workspace_id, 'facebook', String(page.id), String(page.name || ''), cipher, JSON.stringify(page.tasks || []), user).run();
    }
    const note = pages.length ? `Connected ${pages.length} Facebook Page(s) to your selected workspace.` : 'Login succeeded, but Meta returned no Pages. Confirm Page permissions and roles.';
    return new Response(callbackPage(!!pages.length, note), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'set-cookie': cookie, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'" } });
  } catch (e) {
    // Never return raw Meta API responses or tokens to the browser.
    console.error('Meta OAuth connection failed:', e.message);
    return new Response(callbackPage(false, e.message.startsWith('Meta Graph API error') ? e.message : 'OAuth connection failed. Check Worker logs and Meta app configuration.'), { status: 502, headers: { 'content-type': 'text/html; charset=utf-8', 'set-cookie': cookie, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });
  }
}

const HOME = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AKxST Meta Connector</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,Arial;color:#f7f7fb;background:#0c101a}*{box-sizing:border-box}body{max-width:880px;margin:6vh auto;padding:0 20px}.eyebrow{font-size:12px;letter-spacing:2px;color:#9ebaff;font-weight:700}.head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{font-size:clamp(28px,5vw,44px);letter-spacing:-1.5px;margin:10px 0}p{color:#aab5c8;line-height:1.6}.panel{border:1px solid #28324a;background:#141c2c;border-radius:16px;padding:22px;margin:22px 0}.line{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;border-bottom:1px solid #2b354a;padding:16px 0}.line:last-child{border:0}.small{color:#aab5c8;font-size:13px}.muted{color:#8190aa}button,.btn{border:0;border-radius:9px;background:#a6c2ff;color:#0b1424;font-weight:700;padding:11px 17px;cursor:pointer;text-decoration:none;display:inline-block}button:disabled{opacity:.5;cursor:default}input{background:#0a101b;border:1px solid #3b4562;color:white;border-radius:8px;padding:10px;min-width:200px}.danger{background:#3c2631;color:#ffbec9}.note{padding:14px;border-radius:10px;background:#202b40;color:#d5e2f7}#message{white-space:pre-wrap;color:#ffbdc8}.spacer{height:12px}
</style></head><body><div class="eyebrow">AKxST ADVERTISING · PRIVATE CONNECTOR</div><div class="head"><h1>Meta Connections</h1><span id="who" class="small"></span></div><p>Connect Facebook Pages to isolated client workspaces. Access is protected by your Cloudflare account policy. Tokens are encrypted in the backend.</p><div class="panel"><h2>Workspaces</h2><div id="workspaces">Loading…</div><div class="spacer"></div><form id="addWorkspace" style="display:none"><input id="name" maxlength="80" placeholder="Workspace name" required> <button>Create workspace</button></form></div><div class="panel"><strong>OAuth Redirect URL</strong><p class="small" id="redirect">Loading…</p><div class="note">Add this exact URI in Meta Developers → Facebook Login for Business → Valid OAuth Redirect URIs. Clients need App Review / required access before connecting non-role accounts.</div></div><div id="message" role="status"></div>
<script>
const $=id=>document.getElementById(id);
async function api(path, opts){const response=await fetch(path,{credentials:'same-origin',...opts});const data=await response.json();if(!response.ok)throw new Error(data.error||'Request failed');return data}
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text)n.textContent=text;return n}
async function load(){try{const me=await api('/api/me');$('who').textContent=me.email;$('addWorkspace').style.display=me.isAgencyAdmin?'block':'none';$('redirect').textContent=me.redirectUri||'Not configured';const data=await api('/api/workspaces');$('workspaces').replaceChildren();if(!data.workspaces.length){$('workspaces').append(el('p','muted','No assigned workspaces yet.'));return}for(const w of data.workspaces){const wrap=el('div','line');const left=el('div');left.append(el('strong','',w.name),el('div','small','Role: '+w.role));const right=el('div');const more=el('div','small','Loading connections…');left.append(more);wrap.append(left,right);$('workspaces').append(wrap);if(['owner','admin'].includes(w.role)){const a=el('a','btn','Connect Facebook Pages');a.href='/auth/meta/start?workspace_id='+encodeURIComponent(w.id);right.append(a)}try{const c=await api('/api/workspaces/'+encodeURIComponent(w.id)+'/connections');more.textContent=c.connections.length?c.connections.map(x=>x.pageName+' ('+x.pageId+')').join(' · '):'No Facebook Pages connected'}catch(e){more.textContent=e.message}}}catch(e){$('message').textContent=e.message}}
$('addWorkspace').addEventListener('submit',async e=>{e.preventDefault();$('message').textContent='';try{await api('/api/workspaces',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:$('name').value})});$('name').value='';await load()}catch(e){$('message').textContent=e.message}});load();
</script></body></html>`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!configReady(env)) return error(503, 'Configuration incomplete: set Worker secrets, database and PUBLIC_BASE_URL');
    // Never trust identity from a user-supplied header. ctx.access comes from Cloudflare Access.
    let user;
    try { user = await accessUser(ctx); } catch { return error(403, 'Cloudflare Access verification failed'); }
    if (!user) return error(403, 'Cloudflare Access sign-in required. Protect this Worker with an Access policy.');
    try {
      if (request.method === 'GET' && url.pathname === '/') return html(HOME);
      if (request.method === 'GET' && url.pathname === '/api/me') return json({ email: user, isAgencyAdmin: isAgencyAdmin(user, env), redirectUri: `${normalizedBaseUrl(env)}/auth/meta/callback` });
      if (request.method === 'GET' && url.pathname === '/auth/meta/start') return startOAuth(request, env, user);
      if (request.method === 'GET' && url.pathname === '/auth/meta/callback') return metaCallback(request, env, user);
      if (request.method === 'GET' && url.pathname === '/api/workspaces') {
        const rows = await env.DB.prepare('SELECT w.id,w.name,m.role,w.created_at FROM workspaces w JOIN workspace_members m ON w.id=m.workspace_id WHERE m.email=? ORDER BY w.created_at DESC').bind(user).all();
        return json({ workspaces: rows.results || [] });
      }
      if (request.method === 'POST' && url.pathname === '/api/workspaces') {
        if (!csrfSafe(request, env)) return error(403, 'Invalid request origin or content type');
        if (!isAgencyAdmin(user, env)) return error(403, 'Agency admin only');
        const data = await bodyJson(request);
        const name = String(data?.name || '').trim();
        if (name.length < 2 || name.length > 80) return error(400, 'Workspace name must be 2–80 characters');
        const id = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare('INSERT INTO workspaces (id,name,created_by) VALUES (?,?,?)').bind(id, name, user),
          env.DB.prepare("INSERT INTO workspace_members (workspace_id,email,role) VALUES (?,?,'owner')").bind(id, user)
        ]);
        return json({ id, name }, 201);
      }
      const connectionsMatch = url.pathname.match(/^\/api\/workspaces\/([0-9a-f-]{36})\/connections$/);
      if (request.method === 'GET' && connectionsMatch) {
        const workspaceId = connectionsMatch[1];
        if (!await requireRole(env.DB, workspaceId, user)) return error(403, 'Workspace access denied');
        const rows = await env.DB.prepare('SELECT id,page_id,page_name,page_tasks,connected_by,connected_at,updated_at FROM social_connections WHERE workspace_id=? ORDER BY page_name').bind(workspaceId).all();
        return json({ connections: (rows.results || []).map(r => ({ id: r.id, pageId: r.page_id, pageName: r.page_name, tasks: JSON.parse(r.page_tasks), connectedBy: r.connected_by, connectedAt: r.connected_at, updatedAt: r.updated_at })) });
      }
      const memberMatch = url.pathname.match(/^\/api\/workspaces\/([0-9a-f-]{36})\/members$/);
      if (request.method === 'POST' && memberMatch) {
        if (!csrfSafe(request, env)) return error(403, 'Invalid request origin or content type');
        const workspaceId = memberMatch[1];
        if (!await requireRole(env.DB, workspaceId, user, 'owner')) return error(403, 'Workspace owner only');
        const data = await bodyJson(request);
        const email = String(data?.email || '').trim().toLowerCase();
        const role = String(data?.role || 'viewer');
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['admin', 'editor', 'viewer'].includes(role)) return error(400, 'Invalid email or role');
        await env.DB.prepare('INSERT INTO workspace_members (workspace_id,email,role) VALUES (?,?,?) ON CONFLICT(workspace_id,email) DO UPDATE SET role=excluded.role').bind(workspaceId, email, role).run();
        return json({ ok: true });
      }
      const deleteMatch = url.pathname.match(/^\/api\/workspaces\/([0-9a-f-]{36})\/connections\/([0-9a-f-]{36})$/);
      if (request.method === 'DELETE' && deleteMatch) {
        if (!csrfSafe(request, env)) return error(403, 'Invalid request origin or content type');
        const workspaceId = deleteMatch[1];
        if (!await requireRole(env.DB, workspaceId, user, 'admin')) return error(403, 'Workspace admin only');
        const result = await env.DB.prepare('DELETE FROM social_connections WHERE workspace_id=? AND id=?').bind(workspaceId, deleteMatch[2]).run();
        return json({ disconnected: (result.meta?.changes || 0) > 0 });
      }
      return error(404, 'Route not found');
    } catch (e) {
      console.error('Worker request failed:', e.message);
      if (e instanceof SyntaxError) return error(400, 'Invalid JSON');
      return error(500, 'Request failed. Check Cloudflare Worker logs.');
    }
  }
};