const COOKIE = 'ksp_session';
const SESSION_HOURS = 5;
const DEFAULT_USERNAME = 'Branch';
const DEFAULT_PASSWORD = 'KSP123@';

function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function fromBase64url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}
function cookieValue(request, name) {
  const item = (request.headers.get('Cookie') || '').split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`));
  return item ? item.slice(name.length + 1) : null;
}
async function key(env) {
  const secret = env.KSP_SESSION_SECRET;
  if (!secret || secret.length < 32) return null;
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
function sameOrigin(request) {
  const origin = request.headers.get('Origin');
  return Boolean(origin) && origin === new URL(request.url).origin;
}
function cookie(request, value, maxAge) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}
async function createToken(env) {
  const signingKey = await key(env);
  if (!signingKey) return null;
  const body = base64url(new TextEncoder().encode(String(Date.now() + SESSION_HOURS * 60 * 60 * 1000)));
  const signature = await crypto.subtle.sign('HMAC', signingKey, new TextEncoder().encode(body));
  return `${body}.${base64url(new Uint8Array(signature))}`;
}
export async function validSession(request, env) {
  const token = cookieValue(request, COOKIE);
  const signingKey = await key(env);
  if (!token || !signingKey) return false;
  const [body, signature, extra] = token.split('.');
  if (!body || !signature || extra) return false;
  try {
    const expiry = Number(new TextDecoder().decode(fromBase64url(body)));
    if (!Number.isFinite(expiry) || expiry <= Date.now()) return false;
    return crypto.subtle.verify('HMAC', signingKey, fromBase64url(signature), new TextEncoder().encode(body));
  } catch { return false; }
}
export async function authGet(context) {
  return Response.json({ authenticated: await validSession(context.request, context.env) }, { headers: { 'Cache-Control': 'no-store' } });
}
export async function authPost(context) {
  const { request, env } = context;
  if (!sameOrigin(request)) return Response.json({ error: 'Invalid origin' }, { status: 403 });
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const username = env.KSP_LOGIN_USERNAME || DEFAULT_USERNAME;
  const password = env.KSP_LOGIN_PASSWORD || DEFAULT_PASSWORD;
  if (body?.username !== username || body?.password !== password) return Response.json({ error: 'Invalid username or password' }, { status: 401 });
  const token = await createToken(env);
  if (!token) return Response.json({ error: 'Authentication is not configured' }, { status: 503 });
  return Response.json({ ok: true }, { headers: { 'Set-Cookie': cookie(request, token, SESSION_HOURS * 60 * 60), 'Cache-Control': 'no-store' } });
}
export function authDelete(context) {
  if (!sameOrigin(context.request)) return Response.json({ error: 'Invalid origin' }, { status: 403 });
  return Response.json({ ok: true }, { headers: { 'Set-Cookie': cookie(context.request, '', 0), 'Cache-Control': 'no-store' } });
}
export function unauthorized() { return Response.json({ error: 'Unauthorized' }, { status: 401, headers: { 'Cache-Control': 'no-store' } }); }
export function validProfile(profile) { return ['כל הסניפים', 'ליאור דביר', 'עדי אייזיק', 'יחיאל שמילוב', 'עמית בק'].includes(profile); }
export { sameOrigin };
