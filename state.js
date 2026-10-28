import { validSession, unauthorized, validProfile, sameOrigin } from '../_lib/auth.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  if (!(await validSession(request, env))) return unauthorized();
  const profile = new URL(request.url).searchParams.get('profile') || '';
  if (!validProfile(profile)) return Response.json({ error: 'Invalid profile' }, { status: 400 });
  const row = await env.KSP_DB.prepare('SELECT data, updated_at FROM app_state WHERE id = ?1').bind(profile).first();
  return Response.json({ data: row?.data ? JSON.parse(row.data) : null, updatedAt: row?.updated_at || null }, { headers: { 'Cache-Control': 'no-store' } });
}
export async function onRequestPut(context) {
  const { request, env } = context;
  if (!(await validSession(request, env))) return unauthorized();
  if (!sameOrigin(request)) return Response.json({ error: 'Invalid origin' }, { status: 403 });
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > 8_000_000) return Response.json({ error: 'Payload too large' }, { status: 413 });
  let body;
  try {
    const raw = await request.text();
    if (new TextEncoder().encode(raw).byteLength > 8_000_000) return Response.json({ error: 'Payload too large' }, { status: 413 });
    body = JSON.parse(raw);
  } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const data = body?.data;
  const profile = typeof data?.currentUser === 'string' ? data.currentUser : '';
  if (!validProfile(profile) || body.profile !== profile || !Array.isArray(data?.branches) || !Array.isArray(data?.tasks)) return Response.json({ error: 'Invalid state' }, { status: 400 });
  const now = new Date().toISOString();
  const serialized = JSON.stringify(data);
  const summary = typeof body.summary === 'string' ? body.summary.slice(0, 300) : '';
  await env.KSP_DB.batch([
    env.KSP_DB.prepare('INSERT INTO app_state (id, data, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at').bind(profile, serialized, now),
    env.KSP_DB.prepare('INSERT INTO change_log (profile, summary, data, created_at) VALUES (?1, ?2, ?3, ?4)').bind(profile, summary, serialized, now),
  ]);
  return Response.json({ ok: true, updatedAt: now });
}
