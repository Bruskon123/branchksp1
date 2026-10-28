import { validSession, unauthorized, validProfile } from '../../_lib/auth.js';
export async function onRequestGet(context) {
  const { request, env, params } = context;
  if (!(await validSession(request, env))) return unauthorized();
  const profile = new URL(request.url).searchParams.get('profile') || '';
  if (!validProfile(profile)) return Response.json({ error: 'Invalid profile' }, { status: 400 });
  const id = Number(params.id);
  if (!Number.isInteger(id)) return Response.json({ error: 'Invalid id' }, { status: 400 });
  const row = await env.KSP_DB.prepare('SELECT id, profile, summary, data, created_at AS createdAt FROM change_log WHERE id = ?1 AND profile = ?2').bind(id, profile).first();
  if (!row) return Response.json({ error: 'Not found' }, { status: 404 });
  row.data = JSON.parse(row.data);
  return Response.json(row, { headers: { 'Cache-Control': 'no-store' } });
}
