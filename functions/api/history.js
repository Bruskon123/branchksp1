import { validSession, unauthorized, validProfile } from '../_lib/auth.js';
export async function onRequestGet(context) {
  const { request, env } = context;
  if (!(await validSession(request, env))) return unauthorized();
  const url = new URL(request.url), profile = url.searchParams.get('profile') || '';
  if (!validProfile(profile)) return Response.json({ error: 'Invalid profile' }, { status: 400 });
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 100, 1), 500);
  const result = await env.KSP_DB.prepare('SELECT id, summary, created_at AS createdAt FROM change_log WHERE profile = ?1 ORDER BY id DESC LIMIT ?2').bind(profile, limit).all();
  return Response.json(result.results || [], { headers: { 'Cache-Control': 'no-store' } });
}
