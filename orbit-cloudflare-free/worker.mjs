const encoder = new TextEncoder();
const sessionCookie = '__Host-orbit_session';
const adminId = 'heize-owner';
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
function fail(status, message) { throw new HttpError(status, message); }
const secureHeaders = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" };
const json = (data, status = 200) => Response.json(data, { status, headers: secureHeaders });
function redirect(location, cookies = []) { const headers = new Headers({ ...secureHeaders, Location: location }); for (const c of cookies) headers.append('Set-Cookie', c); return new Response(null, { status: 303, headers }); }
const cookie = (name, value, age) => `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
function readCookie(req, name) { const values = (req.headers.get('cookie') || '').split(';').map(s => s.trim()).filter(s => s.startsWith(name + '=')); return values.length === 1 ? values[0].slice(name.length + 1) : ''; }
const random = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
async function hash(value) { return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
const now = () => Math.floor(Date.now() / 1000);
function origin(env) { let u; try { u = new URL(env.APP_ORIGIN); } catch { fail(503, '운영자가 APP_ORIGIN을 설정해야 합니다.'); } if (u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' || u.search || u.hash) fail(503, 'APP_ORIGIN 설정을 확인해주세요.'); return u.origin; }
function sameOrigin(req, env) { if (req.headers.get('origin') !== origin(env) || req.headers.get('sec-fetch-site') === 'cross-site') fail(403, '같은 사이트에서만 요청할 수 있습니다.'); }
async function body(req) {
 if (!req.headers.get('content-type')?.startsWith('application/json')) fail(415, 'JSON 요청이 필요합니다.');
 const reader = req.body?.getReader(); if (!reader) fail(400, '입력값이 없습니다.'); let length = 0; const parts = [];
 while (true) { const { done, value } = await reader.read(); if (done) break; length += value.length; if (length > 40000) { await reader.cancel(); fail(413, '내용이 너무 깁니다.'); } parts.push(value); }
 const bytes = new Uint8Array(length); let offset = 0; for (const part of parts) { bytes.set(part, offset); offset += part.length; }
 let value; try { value = JSON.parse(new TextDecoder().decode(bytes)); } catch { fail(400, '입력 형식을 확인해주세요.'); }
 if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400, '입력 형식을 확인해주세요.'); return value;
}
function text(value, max) { if (typeof value !== 'string' || !value.trim() || value.trim().length > max || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(value)) fail(400, `필수 입력값과 길이(최대 ${max}자)를 확인해주세요.`); return value.trim(); }
function exact(value, keys) { if (Object.keys(value).some(k => !keys.includes(k))) fail(400, '지원하지 않는 항목이 있습니다.'); }
export function safeKakao(value) { try { const u = new URL(value); return u.protocol === 'https:' && u.hostname === 'open.kakao.com' && !u.port && !u.username && !u.password && !u.search && !u.hash && /^\/o\/[A-Za-z0-9_-]{4,80}$/.test(u.pathname); } catch { return false; } }
function postInput(input) { exact(input, ['title','content','price','status','link']); const p = { title: text(input.title,100), content: text(input.content,10000), price: text(input.price,120), status: input.status, link: text(input.link,200) }; if (!['available','unavailable'].includes(p.status) || !safeKakao(p.link)) fail(400, '거래 상태와 https://open.kakao.com/o/… 형식의 링크를 확인해주세요.'); return p; }
async function limit(db, key, max, seconds) {
 const bucket = Math.floor(now() / seconds); const row = await db.prepare('INSERT INTO rate_limits (key,count,expires) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count').bind(key + ':' + bucket, (bucket + 2) * seconds).first();
 if (row.count > max) fail(429, '요청이 많습니다. 잠시 후 다시 시도해주세요.');
}
function configured(env) { return typeof env.ADMIN_PASSWORD === 'string' && env.ADMIN_PASSWORD.length >= 16 && env.ADMIN_PASSWORD.length <= 256; }
async function sessionHash(token,env) { const key=await crypto.subtle.importKey('raw',encoder.encode(env.ADMIN_PASSWORD),{name:'HMAC',hash:'SHA-256'},false,['sign']);return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(token))))); }
async function user(req,env) {
 if(!configured(env))return null;
 const token=readCookie(req,sessionCookie);if(!/^[A-Za-z0-9_-]{43}$/.test(token))return null;
 const row=await env.DB.prepare('SELECT u.id,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.id=?').bind(await sessionHash(token,env),now(),adminId).first();
 return row?{...row,admin:true}:null;
}
async function authorized(req,env) {sameOrigin(req,env);const u=await user(req,env);if(!u?.admin)fail(401,'관리자 비밀번호로 로그인해주세요.');await limit(env.DB,'write:'+u.id,30,60);return u;}
function publicPost(p,u){const {owner,...rest}=p;return {...rest,canEdit:!!u?.admin};}
async function auth(req,env,path,url){
 if(url.origin!==origin(env))fail(400,'등록된 사이트 주소에서 로그인해주세요.');
 if(req.method!=='POST')fail(405,'지원하지 않는 요청입니다.');sameOrigin(req,env);
 if(path==='/auth/logout'){const token=readCookie(req,sessionCookie);if(token&&configured(env))await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sessionHash(token,env)).run();return new Response(JSON.stringify({ok:true}),{headers:{...secureHeaders,'Content-Type':'application/json','Set-Cookie':cookie(sessionCookie,'',0)}});}
 if(path!=='/auth/login')fail(404,'요청을 찾을 수 없습니다.');
 if(!configured(env))fail(503,'Cloudflare에서 16~256자 관리자 비밀번호(ADMIN_PASSWORD)를 먼저 설정해주세요.');
 await limit(env.DB,'admin-login:'+await hash(req.headers.get('CF-Connecting-IP')||'local'),5,900);
 const input=await body(req);exact(input,['password']);
 if(typeof input.password!=='string'||input.password.length>256)fail(400,'비밀번호를 확인해주세요.');
 const actual=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(input.password)));
 const expected=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(env.ADMIN_PASSWORD)));
 let difference=0;for(let i=0;i<expected.length;i++)difference|=actual[i]^expected[i];
 if(difference!==0)fail(401,'비밀번호가 올바르지 않습니다.');
 const token=random();await env.DB.batch([
 env.DB.prepare('INSERT INTO users (id,email,name) VALUES (?,?,?) ON CONFLICT(id) DO NOTHING').bind(adminId,'','헤이즈 관리자'),
 env.DB.prepare('INSERT INTO sessions (token_hash,user_id,expires) VALUES (?,?,?)').bind(await sessionHash(token,env),adminId,now()+28800)
 ]);
 return new Response(JSON.stringify({ok:true}),{headers:{...secureHeaders,'Content-Type':'application/json','Set-Cookie':cookie(sessionCookie,token,28800)}});
}
async function api(req, env, url) {
 const path = url.pathname, db = env.DB;
 if (!db) fail(503,'운영자가 D1 데이터베이스 연결을 완료해야 합니다.');
 if (path === '/api/data' && req.method === 'GET') {
  const u = await user(req,env), scope = url.searchParams.get('scope') || 'all', q = (url.searchParams.get('q') || '').slice(0,100), status = url.searchParams.get('status');
  const page = Math.max(1,Math.min(10000,Math.floor(Number(url.searchParams.get('page')) || 1))); const where = [], args = [];
  if (scope === 'admin') { if (!u?.admin) fail(u?403:401,'관리자 계정으로 로그인해주세요.'); } else if (scope === 'mine') { if (!u) fail(401,'로그인이 필요합니다.'); where.push('owner=?'); args.push(u.id); } else where.push('hidden=0');
  if (q) { where.push("(title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\')"); const query='%'+q.replace(/[\\%_]/g,'\\$&')+'%'; args.push(query,query); }
  if (['available','unavailable'].includes(status)) { where.push('status=?'); args.push(status); }
  const filter = where.length ? ' WHERE '+where.join(' AND ') : '';
  const results = await db.batch([
   db.prepare('SELECT * FROM posts'+filter+' ORDER BY created DESC,id DESC LIMIT 18 OFFSET ?').bind(...args,(page-1)*18),
   db.prepare('SELECT count(*) AS n FROM posts'+filter).bind(...args),
   db.prepare('SELECT * FROM notices ORDER BY created DESC LIMIT 100'),
   db.prepare('SELECT name,description FROM settings WHERE id=1')
  ]);
  return json({posts:results[0].results.map(p=>publicPost(p,u)),total:results[1].results[0].n,page,notices:results[2].results,settings:{...(results[3].results[0]||{description:'필요한 거래를, 간결하게.'}),name:!results[3].results[0]?.name||results[3].results[0].name==='ORBIT'?'헤이즈':results[3].results[0].name},user:u?{name:u.name,admin:u.admin}:null});
 }
 if (path === '/api/posts' && req.method === 'POST') { const u=await authorized(req,env), p=postInput(await body(req)), id=crypto.randomUUID(), date=new Date().toISOString(); await db.prepare('INSERT INTO posts (id,owner,title,content,price,status,link,created,updated) VALUES (?,?,?,?,?,?,?,?,?)').bind(id,u.id,p.title,p.content,p.price,p.status,p.link,date,date).run(); return json({id},201); }
 const match=path.match(/^\/api\/posts\/([0-9a-f-]{36})$/);
 if (match) {
  const id=match[1];
  if(req.method==='GET'){const u=await user(req,env),p=await db.prepare('SELECT * FROM posts WHERE id=?').bind(id).first();if(!p||(p.hidden&&!u?.admin&&p.owner!==u?.id))fail(404,'거래글을 찾을 수 없습니다.');return json({...publicPost(p,u),admin:!!u?.admin});}
  if(!['PATCH','DELETE'].includes(req.method))fail(405,'지원하지 않는 요청입니다.');
  const u=await authorized(req,env),p=await db.prepare('SELECT * FROM posts WHERE id=?').bind(id).first();if(!p)fail(404,'거래글을 찾을 수 없습니다.');if(!u.admin&&p.owner!==u.id)fail(403,'본인의 거래글만 변경할 수 있습니다.');
  if(req.method==='DELETE'){await db.prepare('DELETE FROM posts WHERE id=?').bind(id).run();return json({ok:true});}
  const input=await body(req),date=new Date().toISOString();
  if(Object.keys(input).length===1&&'hidden'in input){if(!u.admin)fail(403,'관리자 권한이 필요합니다.');if(typeof input.hidden!=='boolean')fail(400,'숨김 값을 확인해주세요.');await db.prepare('UPDATE posts SET hidden=?,updated=? WHERE id=?').bind(input.hidden?1:0,date,id).run();}
  else{const v=postInput(input);await db.prepare('UPDATE posts SET title=?,content=?,price=?,status=?,link=?,updated=? WHERE id=?').bind(v.title,v.content,v.price,v.status,v.link,date,id).run();}return json({ok:true});
 }
 if(path==='/api/admin'&&req.method==='POST'){
  await authorized(req,env,true);const data=await body(req),date=new Date().toISOString();
  if(data.action==='settings'){const v=data.value||{};exact(v,['name','description']);await db.prepare('INSERT INTO settings (id,name,description) VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description').bind(text(v.name,40),text(v.description,200)).run();}
  else if(data.action==='notice'){const v=data.value||{};exact(v,['title','content']);const title=text(v.title,100),content=text(v.content,10000);if(data.id){const r=await db.prepare('UPDATE notices SET title=?,content=?,updated=? WHERE id=?').bind(title,content,date,text(data.id,36)).run();if(!r.meta.changes)fail(404,'공지를 찾을 수 없습니다.');}else{const count=await db.prepare('SELECT count(*) AS n FROM notices').first();if(count.n>=100)fail(400,'공지는 최대 100개입니다. 오래된 공지를 정리해주세요.');await db.prepare('INSERT INTO notices (id,title,content,created,updated) VALUES (?,?,?,?,?)').bind(crypto.randomUUID(),title,content,date,date).run();}}
  else if(data.action==='deleteNotice'){await db.prepare('DELETE FROM notices WHERE id=?').bind(text(data.id,36)).run();}else fail(400,'지원하지 않는 요청입니다.');return json({ok:true});
 }
 fail(404,'요청을 찾을 수 없습니다.');
}
export default {
 async fetch(req,env){try{const url=new URL(req.url);if(url.pathname.startsWith('/auth/'))return await auth(req,env,url.pathname,url);if(url.pathname.startsWith('/api/'))return await api(req,env,url);return await env.ASSETS.fetch(req);}catch(e){if(e instanceof HttpError)return json({error:e.message},e.status);console.error('Request failed',e?.name||'Error');return json({error:'일시적으로 처리할 수 없습니다. 잠시 후 다시 시도해주세요.'},503);}},
 async scheduled(_event,env){const time=now();await env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE expires<?').bind(time),env.DB.prepare('DELETE FROM oauth_states WHERE expires<?').bind(time),env.DB.prepare('DELETE FROM rate_limits WHERE expires<?').bind(time)]);}
};
