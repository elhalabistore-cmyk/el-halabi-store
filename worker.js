const COOKIE = 'halabi_admin';
// D1 rows have a size limit; keep uploaded images small enough for safe data-URL storage.
const MAX_IMAGE = 1024 * 1024;
const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Credentials': 'true' };
const json = (data, status=200, extra={}) => new Response(JSON.stringify(data), {status, headers:{'Content-Type':'application/json; charset=utf-8', ...cors, ...extra}});
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
async function sign(value, secret){ const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']); return b64(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(value))); }
async function token(env){ const payload=b64(new TextEncoder().encode(JSON.stringify({sub:'admin',exp:Date.now()+8*60*60*1000}))); return payload+'.'+await sign(payload,env.SESSION_SECRET); }
async function authorized(req,env){ const raw=(req.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1); if(!raw)return false; const [p,s]=raw.split('.'); if(!p||!s||s!==await sign(p,env.SESSION_SECRET))return false; try{const v=JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));return v.sub==='admin'&&v.exp>Date.now()}catch{return false} }
const needAuth=async(req,env)=>await authorized(req,env)?null:json({error:'غير مصرح. سجّل الدخول أولاً.'},401);
export default { async fetch(req,env){
 const url=new URL(req.url), path=url.pathname;
 if(req.method==='OPTIONS')return new Response(null,{headers:cors});
 try {
  if(path==='/api/health')return json({ok:true,service:'El Halabi API'});
  if(path==='/api/products'&&req.method==='GET'){const {results}=await env.DB.prepare('SELECT id,name,category,description,price,image_url,is_active,created_at FROM products WHERE is_active=1 ORDER BY created_at DESC').all();return json(results)}
  if(path==='/api/orders'&&req.method==='POST'){
   const v=await req.json(); if(!v.customer_name||!v.phone||!Array.isArray(v.items)||!v.items.length)return json({error:'الاسم والهاتف والمنتجات مطلوبة.'},400);
   if(String(v.customer_name).length>120||String(v.phone).length>40||String(v.address||'').length>500||v.items.length>50)return json({error:'بيانات الطلب طويلة أكثر من اللازم.'},400);
   const id=crypto.randomUUID(); await env.DB.prepare('INSERT INTO orders(id,customer_name,phone,address,items,status,language,created_at) VALUES(?,?,?,?,?,?,?,?)').bind(id,String(v.customer_name),String(v.phone),String(v.address||''),JSON.stringify(v.items.map(x=>({name:String(x.name).slice(0,120),quantity:Math.max(1,Math.min(99,Number(x.quantity)||1))}))), 'new',v.language==='fr'?'fr':'ar',new Date().toISOString()).run(); return json({id});
  }
  if(path==='/api/admin/login'&&req.method==='POST'){
   const v=await req.json(); if(!env.ADMIN_EMAIL||!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return json({error:'إعدادات المدير غير مكتملة في Cloudflare.'},500);
   if(String(v.email||'').trim().toLowerCase()!==env.ADMIN_EMAIL.toLowerCase()||String(v.password||'')!==env.ADMIN_PASSWORD)return json({error:'البريد الإلكتروني أو كلمة المرور غير صحيحة.'},401);
   const t=await token(env);return json({ok:true},200,{'Set-Cookie':`${COOKIE}=${t}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`});
  }
  if(path==='/api/admin/logout'&&req.method==='POST')return json({ok:true},200,{'Set-Cookie':`${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`});
  if(path.startsWith('/api/admin/')){const denied=await needAuth(req,env);if(denied)return denied;
   if(path==='/api/admin/me')return json({ok:true});
   if(path==='/api/admin/orders'&&req.method==='GET'){const {results}=await env.DB.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 300').all();return json(results.map(x=>({...x,items:JSON.parse(x.items||'[]')})))}
   const statusMatch=path.match(/^\/api\/admin\/orders\/([^/]+)$/); if(statusMatch&&req.method==='PUT'){const v=await req.json();const allowed=['new','confirmed','preparing','ready','delivered','cancelled'];if(!allowed.includes(v.status))return json({error:'حالة غير صالحة.'},400);await env.DB.prepare('UPDATE orders SET status=? WHERE id=?').bind(v.status,statusMatch[1]).run();return json({ok:true})}
   if(path==='/api/admin/products'&&req.method==='GET'){const {results}=await env.DB.prepare('SELECT * FROM products ORDER BY created_at DESC').all();return json(results)}
   if(path==='/api/admin/products'&&(req.method==='POST')){const v=await req.json();if(!v.name||!v.category)return json({error:'اسم المنتج والتصنيف مطلوبان.'},400);const id=crypto.randomUUID();await env.DB.prepare('INSERT INTO products(id,name,category,description,price,image_url,is_active,created_at) VALUES(?,?,?,?,?,?,?,?)').bind(id,v.name,v.category,v.description||'',v.price===''||v.price==null?null:Number(v.price),v.image_url||'',v.is_active?1:0,new Date().toISOString()).run();return json({id})}
   const prod=path.match(/^\/api\/admin\/products\/([^/]+)$/);if(prod&&req.method==='PUT'){const v=await req.json();await env.DB.prepare('UPDATE products SET name=?,category=?,description=?,price=?,image_url=?,is_active=? WHERE id=?').bind(v.name,v.category,v.description||'',v.price===''||v.price==null?null:Number(v.price),v.image_url||'',v.is_active?1:0,prod[1]).run();return json({ok:true})}if(prod&&req.method==='DELETE'){await env.DB.prepare('DELETE FROM products WHERE id=?').bind(prod[1]).run();return json({ok:true})}
   if(path==='/api/admin/upload'&&req.method==='POST'){
    const form=await req.formData(),file=form.get('image');
    if(!file||typeof file==='string'||!['image/jpeg','image/png','image/webp','image/gif'].includes(file.type)||file.size>MAX_IMAGE)
      return json({error:'اختر صورة JPG أو PNG أو WEBP أو GIF لا يتجاوز حجمها 1 ميغابايت.'},400);
    const bytes=new Uint8Array(await file.arrayBuffer());
    let binary='';
    for(let i=0;i<bytes.length;i+=0x8000)binary+=String.fromCharCode(...bytes.subarray(i,i+0x8000));
    const dataUrl=`data:${file.type};base64,${btoa(binary)}`;
    return json({url:dataUrl});
   }
  }
  if(env.ASSETS)return env.ASSETS.fetch(req);
  return new Response('El Halabi API is running. Configure static assets.',{status:404});
 }catch(e){return json({error:'حدث خطأ داخلي. راجع سجلات Worker.',detail:env.ENVIRONMENT==='development'?String(e):undefined},500)}
}};
