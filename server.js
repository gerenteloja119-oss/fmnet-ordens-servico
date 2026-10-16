import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import { createClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';

const {SESSION_SECRET:secret, ADMIN_PASSWORD:password, SUPABASE_URL:url, SUPABASE_SECRET_KEY:key}=process.env;
if(!secret || secret.length<32 || !password || password.length<12) throw Error('Configure SESSION_SECRET (32+ caracteres) e ADMIN_PASSWORD (12+ caracteres) no .env');
if(!url?.startsWith('https://') || !key) throw Error('Configure SUPABASE_URL e SUPABASE_SECRET_KEY no .env');
const db=createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
const Store=session.Store;
class SupabaseSessionStore extends Store {
  get(sid,cb){db.from('fmnet_sessions').select('sess,expires_at').eq('sid',sid).maybeSingle().then(({data,error})=>{
    if(error)return cb(error);
    if(!data || new Date(data.expires_at)<=new Date())return cb(null,null);
    cb(null,data.sess);
  }).catch(cb)}
  set(sid,sess,cb){const exp=sess.cookie?.expires?new Date(sess.cookie.expires):new Date(Date.now()+8*60*60*1000);
    db.from('fmnet_sessions').upsert({sid,sess,expires_at:exp.toISOString()}).then(({error})=>cb?.(error||null)).catch(e=>cb?.(e))}
  destroy(sid,cb){db.from('fmnet_sessions').delete().eq('sid',sid).then(({error})=>cb?.(error||null)).catch(e=>cb?.(e))}
  touch(sid,sess,cb){this.set(sid,sess,cb)}
}
const app=express();app.disable('x-powered-by');app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'20kb'}));
app.use(session({store:new SupabaseSessionStore(),name:'fmnet.sid',secret,resave:false,saveUninitialized:false,cookie:{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:8*60*60*1000}}));
app.use(express.static('public'));
app.use('/api/login',rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:'draft-7',legacyHeaders:false}));
function auth(req,res,next){if(!req.session.auth)return res.status(401).json({error:'Acesso não autorizado'});next()}
function csrf(req,res,next){if(!req.session.csrf || req.get('x-csrf-token')!==req.session.csrf)return res.status(403).json({error:'Sessão inválida. Atualize a página.'});next()}
function safe(fn){return async(req,res)=>{try{await fn(req,res)}catch(e){console.error('Database error:',e.message);res.status(500).json({error:'Falha ao acessar o banco de dados'})}}}
app.get('/api/session',(req,res)=>res.json({authenticated:!!req.session.auth,csrf:req.session.auth?req.session.csrf:null}));
app.post('/api/login',(req,res)=>{const {username,password:p}=req.body||{};
  const a=Buffer.from(typeof p==='string'?p:'');const b=Buffer.from(password);
  const pass=a.length===b.length && crypto.timingSafeEqual(a,b);
  if(username!=='admin'||!pass)return res.status(401).json({error:'Usuário ou senha incorretos'});
  req.session.regenerate(e=>{if(e)return res.status(500).json({error:'Erro de sessão'});req.session.auth=true;req.session.csrf=crypto.randomBytes(24).toString('hex');req.session.save(err=>err?res.status(500).json({error:'Erro de sessão'}):res.json({ok:true,csrf:req.session.csrf}))})
});
app.post('/api/logout',auth,csrf,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/orders',auth,safe(async(req,res)=>{const {data,error}=await db.from('ordens_servico').select('*').order('id',{ascending:false}).limit(1000);if(error)throw error;res.json(data)}));
app.post('/api/orders',auth,csrf,safe(async(req,res)=>{let {name,address,phone,description=''}=req.body||{};if([name,address,phone,description].some(x=>typeof x!=='string')||!name.trim()||!address.trim()||!phone.trim()||name.length>150||address.length>300||phone.length>40||description.length>1500)return res.status(400).json({error:'Preencha os campos corretamente'});
  const {data,error}=await db.from('ordens_servico').insert({name:name.trim(),address:address.trim(),phone:phone.trim(),description:description.trim()}).select().single();if(error)throw error;res.status(201).json(data)}));
app.patch('/api/orders/:id',auth,csrf,safe(async(req,res)=>{const {status}=req.body||{};if(!['Aberta','Em andamento','Concluída'].includes(status))return res.status(400).json({error:'Status inválido'});if(!/^\d+$/.test(req.params.id))return res.status(400).json({error:'ID inválido'});
  const {data,error}=await db.from('ordens_servico').update({status}).eq('id',req.params.id).select().maybeSingle();if(error)throw error;if(!data)return res.status(404).json({error:'OS não encontrada'});res.json(data)}));
app.listen(Number(process.env.PORT)||3000,()=>console.log('FM NET OS (Supabase) em execução'));
