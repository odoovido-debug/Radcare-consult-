const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "DEV_ONLY_CHANGE_THIS_SECRET";
const MAX_MB = Number(process.env.MAX_UPLOAD_MB || 50);
const DATA_DIR = process.env.DATA_DIR || __dirname;
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, "private_uploads");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "radcare.db"));

// Required by platforms such as Render/Railway when they sit behind a proxy.
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const uploadDir = UPLOAD_DIR;
fs.mkdirSync(uploadDir, { recursive: true });

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 country TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('patient','radiographer','student','admin')),
 status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','suspended')),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
 id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL,
 original_name TEXT NOT NULL,
 stored_name TEXT NOT NULL,
 mime_type TEXT NOT NULL,
 size INTEGER NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(owner_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS appointments (
 id TEXT PRIMARY KEY,
 patient_id TEXT NOT NULL,
 radiographer_id TEXT NOT NULL,
 appointment_at TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'requested',
 created_at TEXT NOT NULL,
 FOREIGN KEY(patient_id) REFERENCES users(id),
 FOREIGN KEY(radiographer_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS patient_profiles (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL UNIQUE,
 phone TEXT,
 date_of_birth TEXT,
 emergency_contact TEXT,
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS services (
 id TEXT PRIMARY KEY,
 radiographer_id TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT,
 price_cents INTEGER NOT NULL,
 currency TEXT NOT NULL DEFAULT 'USD',
 duration_minutes INTEGER NOT NULL DEFAULT 30,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 FOREIGN KEY(radiographer_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS conversations (
 id TEXT PRIMARY KEY,
 patient_id TEXT NOT NULL,
 radiographer_id TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(patient_id) REFERENCES users(id),
 FOREIGN KEY(radiographer_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY,
 conversation_id TEXT NOT NULL,
 sender_id TEXT NOT NULL,
 body TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(conversation_id) REFERENCES conversations(id),
 FOREIGN KEY(sender_id) REFERENCES users(id)
);


CREATE TABLE IF NOT EXISTS payments (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 appointment_id TEXT,
 provider TEXT NOT NULL CHECK(provider IN ('mpesa','visa','demo')),
 amount_cents INTEGER NOT NULL,
 currency TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','paid','failed','cancelled')),
 provider_reference TEXT,
 checkout_reference TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id),
 FOREIGN KEY(appointment_id) REFERENCES appointments(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
 id TEXT PRIMARY KEY,
 actor_id TEXT,
 action TEXT NOT NULL,
 target_id TEXT,
 created_at TEXT NOT NULL
);
`);

// Lightweight schema migrations for V6 deployments.
const appointmentColumns = db.prepare("PRAGMA table_info(appointments)").all().map(x => x.name);
if (!appointmentColumns.includes("service_id")) db.exec("ALTER TABLE appointments ADD COLUMN service_id TEXT");
if (!appointmentColumns.includes("amount_cents")) db.exec("ALTER TABLE appointments ADD COLUMN amount_cents INTEGER");
if (!appointmentColumns.includes("currency")) db.exec("ALTER TABLE appointments ADD COLUMN currency TEXT");


const adminEmail = process.env.ADMIN_EMAIL || "admin@radcare.com";
const adminPassword = process.env.ADMIN_PASSWORD || "RadCare@2026!Admin";
if (adminEmail && adminPassword && !db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail.toLowerCase())) {
  const admin = {
    id: id(), name: "RadCare Administrator", email: adminEmail.toLowerCase(),
    password_hash: bcrypt.hashSync(adminPassword, 12), country: "Global",
    role: "admin", status: "approved", created_at: now()
  };
  db.prepare("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)").run(
    admin.id, admin.name, admin.email, admin.password_hash, admin.country,
    admin.role, admin.status, admin.created_at
  );
}

function now(){ return new Date().toISOString(); }
function id(){ return crypto.randomUUID(); }
function publicUser(u){
  return {id:u.id,name:u.name,email:u.email,country:u.country,role:u.role,status:u.status,created_at:u.created_at};
}
function log(actor, action, target=null){
  db.prepare("INSERT INTO audit_logs VALUES (?,?,?,?,?)").run(id(), actor?.id || null, action, target, now());
}
function tokenFor(u){
  return jwt.sign({sub:u.id, role:u.role}, JWT_SECRET, {expiresIn:"8h"});
}

function paymentConfig(){
  return {
    mpesa: {
      consumerKey: process.env.MPESA_CONSUMER_KEY,
      consumerSecret: process.env.MPESA_CONSUMER_SECRET,
      shortcode: process.env.MPESA_SHORTCODE,
      passkey: process.env.MPESA_PASSKEY,
      callbackUrl: process.env.MPESA_CALLBACK_URL,
      environment: process.env.MPESA_ENVIRONMENT || "sandbox"
    },
    visa: {
      apiKey: process.env.VISA_API_KEY,
      sharedSecret: process.env.VISA_SHARED_SECRET,
      merchantId: process.env.VISA_MERCHANT_ID,
      environment: process.env.VISA_ENVIRONMENT || "sandbox"
    }
  };
}
function paymentMode(){ return (process.env.PAYMENT_MODE || "demo").toLowerCase(); }
function paymentBaseUrl(){
  return paymentConfig().mpesa.environment==="production"
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";
}
async function mpesaAccessToken(){
  const c=paymentConfig().mpesa;
  if(!c.consumerKey||!c.consumerSecret) throw Error("M-PESA credentials are not configured");
  const basic=Buffer.from(c.consumerKey+":"+c.consumerSecret).toString("base64");
  const r=await fetch(paymentBaseUrl()+"/oauth/v1/generate?grant_type=client_credentials",{headers:{Authorization:"Basic "+basic}});
  const d=await r.json();
  if(!r.ok||!d.access_token) throw Error("Unable to authenticate with M-PESA");
  return d.access_token;
}
function mpesaTimestamp(){
  const d=new Date();
  const pad=n=>String(n).padStart(2,"0");
  return d.getFullYear()+pad(d.getMonth()+1)+pad(d.getDate())+pad(d.getHours())+pad(d.getMinutes())+pad(d.getSeconds());
}
async function initiateMpesa(phone,amount,accountReference){
  const c=paymentConfig().mpesa;
  if(!c.shortcode||!c.passkey||!c.callbackUrl) throw Error("M-PESA merchant configuration is incomplete");
  const token=await mpesaAccessToken();
  const ts=mpesaTimestamp();
  const password=Buffer.from(c.shortcode+c.passkey+ts).toString("base64");
  const payload={
    BusinessShortCode:c.shortcode,Password:password,Timestamp:ts,TransactionType:"CustomerPayBillOnline",
    Amount:Math.max(1,Math.round(amount)),PartyA:phone,PartyB:c.shortcode,PhoneNumber:phone,
    CallBackURL:c.callbackUrl,AccountReference:accountReference,TransactionDesc:"RadCare consultation"
  };
  const r=await fetch(paymentBaseUrl()+"/mpesa/stkpush/v1/processrequest",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const d=await r.json();
  if(!r.ok||d.ResponseCode!=="0") throw Error(d.errorMessage||d.ResponseDescription||"M-PESA request failed");
  return {providerReference:d.CheckoutRequestID,checkoutReference:d.MerchantRequestID,status:"pending",raw:d};
}

function auth(req,res,next){
  try{
    const token=req.cookies.radcare_token || (req.headers.authorization||"").replace(/^Bearer\s+/,"");
    if(!token) return res.status(401).json({error:"Authentication required"});
    const p=jwt.verify(token,JWT_SECRET);
    const u=db.prepare("SELECT * FROM users WHERE id=?").get(p.sub);
    if(!u || u.status==="suspended" || u.status==="rejected") return res.status(401).json({error:"Account unavailable"});
    req.user=u; next();
  }catch(e){ return res.status(401).json({error:"Invalid or expired session"}); }
}
function roles(...allowed){
  return (req,res,next)=>allowed.includes(req.user.role)?next():res.status(403).json({error:"Insufficient permissions"});
}

app.post("/api/auth/register", async (req,res)=>{
  try{
    const {name,email,password,country,role}=req.body;
    if(!name||!email||!password||!country||!["patient","radiographer","student"].includes(role))
      return res.status(400).json({error:"Complete all required fields"});
    if(password.length<8) return res.status(400).json({error:"Password must be at least 8 characters"});
    const normalized=email.trim().toLowerCase();
    if(db.prepare("SELECT id FROM users WHERE email=?").get(normalized))
      return res.status(409).json({error:"Email already registered"});
    const status=role==="radiographer"?"pending":"approved";
    const u={id:id(),name:name.trim(),email:normalized,password_hash:await bcrypt.hash(password,12),country:country.trim(),role,status,created_at:now()};
    db.prepare("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)").run(u.id,u.name,u.email,u.password_hash,u.country,u.role,u.status,u.created_at);
    log(u,"ACCOUNT_CREATED",u.id);
    res.status(201).json({user:publicUser(u),message:status==="pending"?"Radiographer application submitted for approval":"Account created"});
  }catch(e){res.status(500).json({error:"Registration failed"});}
});

app.post("/api/auth/login", async (req,res)=>{
  const {email,password}=req.body;
  const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").trim().toLowerCase());
  if(!u || !(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"Invalid email or password"});
  if(u.role==="radiographer" && u.status!=="approved") return res.status(403).json({error:"Radiographer account is pending approval"});
  if(u.status!=="approved") return res.status(403).json({error:"Account is not active"});
  const token=tokenFor(u);
  res.cookie("radcare_token",token,{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production" || process.env.FORCE_SECURE_COOKIE==="true",maxAge:8*60*60*1000});
  log(u,"LOGIN");
  res.json({user:publicUser(u)});
});
app.post("/api/auth/logout",(req,res)=>{res.clearCookie("radcare_token");res.json({ok:true});});
app.get("/api/auth/me",auth,(req,res)=>res.json({user:publicUser(req.user)}));

app.get("/api/radiographers",auth,(req,res)=>{
  const rows=db.prepare("SELECT id,name,country,created_at FROM users WHERE role='radiographer' AND status='approved' ORDER BY name").all();
  res.json({radiographers:rows});
});

app.post("/api/appointments",auth,roles("patient"),(req,res)=>{
  const {radiographerId,serviceId,appointmentAt}=req.body;
  const r=db.prepare("SELECT id FROM users WHERE id=? AND role='radiographer' AND status='approved'").get(radiographerId);
  if(!r) return res.status(400).json({error:"Approved radiographer not found"});
  if(!appointmentAt) return res.status(400).json({error:"Appointment time required"});
  const dt=new Date(appointmentAt);
  if(Number.isNaN(dt.getTime()) || dt.getTime() < Date.now()-60000) return res.status(400).json({error:"Choose a valid future appointment time"});
  let service=null;
  if(serviceId){
    service=db.prepare("SELECT id,title,price_cents,currency FROM services WHERE id=? AND radiographer_id=? AND active=1").get(serviceId,radiographerId);
    if(!service) return res.status(400).json({error:"Service not found or inactive"});
  }
  const a={id:id(),patient_id:req.user.id,radiographer_id:radiographerId,appointment_at:dt.toISOString(),status:"requested",created_at:now(),service_id:service?.id||null,amount_cents:service?.price_cents||null,currency:service?.currency||null};
  db.prepare("INSERT INTO appointments (id,patient_id,radiographer_id,appointment_at,status,created_at,service_id,amount_cents,currency) VALUES (?,?,?,?,?,?,?,?,?)").run(a.id,a.patient_id,a.radiographer_id,a.appointment_at,a.status,a.created_at,a.service_id,a.amount_cents,a.currency);
  log(req.user,"APPOINTMENT_CREATED",a.id);
  res.status(201).json({appointment:a,service});
});
app.get("/api/appointments",auth,(req,res)=>{
  const base=`SELECT a.*, r.name radiographer_name, p.name patient_name, s.title service_title FROM appointments a JOIN users r ON r.id=a.radiographer_id JOIN users p ON p.id=a.patient_id LEFT JOIN services s ON s.id=a.service_id`;
  const rows=req.user.role==="patient"
    ? db.prepare(base+" WHERE a.patient_id=? ORDER BY appointment_at").all(req.user.id)
    : req.user.role==="radiographer"
    ? db.prepare(base+" WHERE a.radiographer_id=? ORDER BY appointment_at").all(req.user.id)
    : db.prepare(base+" ORDER BY appointment_at").all();
  res.json({appointments:rows});
});

const storage=multer.diskStorage({
  destination:(req,file,cb)=>cb(null,uploadDir),
  filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())
});
const upload=multer({
  storage,
  limits:{fileSize:MAX_MB*1024*1024},
  fileFilter:(req,file,cb)=>{
    const allowed=["application/pdf","image/jpeg","image/png","application/dicom","application/octet-stream"];
    cb(null,allowed.includes(file.mimetype));
  }
});
app.post("/api/files",auth,roles("patient"),upload.array("files",10),(req,res)=>{
  const saved=[];
  for(const f of req.files){
    const rec={id:id(),owner_id:req.user.id,original_name:f.originalname,stored_name:f.filename,mime_type:f.mimetype,size:f.size,created_at:now()};
    db.prepare("INSERT INTO files VALUES (?,?,?,?,?,?,?)").run(rec.id,rec.owner_id,rec.original_name,rec.stored_name,rec.mime_type,rec.size,rec.created_at);
    log(req.user,"FILE_UPLOADED",rec.id); saved.push({id:rec.id,name:rec.original_name,size:rec.size});
  }
  res.status(201).json({files:saved});
});

app.get("/api/admin/radiographers",auth,roles("admin"),(req,res)=>{
  const rows=db.prepare("SELECT id,name,email,country,status,created_at FROM users WHERE role='radiographer' ORDER BY created_at DESC").all();
  res.json({radiographers:rows});
});
app.post("/api/admin/radiographers/:id/approve",auth,roles("admin"),(req,res)=>{
  const result=db.prepare("UPDATE users SET status='approved' WHERE id=? AND role='radiographer'").run(req.params.id);
  if(!result.changes) return res.status(404).json({error:"Radiographer not found"});
  log(req.user,"RADIOGRAPHER_APPROVED",req.params.id); res.json({ok:true});
});
app.post("/api/admin/radiographers/:id/reject",auth,roles("admin"),(req,res)=>{
  const result=db.prepare("UPDATE users SET status='rejected' WHERE id=? AND role='radiographer'").run(req.params.id);
  if(!result.changes) return res.status(404).json({error:"Radiographer not found"});
  log(req.user,"RADIOGRAPHER_REJECTED",req.params.id); res.json({ok:true});
});

app.get("/api/admin/stats",auth,roles("admin"),(req,res)=>{
  const count=role=>db.prepare("SELECT COUNT(*) n FROM users WHERE role=?").get(role).n;
  res.json({users:db.prepare("SELECT COUNT(*) n FROM users").get().n,patients:count("patient"),radiographers:count("radiographer"),students:count("student"),pending:db.prepare("SELECT COUNT(*) n FROM users WHERE role='radiographer' AND status='pending'").get().n});
});


app.get("/api/patient/profile",auth,roles("patient"),(req,res)=>{
  const p=db.prepare("SELECT * FROM patient_profiles WHERE user_id=?").get(req.user.id);
  res.json({profile:p||null});
});
app.put("/api/patient/profile",auth,roles("patient"),(req,res)=>{
  const {phone,dateOfBirth,emergencyContact}=req.body;
  const existing=db.prepare("SELECT id FROM patient_profiles WHERE user_id=?").get(req.user.id);
  if(existing) db.prepare("UPDATE patient_profiles SET phone=?,date_of_birth=?,emergency_contact=? WHERE user_id=?")
    .run(phone||null,dateOfBirth||null,emergencyContact||null,req.user.id);
  else db.prepare("INSERT INTO patient_profiles VALUES (?,?,?,?,?,?)")
    .run(id(),req.user.id,phone||null,dateOfBirth||null,emergencyContact||null,now());
  log(req.user,"PATIENT_PROFILE_UPDATED",req.user.id);
  res.json({ok:true});
});

app.post("/api/services",auth,roles("radiographer"),(req,res)=>{
  const {title,description,priceCents,currency,durationMinutes}=req.body;
  if(!title || !Number.isInteger(Number(priceCents)) || Number(priceCents)<0)
    return res.status(400).json({error:"Valid title and non-negative price are required"});
  const s={id:id(),radiographer_id:req.user.id,title:title.trim(),description:description||"",price_cents:Number(priceCents),
    currency:(currency||"USD").toUpperCase(),duration_minutes:Number(durationMinutes||30),active:1,created_at:now()};
  db.prepare("INSERT INTO services VALUES (?,?,?,?,?,?,?,?)").run(s.id,s.radiographer_id,s.title,s.description,s.price_cents,s.currency,s.duration_minutes,s.active,s.created_at);
  log(req.user,"SERVICE_CREATED",s.id); res.status(201).json({service:s});
});
app.get("/api/my/services",auth,roles("radiographer"),(req,res)=>{
  res.json({services:db.prepare("SELECT * FROM services WHERE radiographer_id=? ORDER BY created_at DESC").all(req.user.id)});
});
app.patch("/api/services/:id",auth,roles("radiographer"),(req,res)=>{
  const s=db.prepare("SELECT * FROM services WHERE id=? AND radiographer_id=?").get(req.params.id,req.user.id);
  if(!s) return res.status(404).json({error:"Service not found"});
  const title=String(req.body.title??s.title).trim();
  const description=String(req.body.description??s.description).trim();
  const price=Number(req.body.priceCents??s.price_cents);
  const duration=Number(req.body.durationMinutes??s.duration_minutes);
  const active=req.body.active===undefined?s.active:(req.body.active?1:0);
  if(!title || !Number.isInteger(price) || price<0 || !Number.isInteger(duration) || duration<5) return res.status(400).json({error:"Invalid service details"});
  db.prepare("UPDATE services SET title=?,description=?,price_cents=?,duration_minutes=?,active=? WHERE id=? AND radiographer_id=?").run(title,description,price,duration,active,s.id,req.user.id);
  log(req.user,"SERVICE_UPDATED",s.id); res.json({ok:true});
});
app.delete("/api/services/:id",auth,roles("radiographer"),(req,res)=>{
  const r=db.prepare("UPDATE services SET active=0 WHERE id=? AND radiographer_id=?").run(req.params.id,req.user.id);
  if(!r.changes) return res.status(404).json({error:"Service not found"});
  log(req.user,"SERVICE_DEACTIVATED",req.params.id); res.json({ok:true});
});

app.get("/api/radiographers/:id/services",auth,(req,res)=>{
  const rows=db.prepare("SELECT id,title,description,price_cents,currency,duration_minutes FROM services WHERE radiographer_id=? AND active=1 ORDER BY title").all(req.params.id);
  res.json({services:rows});
});

app.post("/api/conversations",auth,roles("patient"),(req,res)=>{
  const r=db.prepare("SELECT id FROM users WHERE id=? AND role='radiographer' AND status='approved'").get(req.body.radiographerId);
  if(!r) return res.status(404).json({error:"Approved radiographer not found"});
  let c=db.prepare("SELECT * FROM conversations WHERE patient_id=? AND radiographer_id=?").get(req.user.id,r.id);
  if(!c){c={id:id(),patient_id:req.user.id,radiographer_id:r.id,created_at:now()};
    db.prepare("INSERT INTO conversations VALUES (?,?,?,?)").run(c.id,c.patient_id,c.radiographer_id,c.created_at);
    log(req.user,"CONVERSATION_CREATED",c.id);
  }
  res.status(201).json({conversation:c});
});
app.get("/api/conversations",auth,(req,res)=>{
  const rows=req.user.role==="patient"
    ? db.prepare("SELECT c.*,u.name radiographer_name FROM conversations c JOIN users u ON u.id=c.radiographer_id WHERE c.patient_id=? ORDER BY c.created_at DESC").all(req.user.id)
    : req.user.role==="radiographer"
    ? db.prepare("SELECT c.*,u.name patient_name FROM conversations c JOIN users u ON u.id=c.patient_id WHERE c.radiographer_id=? ORDER BY c.created_at DESC").all(req.user.id)
    : [];
  res.json({conversations:rows});
});
app.get("/api/conversations/:id/messages",auth,(req,res)=>{
  const c=db.prepare("SELECT * FROM conversations WHERE id=?").get(req.params.id);
  if(!c) return res.status(404).json({error:"Conversation not found"});
  if(c.patient_id!==req.user.id && c.radiographer_id!==req.user.id && req.user.role!=="admin") return res.status(403).json({error:"Access denied"});
  res.json({messages:db.prepare("SELECT id,sender_id,body,created_at FROM messages WHERE conversation_id=? ORDER BY created_at").all(c.id)});
});
app.post("/api/conversations/:id/messages",auth,(req,res)=>{
  const c=db.prepare("SELECT * FROM conversations WHERE id=?").get(req.params.id);
  if(!c) return res.status(404).json({error:"Conversation not found"});
  if(c.patient_id!==req.user.id && c.radiographer_id!==req.user.id) return res.status(403).json({error:"Access denied"});
  const body=String(req.body.body||"").trim();
  if(!body || body.length>4000) return res.status(400).json({error:"Message must be 1–4000 characters"});
  const m={id:id(),conversation_id:c.id,sender_id:req.user.id,body,created_at:now()};
  db.prepare("INSERT INTO messages VALUES (?,?,?,?)").run(m.id,m.conversation_id,m.sender_id,m.body,m.created_at);
  log(req.user,"MESSAGE_SENT",m.id); res.status(201).json({message:m});
});

app.post("/api/appointments/:id/status",auth,(req,res)=>{
  const allowed=["requested","confirmed","cancelled","completed"];
  const status=req.body.status;
  if(!allowed.includes(status)) return res.status(400).json({error:"Invalid status"});
  const a=db.prepare("SELECT * FROM appointments WHERE id=?").get(req.params.id);
  if(!a) return res.status(404).json({error:"Appointment not found"});
  const permitted=req.user.role==="admin" || a.patient_id===req.user.id || a.radiographer_id===req.user.id;
  if(!permitted) return res.status(403).json({error:"Access denied"});
  db.prepare("UPDATE appointments SET status=? WHERE id=?").run(status,a.id);
  log(req.user,"APPOINTMENT_STATUS_"+status.toUpperCase(),a.id);
  res.json({ok:true});
});


app.post("/api/payments/create",auth,roles("patient"),async(req,res)=>{
  try{
    const {appointmentId,provider,amountCents,currency,phone}=req.body;
    const a=db.prepare("SELECT * FROM appointments WHERE id=? AND patient_id=?").get(appointmentId,req.user.id);
    if(!a) return res.status(404).json({error:"Appointment not found"});
    const amount=Number(amountCents);
    if(!Number.isInteger(amount)||amount<=0) return res.status(400).json({error:"Invalid amount"});
    const p=(provider||"").toLowerCase();
    if(!["mpesa","visa","demo"].includes(p)) return res.status(400).json({error:"Unsupported payment method"});
    const pay={id:id(),user_id:req.user.id,appointment_id:a.id,provider:p,amount_cents:amount,currency:(currency||"USD").toUpperCase(),
      status:"pending",provider_reference:null,checkout_reference:null,created_at:now(),updated_at:now()};
    if(p==="demo" || paymentMode()==="demo"){
      pay.provider="demo"; pay.status="paid"; pay.provider_reference="DEMO-"+pay.id;
    } else if(p==="mpesa"){
      if(pay.currency!=="KES") return res.status(400).json({error:"M-PESA payments must use KES"});
      if(!phone) return res.status(400).json({error:"Kenyan M-PESA phone number is required"});
      const r=await initiateMpesa(phone,Math.ceil(amount/100), "RAD-"+a.id.slice(0,12));
      pay.provider_reference=r.providerReference; pay.checkout_reference=r.checkoutReference;
    } else if(p==="visa"){
      // Never collect card PAN/CVV here. A production Visa/acquirer hosted checkout/tokenization flow must be used.
      if(!paymentConfig().visa.apiKey && paymentMode()!=="demo")
        return res.status(503).json({error:"Visa gateway credentials are not configured"});
      pay.status="pending";
      pay.provider_reference="VISA_CHECKOUT_PENDING-"+pay.id;
    }
    db.prepare("INSERT INTO payments VALUES (?,?,?,?,?,?,?,?,?,?,?)").run(pay.id,pay.user_id,pay.appointment_id,pay.provider,pay.amount_cents,pay.currency,pay.status,pay.provider_reference,pay.checkout_reference,pay.created_at,pay.updated_at);
    log(req.user,"PAYMENT_CREATED",pay.id);
    res.status(201).json({payment:{id:pay.id,provider:pay.provider,status:pay.status,amountCents:pay.amount_cents,currency:pay.currency,providerReference:pay.provider_reference,checkoutReference:pay.checkout_reference}});
  }catch(e){res.status(502).json({error:e.message||"Payment initiation failed"});}
});

app.post("/api/payments/mpesa/callback",express.json({type:"application/json"}),(req,res)=>{
  const cb=req.body?.Body?.stkCallback;
  if(!cb) return res.json({ResultCode:0,ResultDesc:"Accepted"});
  const checkoutId=cb.CheckoutRequestID;
  const pay=db.prepare("SELECT * FROM payments WHERE provider='mpesa' AND provider_reference=?").get(checkoutId);
  if(pay){
    const status=Number(cb.ResultCode)===0?"paid":"failed";
    db.prepare("UPDATE payments SET status=?,updated_at=? WHERE id=?").run(status,now(),pay.id);
    log(null,"MPESA_CALLBACK_"+status.toUpperCase(),pay.id);
  }
  res.json({ResultCode:0,ResultDesc:"Accepted"});
});

app.get("/api/payments",auth,(req,res)=>{
  const rows=req.user.role==="admin"
    ? db.prepare("SELECT * FROM payments ORDER BY created_at DESC").all()
    : db.prepare("SELECT * FROM payments WHERE user_id=? ORDER BY created_at DESC").all(req.user.id);
  res.json({payments:rows});
});

app.get("/api/files",auth,(req,res)=>{
  const rows=req.user.role==="admin"
    ? db.prepare("SELECT f.id,f.owner_id,f.original_name,f.mime_type,f.size,f.created_at,u.name owner_name,u.email owner_email FROM files f JOIN users u ON u.id=f.owner_id ORDER BY f.created_at DESC").all()
    : db.prepare("SELECT id,original_name,mime_type,size,created_at FROM files WHERE owner_id=? ORDER BY created_at DESC").all(req.user.id);
  res.json({files:rows});
});

app.get("/api/files/:id",auth,(req,res)=>{
  const f=db.prepare("SELECT * FROM files WHERE id=?").get(req.params.id);
  if(!f) return res.status(404).json({error:"File not found"});
  if(req.user.role!=="admin" && f.owner_id!==req.user.id) return res.status(403).json({error:"Access denied"});
  const full=path.join(uploadDir,f.stored_name);
  if(!fs.existsSync(full)) return res.status(404).json({error:"Stored file not found"});
  res.download(full,f.original_name);
});

app.get("/api/admin/users",auth,roles("admin"),(req,res)=>{
  const rows=db.prepare("SELECT id,name,email,country,role,status,created_at FROM users ORDER BY created_at DESC").all();
  res.json({users:rows});
});

app.post("/api/admin/users/:id/status",auth,roles("admin"),(req,res)=>{
  const status=req.body.status;
  if(!["approved","suspended","rejected"].includes(status)) return res.status(400).json({error:"Invalid account status"});
  const target=db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if(!target) return res.status(404).json({error:"User not found"});
  if(target.id===req.user.id) return res.status(400).json({error:"You cannot change your own status"});
  db.prepare("UPDATE users SET status=? WHERE id=?").run(status,target.id);
  log(req.user,"USER_STATUS_"+status.toUpperCase(),target.id); res.json({ok:true});
});

app.get("/api/health",(req,res)=>res.status(200).json({ok:true,service:"RadCare API",version:"6.0.0"}));


app.use((err,req,res,next)=>{
  if(err instanceof multer.MulterError) return res.status(400).json({error:err.message});
  if(err) return res.status(400).json({error:err.message||"Request failed"});
  next();
});

app.get("/{*splat}",(req,res)=>{
  if(req.path.startsWith("/api/")) return res.status(404).json({error:"API route not found"});
  res.sendFile(path.join(__dirname,"public","index.html"));
});

app.listen(PORT,()=>console.log(`RadCare V6 running at http://localhost:${PORT}`));
