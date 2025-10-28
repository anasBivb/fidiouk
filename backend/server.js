import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import ffmpeg from 'fluent-ffmpeg';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import Stripe from 'stripe';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const OPENAI_KEY = process.env.OPENAI_API_KEY;
const TEMP_DIR = process.env.TEMP_DIR || './tmp';
const FREE_CREDITS = parseInt(process.env.FREE_CREDITS || '5', 10);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '');

if(!OPENAI_KEY) {
  console.error('Missing OPENAI_API_KEY in .env');
  process.exit(1);
}

if(!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive:true });

// In-memory users (demo)
const users = {}; // { email: { email, credits, videos: [] } }

// Session + Passport (Google OAuth)
app.use(session({ secret: process.env.SESSION_SECRET || 'fidiouk_secret', resave:false, saveUninitialized:true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails && profile.emails[0] && profile.emails[0].value;
  if(!email) return done(new Error('No email in Google profile'));
  if(!users[email]) users[email] = { email, credits: FREE_CREDITS, videos: [] };
  return done(null, users[email]);
}));

passport.serializeUser((user, done) => done(null, user.email));
passport.deserializeUser((email, done) => done(null, users[email]));

app.get('/auth/google', passport.authenticate('google', { scope:['email','profile'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req,res) => {
  return res.redirect('/?logged=true&email=' + encodeURIComponent(req.user.email));
});

// Helpers: image + speech via OpenAI (may need model names adjusted)
async function generateImage(prompt, idx){
  const res = await fetch('https://api.openai.com/v1/images/generations', {
    method: 'POST',
    headers: { Authorization: `Bearer ${OPENAI_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'gpt-image-1', prompt, size:'1024x1024', n:1 })
  });
  const data = await res.json();
  const b64 = data?.data?.[0]?.b64_json;
  if(!b64) throw new Error('Image generation failed: ' + JSON.stringify(data));
  const buffer = Buffer.from(b64, 'base64');
  const filename = path.join(TEMP_DIR, `${uuidv4()}-${idx}.png`);
  fs.writeFileSync(filename, buffer);
  return filename;
}

async function generateSpeech(text, voice='arabic_fusha'){
  const res = await fetch('https://api.openai.com/v1/audio/speech', {
    method:'POST',
    headers:{ Authorization:`Bearer ${OPENAI_KEY}`, 'Content-Type':'application/json' },
    body: JSON.stringify({ model:'gpt-4o-mini-tts', voice, input: text })
  });
  if(res.status !== 200){ const t = await res.text(); throw new Error('TTS failed: ' + t); }
  const ab = await res.arrayBuffer();
  const outPath = path.join(TEMP_DIR, `${uuidv4()}.mp3`);
  fs.writeFileSync(outPath, Buffer.from(ab));
  return outPath;
}

function imagesAndAudioToVideo(imagePaths, audioPath, outPath){
  return new Promise((resolve, reject) => {
    ffmpeg.ffprobe(audioPath, (err, metadata) => {
      if(err) return reject(err);
      const duration = Math.max(1, metadata.format.duration || 5);
      const numImages = imagePaths.length;
      const seg = duration / numImages;
      const listFile = path.join(TEMP_DIR, `${uuidv4()}-list.txt`);
      const lines = imagePaths.map(p => `file '${path.resolve(p)}'\nduration ${seg}`).join('\n');
      const last = `file '${path.resolve(imagePaths[imagePaths.length-1])}'\n`;
      fs.writeFileSync(listFile, lines + '\n' + last);

      ffmpeg()
        .input(listFile)
        .inputOptions(['-f','concat','-safe','0'])
        .input(audioPath)
        .outputOptions(['-c:v libx264','-pix_fmt yuv420p','-c:a aac','-shortest'])
        .save(outPath)
        .on('end', ()=> { try{ fs.unlinkSync(listFile) }catch(e){}; resolve(outPath); })
        .on('error', (e)=> reject(e));
    });
  });
}

// Routes: signup/login (demo), generate video, create-checkout-session
app.post('/api/signup', (req,res)=>{
  const { email } = req.body; if(!email) return res.status(400).json({ error:'missing_email' });
  if(users[email]) return res.json({ ok:true, user: users[email] });
  users[email] = { email, credits: FREE_CREDITS, videos: [] };
  return res.json({ ok:true, user: users[email] });
});

app.post('/api/login', (req,res)=>{
  const { email } = req.body; if(!email) return res.status(400).json({ error:'missing_email' });
  if(!users[email]) return res.status(404).json({ error:'not_found' });
  return res.json({ ok:true, user: users[email] });
});

app.post('/api/generate', async (req,res)=>{
  try{
    const { email, text, style, voice } = req.body; if(!email || !text) return res.status(400).json({ error:'missing' });
    const user = users[email]; if(!user) return res.status(404).json({ error:'user_not_found' });
    if((user.credits||0) <= 0) return res.status(402).json({ error:'no_credits' });

    let numImages = 4;
    if(style === 'advert') numImages = 5;
    if(style === 'story') numImages = 4;
    if(style === 'educational') numImages = 3;

    const scenePrompts = [];
    for(let i=0;i<numImages;i++) scenePrompts.push(`${text} — مشهد ${i+1} بأسلوب ${style}. صورة جذابة ومناسبة لفيديو إعلاني باللغة العربية, تفصيلية, عالية الجودة`);

    const imagePaths = [];
    for(let i=0;i<scenePrompts.length;i++){
      const p = scenePrompts[i];
      const imgPath = await generateImage(p, i);
      imagePaths.push(imgPath);
    }

    const audioPath = await generateSpeech(text, voice || 'arabic_fusha');
    const outFile = path.join(TEMP_DIR, `${uuidv4()}.mp4`);
    await imagesAndAudioToVideo(imagePaths, audioPath, outFile);

    user.credits = Math.max(0, (user.credits||FREE_CREDITS) - 1);
    const videoRecord = { id: uuidv4(), file: outFile, date: new Date().toISOString() };
    user.videos.push(videoRecord);

    return res.json({ ok:true, file: `/api/video/${path.basename(outFile)}`, credits: user.credits });
  } catch(err){ console.error(err); return res.status(500).json({ error:'server_error', details:String(err) }); }
});

app.get('/api/video/:name', (req,res)=>{ const file = path.join(TEMP_DIR, req.params.name); if(!fs.existsSync(file)) return res.status(404).send('Not found'); res.sendFile(path.resolve(file)); });

app.post('/create-checkout-session', async (req,res)=>{
  const { priceId } = req.body;
  const session = await stripe.checkout.sessions.create({ mode:'subscription', line_items:[{ price: priceId, quantity:1 }], success_url: 'https://your-frontend-url/success', cancel_url: 'https://your-frontend-url/subscriptions' });
  res.json({ sessionId: session.id, publicKey: process.env.STRIPE_PUBLIC_KEY });
});

app.get('/api/status', (req,res)=> res.json({ ok:true }));

app.listen(PORT, ()=> console.log(`Server running on http://localhost:${PORT}`));
