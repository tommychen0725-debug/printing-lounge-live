const express = require('express');
const jwt     = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

// Node 18 WebSocket compat for Supabase Realtime
if (!globalThis.WebSocket) {
  globalThis.WebSocket = require('ws');
}

const app = express();
app.use(express.json({ limit: '30mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY || '';
const JWT_SECRET   = process.env.JWT_SECRET || 'pl-live-secret-2026';
const PORT         = process.env.PORT || 3000;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

/* ── AUTH MIDDLEWARE ── */
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Geen token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Ongeldig token' });
  }
}

/* ── ROUTES ── */

// Dashboard page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Live presentation page
app.get('/live/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'live.html'));
});

// Public: list all lives (no passcode, just metadata)
app.get('/api/lives', async (req, res) => {
  const { data, error } = await supabase
    .from('lives')
    .select('id, slug, title, subtitle, date_range, is_active, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Public: get basic live info for auth overlay (no passcode exposed)
app.get('/api/live-info/:slug', async (req, res) => {
  const { data, error } = await supabase
    .from('lives')
    .select('title, subtitle, date_range')
    .eq('slug', req.params.slug)
    .single();
  if (error || !data) return res.status(404).json({ error: 'Niet gevonden' });
  res.json(data);
});

// Auth: verify passcode → return JWT + full live config
app.post('/api/auth', async (req, res) => {
  const { slug, passcode } = req.body || {};
  if (!slug || !passcode) return res.status(400).json({ error: 'Velden ontbreken' });

  const { data: live, error } = await supabase
    .from('lives')
    .select('*')
    .eq('slug', slug)
    .single();

  if (error || !live) return res.status(404).json({ error: 'Live niet gevonden' });
  if (live.passcode !== passcode) return res.status(401).json({ error: 'Verkeerde code' });

  const token = jwt.sign(
    { live_id: live.id, slug },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  // Don't expose passcode to client
  const { passcode: _p, ...safeLive } = live;
  res.json({ token, live: safeLive });
});

// Protected: get full live config (includes days JSON)
app.get('/api/live/:slug', requireAuth, async (req, res) => {
  if (req.user.slug !== req.params.slug) return res.status(403).json({ error: 'Verboden' });

  const { data: live, error } = await supabase
    .from('lives')
    .select('*')
    .eq('slug', req.params.slug)
    .single();

  if (error || !live) return res.status(404).json({ error: 'Niet gevonden' });
  const { passcode: _p, ...safeLive } = live;
  res.json(safeLive);
});

// Protected: get all slide data for a live
app.get('/api/slides/:slug', requireAuth, async (req, res) => {
  if (req.user.slug !== req.params.slug) return res.status(403).json({ error: 'Verboden' });

  const { data, error } = await supabase
    .from('slide_data')
    .select('slide_idx, slot_key, value')
    .eq('live_id', req.user.live_id)
    .order('slide_idx');

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Protected: save notes or image URL
app.post('/api/save', requireAuth, async (req, res) => {
  const { slide_idx, slot_key, value } = req.body || {};
  if (slide_idx === undefined || !slot_key) return res.status(400).json({ error: 'Velden ontbreken' });

  if (value === null || value === '') {
    const { error } = await supabase
      .from('slide_data')
      .delete()
      .eq('live_id', req.user.live_id)
      .eq('slide_idx', slide_idx)
      .eq('slot_key', slot_key);
    if (error) return res.status(500).json({ error: error.message });
    return res.json({ ok: true });
  }

  const { error } = await supabase
    .from('slide_data')
    .upsert(
      { live_id: req.user.live_id, slide_idx, slot_key, value, updated_at: new Date().toISOString() },
      { onConflict: 'live_id,slide_idx,slot_key' }
    );

  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Protected: upload image to Supabase Storage
app.post('/api/upload', requireAuth, async (req, res) => {
  const { slide_idx, slot_key, base64 } = req.body || {};
  if (!base64) return res.status(400).json({ error: 'Geen afbeelding' });

  const matches = base64.match(/^data:([^;]+);base64,(.+)$/s);
  if (!matches) return res.status(400).json({ error: 'Ongeldig formaat' });

  const mimeType = matches[1];
  const ext = mimeType.split('/')[1] || 'png';
  const buffer = Buffer.from(matches[2], 'base64');
  const filename = `${req.user.live_id}/${slide_idx}-${slot_key}-${Date.now()}.${ext}`;

  const { error: uploadErr } = await supabase.storage
    .from('live-slides')
    .upload(filename, buffer, { contentType: mimeType, upsert: true });

  if (uploadErr) return res.status(500).json({ error: uploadErr.message });

  const { data: { publicUrl } } = supabase.storage
    .from('live-slides')
    .getPublicUrl(filename);

  // Persist URL in slide_data
  await supabase
    .from('slide_data')
    .upsert(
      { live_id: req.user.live_id, slide_idx, slot_key, value: publicUrl, updated_at: new Date().toISOString() },
      { onConflict: 'live_id,slide_idx,slot_key' }
    );

  res.json({ url: publicUrl });
});

app.listen(PORT, () => console.log(`Printing Lounge Live op poort ${PORT}`));
