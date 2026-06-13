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

const SUPABASE_URL  = process.env.SUPABASE_URL  || '';
const SUPABASE_KEY  = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY || '';
const JWT_SECRET    = process.env.JWT_SECRET    || 'pl-live-secret-2026';
const ADMIN_USER    = process.env.ADMIN_USER    || 'admin';
const ADMIN_PASS    = process.env.ADMIN_PASS    || 'pl-admin-2026';
const PORT          = process.env.PORT          || 3000;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

/* ── HELPERS ── */

function requireAuth(req, res, next) {
  const auth  = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Geen token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Ongeldig token' });
  }
}

function requireAdmin(req, res, next) {
  const auth  = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Geen token' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    if (user.role !== 'admin') return res.status(403).json({ error: 'Geen admin toegang' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Ongeldig token' });
  }
}

// Auth middleware for live routes: accept admin OR matching guest token
function requireLiveAccess(req, res, next) {
  const auth  = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Geen token' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    if (user.role === 'admin' || user.slug === req.params.slug) {
      req.user = user;
      return next();
    }
    return res.status(403).json({ error: 'Verboden' });
  } catch {
    res.status(401).json({ error: 'Ongeldig token' });
  }
}

// Auto-generate Dutch trading days for a live
function generateTradingDays(startDateStr, numWeeks) {
  const NL_DAYS   = ['Zondag','Maandag','Dinsdag','Woensdag','Donderdag','Vrijdag','Zaterdag'];
  const NL_SHORT  = ['Zo','Ma','Di','Wo','Do','Vr','Za'];
  const NL_MONTHS = ['Januari','Februari','Maart','April','Mei','Juni','Juli','Augustus','September','Oktober','November','December'];

  const start = new Date(startDateStr + 'T12:00:00Z');
  const dow   = start.getUTCDay();
  const monday = new Date(start);
  monday.setUTCDate(start.getUTCDate() - (dow === 0 ? 6 : dow - 1));

  const days = [];
  for (let w = 0; w < numWeeks; w++) {
    for (let d = 0; d < 5; d++) {
      const date = new Date(monday);
      date.setUTCDate(monday.getUTCDate() + w * 7 + d);
      const wd = date.getUTCDay();
      days.push({
        num:   days.length + 1,
        label: `${NL_DAYS[wd]} ${date.getUTCDate()} ${NL_MONTHS[date.getUTCMonth()]}`,
        short: `${String(date.getUTCDate()).padStart(2,'0')} ${NL_MONTHS[date.getUTCMonth()].slice(0,3)}`,
        week:  w + 1,
        day:   NL_SHORT[wd]
      });
    }
  }
  return days;
}

function generateSlug(title, startDateStr) {
  const year = new Date(startDateStr + 'T12:00:00Z').getUTCFullYear();
  const base = title
    .toLowerCase()
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9\s]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .slice(0, 44);
  return `${base}-${year}`;
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
}

/* ════════════════════════════════
   PUBLIC ROUTES
════════════════════════════════ */

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/live/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'live.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Public list of lives (metadata only, no passcode)
app.get('/api/lives', async (req, res) => {
  const { data, error } = await supabase
    .from('lives')
    .select('id, slug, title, subtitle, date_range, is_active, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Public: title/subtitle/date for auth overlay (no passcode)
app.get('/api/live-info/:slug', async (req, res) => {
  const { data, error } = await supabase
    .from('lives')
    .select('title, subtitle, date_range')
    .eq('slug', req.params.slug)
    .single();
  if (error || !data) return res.status(404).json({ error: 'Niet gevonden' });
  res.json(data);
});

// Guest login: name + passcode → JWT + log
app.post('/api/auth', async (req, res) => {
  const { slug, passcode, name } = req.body || {};
  if (!slug || !passcode || !name?.trim()) {
    return res.status(400).json({ error: 'Naam en code zijn verplicht' });
  }

  const { data: live, error } = await supabase
    .from('lives')
    .select('*')
    .eq('slug', slug)
    .single();

  if (error || !live) return res.status(404).json({ error: 'Live niet gevonden' });
  if (!live.is_active) return res.status(403).json({ error: 'Deze sessie is niet actief' });
  if (live.passcode !== passcode) return res.status(401).json({ error: 'Verkeerde code' });

  // Log the visit
  await supabase.from('access_log').insert({
    live_id: live.id,
    name:    name.trim(),
    ip:      getClientIp(req)
  });

  const token = jwt.sign(
    { live_id: live.id, slug, role: 'guest', name: name.trim() },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  const { passcode: _p, ...safeLive } = live;
  res.json({ token, live: safeLive });
});

/* ════════════════════════════════
   LIVE PROTECTED ROUTES
════════════════════════════════ */

app.get('/api/live/:slug', requireLiveAccess, async (req, res) => {
  const { data: live, error } = await supabase
    .from('lives')
    .select('*')
    .eq('slug', req.params.slug)
    .single();
  if (error || !live) return res.status(404).json({ error: 'Niet gevonden' });
  const { passcode: _p, ...safeLive } = live;
  res.json(safeLive);
});

app.get('/api/slides/:slug', requireLiveAccess, async (req, res) => {
  // Resolve live_id from slug (admin JWT doesn't carry it)
  const liveId = req.user.role === 'admin'
    ? (await supabase.from('lives').select('id').eq('slug', req.params.slug).single()).data?.id
    : req.user.live_id;
  if (!liveId) return res.status(404).json({ error: 'Niet gevonden' });

  const { data, error } = await supabase
    .from('slide_data')
    .select('slide_idx, slot_key, value')
    .eq('live_id', liveId)
    .order('slide_idx');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Guests cannot save
app.post('/api/save', requireLiveAccess, async (req, res) => {
  if (req.user.role === 'guest') return res.status(403).json({ error: 'Geen schrijftoegang' });

  const { slide_idx, slot_key, value } = req.body || {};
  if (slide_idx === undefined || !slot_key) return res.status(400).json({ error: 'Velden ontbreken' });

  const liveId = req.user.role === 'admin'
    ? (await supabase.from('lives').select('id').eq('slug', req.params?.slug || '').single()).data?.id || req.body.live_id
    : req.user.live_id;

  // For admin, get live_id from slug in body or resolve from token
  const resolvedLiveId = req.user.role === 'admin' ? req.body.live_id : req.user.live_id;
  if (!resolvedLiveId) return res.status(400).json({ error: 'live_id ontbreekt' });

  if (value === null || value === '') {
    const { error } = await supabase
      .from('slide_data')
      .delete()
      .eq('live_id', resolvedLiveId)
      .eq('slide_idx', slide_idx)
      .eq('slot_key', slot_key);
    if (error) return res.status(500).json({ error: error.message });
    return res.json({ ok: true });
  }

  const { error } = await supabase
    .from('slide_data')
    .upsert(
      { live_id: resolvedLiveId, slide_idx, slot_key, value, updated_at: new Date().toISOString() },
      { onConflict: 'live_id,slide_idx,slot_key' }
    );
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Guests cannot upload
app.post('/api/upload', requireLiveAccess, async (req, res) => {
  if (req.user.role === 'guest') return res.status(403).json({ error: 'Geen schrijftoegang' });

  const { slide_idx, slot_key, base64, live_id } = req.body || {};
  if (!base64) return res.status(400).json({ error: 'Geen afbeelding' });

  const resolvedLiveId = req.user.role === 'admin' ? live_id : req.user.live_id;
  if (!resolvedLiveId) return res.status(400).json({ error: 'live_id ontbreekt' });

  const matches = base64.match(/^data:([^;]+);base64,(.+)$/s);
  if (!matches) return res.status(400).json({ error: 'Ongeldig formaat' });

  const mimeType = matches[1];
  const ext      = mimeType.split('/')[1] || 'png';
  const buffer   = Buffer.from(matches[2], 'base64');
  const filename = `${resolvedLiveId}/${slide_idx}-${slot_key}-${Date.now()}.${ext}`;

  const { error: uploadErr } = await supabase.storage
    .from('live-slides')
    .upload(filename, buffer, { contentType: mimeType, upsert: true });
  if (uploadErr) return res.status(500).json({ error: uploadErr.message });

  const { data: { publicUrl } } = supabase.storage.from('live-slides').getPublicUrl(filename);

  await supabase.from('slide_data').upsert(
    { live_id: resolvedLiveId, slide_idx, slot_key, value: publicUrl, updated_at: new Date().toISOString() },
    { onConflict: 'live_id,slide_idx,slot_key' }
  );

  res.json({ url: publicUrl });
});

/* ════════════════════════════════
   ADMIN AUTH
════════════════════════════════ */

app.post('/api/admin/auth', (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).json({ error: 'Verkeerde inloggegevens' });
  }
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

/* ════════════════════════════════
   ADMIN ROUTES
════════════════════════════════ */

// All lives + access count + last access
app.get('/api/admin/lives', requireAdmin, async (req, res) => {
  const { data: lives, error } = await supabase
    .from('lives')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });

  const { data: counts } = await supabase
    .from('access_log')
    .select('live_id');

  const countMap = {};
  (counts || []).forEach(r => {
    countMap[r.live_id] = (countMap[r.live_id] || 0) + 1;
  });

  res.json(lives.map(l => ({ ...l, visitor_count: countMap[l.id] || 0 })));
});

// Create new live
app.post('/api/admin/lives', requireAdmin, async (req, res) => {
  const { title, subtitle, start_date, num_weeks, passcode } = req.body || {};
  if (!title || !start_date || !passcode) {
    return res.status(400).json({ error: 'Titel, startdatum en code zijn verplicht' });
  }

  const weeks = Math.min(Math.max(parseInt(num_weeks) || 1, 1), 4);
  const days  = generateTradingDays(start_date, weeks);
  const slug  = generateSlug(title, start_date);

  const firstDay = days[0];
  const lastDay  = days[days.length - 1];
  const dateRange = `${firstDay.label.split(' ').slice(1).join(' ')} — ${lastDay.label.split(' ').slice(1).join(' ')}`;

  const { data, error } = await supabase
    .from('lives')
    .insert({
      slug,
      title,
      subtitle:   subtitle || 'NQ Intraday',
      date_range: dateRange,
      days,
      passcode,
      is_active:  true
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Update live (passcode, title, is_active, etc.)
app.patch('/api/admin/lives/:id', requireAdmin, async (req, res) => {
  const allowed = ['title', 'subtitle', 'date_range', 'passcode', 'is_active'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  const { data, error } = await supabase
    .from('lives')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Access log — all or filtered by live_id
app.get('/api/admin/log', requireAdmin, async (req, res) => {
  let query = supabase
    .from('access_log')
    .select('id, live_id, name, logged_in_at, ip, lives(title, slug)')
    .order('logged_in_at', { ascending: false })
    .limit(200);

  if (req.query.live_id) {
    query = query.eq('live_id', req.query.live_id);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.listen(PORT, () => console.log(`Printing Lounge Live op poort ${PORT}`));
