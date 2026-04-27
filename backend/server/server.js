import express from 'express';
import cors from 'cors';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = "CDR_Forensic_Secret_2026";

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const DATA_DIR    = path.join(process.cwd(), 'data');
const UPLOADS_DIR = path.join(process.cwd(), 'uploads');
const CASES_FILE  = path.join(DATA_DIR, 'cases.json');
const USERS_FILE  = path.join(DATA_DIR, 'users.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
console.log('✅ data and uploads folders ready');

if (!fs.existsSync(CASES_FILE)) fs.writeFileSync(CASES_FILE, JSON.stringify({ cases: [] }, null, 2));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

const loadUsers = () => JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
const saveUsers = (d) => fs.writeFileSync(USERS_FILE, JSON.stringify(d, null, 2));
const loadCases = () => JSON.parse(fs.readFileSync(CASES_FILE, 'utf8'));
const saveCases = (d) => fs.writeFileSync(CASES_FILE, JSON.stringify(d, null, 2));

const authenticateToken = (req, res, next) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(403).json({ error: "Invalid token" }); }
};

// Health
app.get('/api/health', (req, res) => res.json({ status: "OK", version: "4.0" }));

// Serve uploads folder
app.use('/uploads', express.static(UPLOADS_DIR));

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password, fullName } = req.body;
  const db = loadUsers();
  if (db.users.find(u => u.username === username))
    return res.status(400).json({ error: "User already exists" });
  const hashed = await bcrypt.hash(password, 10);
  db.users.push({ id: 'u-' + Date.now(), username, fullName: fullName || username, password: hashed });
  saveUsers(db);
  res.json({ message: "Registered successfully" });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const db = loadUsers();
  const user = db.users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(400).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, username, fullName: user.fullName }, JWT_SECRET);
  res.json({ token, username, user: { id: user.id, username, fullName: user.fullName } });
});

// Cases - GET all
app.get('/api/cases', authenticateToken, (req, res) => res.json(loadCases().cases));

// Cases - CREATE
app.post('/api/cases', authenticateToken, (req, res) => {
  const db = loadCases();
  const newCase = {
    id: 'c-' + Date.now(),
    caseNumber:  req.body.caseNumber  || `CASE-${Date.now()}`,
    victimName:  req.body.victimName  || '',
    description: req.body.description || '',
    createdAt:   Date.now(),
    createdBy:   req.user?.username   || '',
    files: [],
    analysis: []
  };
  db.cases.push(newCase);
  saveCases(db);
  res.json(newCase);
});

// Cases - GET one
app.get('/api/cases/:id', authenticateToken, (req, res) => {
  const c = loadCases().cases.find(c => c.id === req.params.id);
  if (!c) return res.status(404).json({ error: "Case not found" });
  res.json(c);
});

// Cases - DELETE
app.delete('/api/cases/:id', authenticateToken, (req, res) => {
  const db = loadCases();
  db.cases = db.cases.filter(c => c.id !== req.params.id);
  saveCases(db);
  res.json({ message: "Deleted" });
});

// ✅ FILE UPLOAD - FIXED (uploads folder mein jaegi ab)
app.post('/api/cases/:id/files', authenticateToken, upload.single('file'), (req, res) => {
  console.log(`📁 Upload request → case: ${req.params.id}`);

  if (!req.file) {
    console.log('❌ No file in request');
    return res.status(400).json({ error: "No file uploaded" });
  }

  const db = loadCases();
  const caseItem = db.cases.find(c => c.id === req.params.id);
  if (!caseItem) return res.status(404).json({ error: "Case not found" });

  const fileMeta = {
    id:          'f-' + Date.now(),
    name:        req.file.originalname,
    storedName:  req.file.filename,
    path:        req.file.path,
    size:        req.file.size,
    uploadedAt:  Date.now(),
    uploadedBy:  req.user?.username || 'unknown'
  };

  caseItem.files.push(fileMeta);
  saveCases(db);

  console.log(`✅ File saved → ${req.file.path}`);
  res.json({ message: "File uploaded successfully", file: fileMeta });
});

// Download file
app.get('/api/cases/:id/files/:fileId/download', authenticateToken, (req, res) => {
  const db = loadCases();
  const caseItem = db.cases.find(c => c.id === req.params.id);
  if (!caseItem) return res.status(404).json({ error: "Case not found" });
  const file = caseItem.files.find(f => f.id === req.params.fileId);
  if (!file || !fs.existsSync(file.path)) return res.status(404).json({ error: "File not found on disk" });
  res.download(file.path, file.name);
});

app.listen(PORT, () => {
  console.log(`🔥 CDR Backend running → http://localhost:${PORT}`);
  console.log(`📁 Uploads → ${UPLOADS_DIR}`);
});

// ==================== IP THREAT INTELLIGENCE ====================
const ABUSEIPDB_API_KEY = "d78965b3a5aea332a50c2133397f307703c020aaacfe782886b16fce925962a8efdfc35b3591499e";

const COUNTRY_NAMES = {
  IN:"India", US:"United States", GB:"United Kingdom", CN:"China", RU:"Russia",
  DE:"Germany", FR:"France", JP:"Japan", BR:"Brazil", AU:"Australia", CA:"Canada",
  KR:"South Korea", NL:"Netherlands", SG:"Singapore", HK:"Hong Kong", PK:"Pakistan",
  BD:"Bangladesh", TR:"Turkey", IR:"Iran", UA:"Ukraine", IT:"Italy", ES:"Spain",
  PL:"Poland", SE:"Sweden", NO:"Norway", FI:"Finland", DK:"Denmark", ID:"Indonesia",
  TH:"Thailand", MY:"Malaysia", VN:"Vietnam", NG:"Nigeria", ZA:"South Africa",
  EG:"Egypt", KE:"Kenya", MX:"Mexico", AR:"Argentina", CL:"Chile", CO:"Colombia",
  AE:"United Arab Emirates", SA:"Saudi Arabia", IL:"Israel", CH:"Switzerland",
  AT:"Austria", BE:"Belgium", PT:"Portugal", CZ:"Czech Republic", RO:"Romania",
  HU:"Hungary", BG:"Bulgaria", LK:"Sri Lanka", NP:"Nepal", PH:"Philippines", TW:"Taiwan",
};

app.post('/api/ip-bulk', async (req, res) => {
  try {
    const { ips } = req.body;
    if (!Array.isArray(ips) || !ips.length)
      return res.status(400).json({ error: "No IPs" });

    console.log(`🔍 IP Bulk: ${ips.length} IPs`);
    const results = [];

    for (const ip of ips) {
      const cleanIP = String(ip).trim();
      if (!cleanIP) continue;
      console.log(`  ⟶ ${cleanIP}`);

      let basic = {};
      let threat = { abuseScore:0, reports:0, lastReported:'—', usageType:'—', domain:'—', isWhitelisted:false };

      try {
        const aRes = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${cleanIP}&maxAgeInDays=90`,
          { headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' } }
        );
        const aText = await aRes.text();
        console.log(`    📦 AbuseIPDB: ${aText.slice(0,200)}`);

        if (aRes.ok) {
          const d = JSON.parse(aText)?.data;
          if (d) {
            let city = '—';
            try {
              const g = await fetch(`https://ipwho.is/${cleanIP}`);
              if (g.ok) { const gd = await g.json(); if (gd.success !== false) city = gd.city || '—'; }
            } catch {}

            basic = {
              type:    d.ipVersion === 6 ? 'IPv6' : 'IPv4',
              country: COUNTRY_NAMES[d.countryCode] || d.countryCode || '—',
              city,
              connection: { isp: d.isp || '—', org: d.domain || '—', asn: '—' }
            };
            threat = {
              abuseScore:   d.abuseConfidenceScore ?? 0,
              reports:      d.totalReports         ?? 0,
              lastReported: d.lastReportedAt        || '—',
              usageType:    d.usageType             || '—',
              domain:       d.domain                || '—',
              isWhitelisted: d.isWhitelisted        || false
            };
            console.log(`    ✅ ${basic.country} | ${basic.city} | ${basic.connection.isp} | Score:${threat.abuseScore}`);
          }
        }
      } catch (e) { console.log(`    ❌ ${e.message}`); }

      results.push({ ip: cleanIP, basic, threat,
        riskLevel: threat.abuseScore >= 70 ? "HIGH" : threat.abuseScore >= 30 ? "MEDIUM" : "LOW"
      });
    }

    console.log(`✅ IP Scan done: ${results.length} results`);
    res.json({ count: results.length, results });
  } catch (err) {
    console.error("❌", err);
    res.status(500).json({ error: err.message });
  }
});
