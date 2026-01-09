const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Directories
const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(dataDir, 'uploads');
const backupDir = path.join(dataDir, 'backups');
const dbFile = path.join(dataDir, 'database.json');

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

// Database
let db = {
  users: [],
  materials: [],
  partiyalar: [],
  operations: [],
  ngRecords: [],
  certificates: [],
  counters: { materials: 0, partiyalar: 0, operations: 0, ngRecords: 0, certificates: 0 }
};

function loadDB() {
  try {
    if (fs.existsSync(dbFile)) {
      const data = fs.readFileSync(dbFile, 'utf8');
      db = JSON.parse(data);
      if (!db.counters) {
        db.counters = {
          materials: Math.max(0, ...db.materials.map(m => m.id), 0),
          partiyalar: Math.max(0, ...db.partiyalar.map(p => p.id), 0),
          operations: Math.max(0, ...db.operations.map(o => o.id), 0),
          ngRecords: Math.max(0, ...db.ngRecords.map(n => n.id), 0),
          certificates: Math.max(0, ...db.certificates.map(c => c.id), 0)
        };
      }
    }
  } catch (e) { console.error('DB load error:', e); }
}

function saveDB() {
  try {
    fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
  } catch (e) { console.error('DB save error:', e); }
}

function initUsers() {
  // v2.3 - Parollarni bir marta yangilash
  if (!db.passwordVersion || db.passwordVersion < 23) {
    // Kimyo admin
    const kimyo = db.users.find(u => u.username === 'Kimyo');
    if (kimyo) {
      kimyo.password = bcrypt.hashSync('123456', 10);
      kimyo.role = 'admin';
    } else {
      db.users.push({ id: 1, username: 'Kimyo', password: bcrypt.hashSync('123456', 10), role: 'admin' });
    }
    
    // bydombor viewer
    const viewer = db.users.find(u => u.username === 'bydombor');
    if (viewer) {
      viewer.password = bcrypt.hashSync('0035', 10);
      viewer.role = 'viewer';
    } else {
      db.users.push({ id: 2, username: 'bydombor', password: bcrypt.hashSync('0035', 10), role: 'viewer' });
    }
    
    db.passwordVersion = 23;
    saveDB();
    console.log('✅ Foydalanuvchilar yangilandi (v2.3)');
  }
}

// Auto backup
function autoBackup() {
  const today = new Date().toISOString().split('T')[0];
  const backupFile = path.join(backupDir, `backup_${today}.json`);
  if (!fs.existsSync(backupFile)) {
    try {
      fs.writeFileSync(backupFile, JSON.stringify(db, null, 2));
      console.log('📦 Auto backup:', backupFile);
      const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.json')).sort().reverse();
      files.slice(30).forEach(f => fs.unlinkSync(path.join(backupDir, f)));
    } catch (e) { console.error('Backup error:', e); }
  }
}

loadDB();
initUsers();
autoBackup();
setInterval(autoBackup, 3600000);
setInterval(saveDB, 60000);

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

// Session configuration for corporate server
const sessionConfig = {
  secret: 'byd-kimyoviy-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 86400000 * 7, // 7 days
    httpOnly: true,
    sameSite: 'lax'
  },
  name: 'byd.sid'
};

// Trust proxy for corporate network
app.set('trust proxy', 1);

app.use(session(sessionConfig));

const upload = multer({
  storage: multer.diskStorage({
    destination: (r, f, cb) => cb(null, uploadDir),
    filename: (r, f, cb) => cb(null, Date.now() + '-' + f.originalname.replace(/[^a-zA-Z0-9.-]/g, '_'))
  }),
  limits: { fileSize: 100 * 1024 * 1024 }
});

const auth = (req, res, next) => { if (!req.session.user) return res.status(401).json({ error: 'Login qiling' }); next(); };
const admin = (req, res, next) => { if (!req.session.user) return res.status(401).json({ error: 'Login qiling' }); if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Ruxsat yo\'q' }); next(); };

// AUTH
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Login yoki parol noto\'g\'ri' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ success: true, user: { username: user.username, role: user.role } });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', (req, res) => { if (!req.session.user) return res.status(401).json({ error: 'Not logged in' }); res.json({ user: req.session.user }); });

app.post('/api/change-password', admin, (req, res) => {
  const { currentPassword, newLogin, newPassword } = req.body;
  const user = db.users.find(u => u.id === req.session.user.id);
  if (!user || !bcrypt.compareSync(currentPassword, user.password)) return res.status(400).json({ error: 'Parol noto\'g\'ri' });
  user.username = newLogin;
  user.password = bcrypt.hashSync(newPassword, 10);
  req.session.user.username = newLogin;
  saveDB();
  res.json({ success: true });
});

// MATERIALS
app.get('/api/materials', auth, (req, res) => res.json(db.materials));

app.post('/api/materials', admin, (req, res) => {
  const { code, name, unit, minQty, expiryMonths, category } = req.body;
  if (db.materials.find(m => m.code === code)) return res.status(400).json({ error: 'Kod mavjud!' });
  const id = ++db.counters.materials;
  db.materials.push({ id, code, name, unit: unit || 'litr', minQty: minQty || 10, expiryMonths: expiryMonths || 12, category: category || 'oil', createdAt: new Date().toISOString() });
  saveDB();
  res.json({ success: true, id });
});

app.put('/api/materials/:id', admin, (req, res) => {
  const { code, name, unit, minQty, expiryMonths, category } = req.body;
  const id = parseInt(req.params.id);
  const mat = db.materials.find(m => m.id === id);
  if (!mat) return res.status(404).json({ error: 'Topilmadi' });
  if (db.materials.find(m => m.code === code && m.id !== id)) return res.status(400).json({ error: 'Kod mavjud!' });
  Object.assign(mat, { code, name, unit, minQty, expiryMonths, category });
  saveDB();
  res.json({ success: true });
});

app.delete('/api/materials/:id', admin, (req, res) => {
  const id = parseInt(req.params.id);
  db.materials = db.materials.filter(m => m.id !== id);
  db.partiyalar = db.partiyalar.filter(p => p.materialId !== id);
  db.operations = db.operations.filter(o => o.materialId !== id);
  db.ngRecords = db.ngRecords.filter(n => n.materialId !== id);
  db.certificates = db.certificates.filter(c => c.materialId !== id);
  saveDB();
  res.json({ success: true });
});

// PARTIYALAR & OPERATIONS
app.get('/api/partiyalar', auth, (req, res) => res.json(db.partiyalar));
app.get('/api/operations', auth, (req, res) => res.json(db.operations));

// KIRIM
app.post('/api/kirim', admin, (req, res) => {
  const { materialId, qty, expiryStart, expiryEnd, date, note } = req.body;
  const d = date || new Date().toISOString().split('T')[0];
  const partiyaId = ++db.counters.partiyalar;
  db.partiyalar.push({ id: partiyaId, materialId: parseInt(materialId), expiryStart, expiryEnd, initialQty: parseFloat(qty), currentQty: parseFloat(qty), renewed: 0, createdAt: new Date().toISOString() });
  const opId = ++db.counters.operations;
  db.operations.push({ id: opId, materialId: parseInt(materialId), partiyaId, type: 'kirim', qty: parseFloat(qty), date: d, note: note || '', createdAt: new Date().toISOString() });
  saveDB();
  res.json({ success: true, partiyaId });
});

// CHIQIM
app.post('/api/chiqim', admin, (req, res) => {
  const { materialId, partiyaId, qty, date, note } = req.body;
  const partiya = db.partiyalar.find(p => p.id === parseInt(partiyaId));
  if (!partiya) return res.status(400).json({ error: 'Partiya topilmadi!' });
  if (partiya.currentQty < parseFloat(qty)) return res.status(400).json({ error: 'Yetarli emas! Mavjud: ' + partiya.currentQty });
  partiya.currentQty -= parseFloat(qty);
  const opId = ++db.counters.operations;
  db.operations.push({ id: opId, materialId: parseInt(materialId), partiyaId: parseInt(partiyaId), type: 'chiqim', qty: parseFloat(qty), date: date || new Date().toISOString().split('T')[0], note: note || '', createdAt: new Date().toISOString() });
  saveDB();
  res.json({ success: true });
});

// NG
app.get('/api/ng-records', auth, (req, res) => res.json(db.ngRecords));

app.post('/api/ng', admin, (req, res) => {
  const { materialId, partiyaId, qty, reason, note } = req.body;
  const partiya = db.partiyalar.find(p => p.id === parseInt(partiyaId));
  const mat = db.materials.find(m => m.id === parseInt(materialId));
  if (!partiya) return res.status(400).json({ error: 'Partiya topilmadi!' });
  if (partiya.currentQty < parseFloat(qty)) return res.status(400).json({ error: 'Yetarli emas!' });
  const d = new Date().toISOString().split('T')[0];
  partiya.currentQty -= parseFloat(qty);
  const ngId = ++db.counters.ngRecords;
  db.ngRecords.push({ id: ngId, materialId: parseInt(materialId), partiyaId: parseInt(partiyaId), materialCode: mat?.code || '', materialName: mat?.name || '', qty: parseFloat(qty), reason, note: note || '', date: d, expiryEnd: partiya.expiryEnd, restored: 0, createdAt: new Date().toISOString() });
  const opId = ++db.counters.operations;
  db.operations.push({ id: opId, materialId: parseInt(materialId), partiyaId: parseInt(partiyaId), type: 'ng', qty: parseFloat(qty), date: d, reason, note: note || '', createdAt: new Date().toISOString() });
  saveDB();
  res.json({ success: true, id: ngId });
});

// OPERATION EDIT
app.put('/api/operations/:id', admin, (req, res) => {
  const id = parseInt(req.params.id);
  const { qty, date, note } = req.body;
  const op = db.operations.find(o => o.id === id);
  if (!op) return res.status(404).json({ error: 'Operatsiya topilmadi!' });
  
  // Update partiya qty if qty changed
  if (op.qty !== parseFloat(qty)) {
    const partiya = db.partiyalar.find(p => p.id === op.partiyaId);
    if (partiya) {
      const diff = parseFloat(qty) - op.qty;
      if (op.type === 'kirim' || op.type === 'initial' || op.type === 'restore') {
        partiya.currentQty += diff;
        if (op.type === 'kirim') partiya.initialQty += diff;
      } else if (op.type === 'chiqim' || op.type === 'ng') {
        partiya.currentQty -= diff;
      }
      if (partiya.currentQty < 0) partiya.currentQty = 0;
    }
  }
  
  op.qty = parseFloat(qty);
  op.date = date || op.date;
  op.note = note !== undefined ? note : op.note;
  op.updatedAt = new Date().toISOString();
  saveDB();
  res.json({ success: true });
});

// OPERATION DELETE
app.delete('/api/operations/:id', admin, (req, res) => {
  const id = parseInt(req.params.id);
  const op = db.operations.find(o => o.id === id);
  if (!op) return res.status(404).json({ error: 'Operatsiya topilmadi!' });
  
  // Reverse the operation effect on partiya
  const partiya = db.partiyalar.find(p => p.id === op.partiyaId);
  if (partiya) {
    if (op.type === 'kirim' || op.type === 'initial' || op.type === 'restore') {
      partiya.currentQty -= op.qty;
      if (op.type === 'kirim') partiya.initialQty -= op.qty;
    } else if (op.type === 'chiqim' || op.type === 'ng') {
      partiya.currentQty += op.qty;
    }
    if (partiya.currentQty < 0) partiya.currentQty = 0;
    
    // If partiya becomes empty and has no operations, remove it
    const remainingOps = db.operations.filter(o => o.partiyaId === partiya.id && o.id !== id);
    if (remainingOps.length === 0 && partiya.currentQty === 0) {
      db.partiyalar = db.partiyalar.filter(p => p.id !== partiya.id);
    }
  }
  
  // If it was an NG operation, also remove the NG record
  if (op.type === 'ng') {
    const ngRecord = db.ngRecords.find(n => n.materialId === op.materialId && n.partiyaId === op.partiyaId && n.qty === op.qty);
    if (ngRecord) {
      db.ngRecords = db.ngRecords.filter(n => n.id !== ngRecord.id);
    }
  }
  
  db.operations = db.operations.filter(o => o.id !== id);
  saveDB();
  res.json({ success: true });
});

// NG RESTORE
app.post('/api/ng/:id/restore', admin, (req, res) => {
  const ng = db.ngRecords.find(n => n.id === parseInt(req.params.id));
  if (!ng) return res.status(400).json({ error: 'Topilmadi!' });
  if (ng.restored) return res.status(400).json({ error: 'Allaqachon qaytarilgan!' });
  const d = new Date().toISOString().split('T')[0];
  ng.restored = 1;
  ng.restoredAt = new Date().toISOString();
  const partiya = db.partiyalar.find(p => p.id === ng.partiyaId);
  if (partiya) partiya.currentQty += ng.qty;
  const opId = ++db.counters.operations;
  db.operations.push({ id: opId, materialId: ng.materialId, partiyaId: ng.partiyaId, type: 'restore', qty: ng.qty, date: d, note: 'NG dan qaytarildi', createdAt: new Date().toISOString() });
  saveDB();
  res.json({ success: true });
});

// RENEW
app.post('/api/renew', admin, upload.single('certificate'), (req, res) => {
  const { materialId, partiyaId, expiryStart, expiryEnd, note, ngId } = req.body;
  const d = new Date().toISOString().split('T')[0];
  const now = new Date().toISOString();
  const mat = db.materials.find(m => m.id === parseInt(materialId));
  let targetPartiyaId = partiyaId ? parseInt(partiyaId) : null;
  
  if (ngId && ngId !== '' && ngId !== 'null' && ngId !== 'undefined') {
    const ng = db.ngRecords.find(n => n.id === parseInt(ngId) && !n.restored);
    if (ng) {
      targetPartiyaId = ng.partiyaId;
      ng.restored = 1;
      ng.restoredAt = now;
      const partiya = db.partiyalar.find(p => p.id === ng.partiyaId);
      if (partiya) {
        partiya.currentQty += ng.qty;
        partiya.expiryStart = expiryStart;
        partiya.expiryEnd = expiryEnd;
        partiya.renewed = 1;
        partiya.renewedAt = now;
      }
      const opId = ++db.counters.operations;
      db.operations.push({ id: opId, materialId: parseInt(materialId), partiyaId: ng.partiyaId, type: 'restore', qty: ng.qty, date: d, note: 'NG dan qaytarildi va muddat yangilandi: ' + expiryEnd, createdAt: now });
    }
  } else if (targetPartiyaId) {
    const partiya = db.partiyalar.find(p => p.id === targetPartiyaId);
    if (partiya) {
      partiya.expiryStart = expiryStart;
      partiya.expiryEnd = expiryEnd;
      partiya.renewed = 1;
      partiya.renewedAt = now;
      const opId = ++db.counters.operations;
      db.operations.push({ id: opId, materialId: parseInt(materialId), partiyaId: targetPartiyaId, type: 'renew', qty: partiya.currentQty || 0, date: d, note: expiryEnd + ' gacha yangilandi. ' + (note || ''), createdAt: now });
    }
  }
  
  let certId = null;
  if (req.file && targetPartiyaId) {
    certId = ++db.counters.certificates;
    db.certificates.push({ id: certId, materialId: parseInt(materialId), partiyaId: targetPartiyaId, materialCode: mat?.code || '', materialName: mat?.name || '', fileName: req.file.originalname, filePath: req.file.filename, fileSize: req.file.size, newExpiryStart: expiryStart, newExpiryEnd: expiryEnd, note: note || '', createdAt: now });
  }
  saveDB();
  res.json({ success: true, certificateId: certId });
});

// CERTIFICATES
app.get('/api/certificates', auth, (req, res) => res.json(db.certificates));

app.get('/api/certificates/:id/download', auth, (req, res) => {
  const cert = db.certificates.find(c => c.id === parseInt(req.params.id));
  if (!cert) return res.status(404).json({ error: 'Topilmadi' });
  const filePath = path.join(uploadDir, cert.filePath);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Fayl topilmadi' });
  res.download(filePath, cert.fileName);
});

app.get('/api/certificates/:id/view', auth, (req, res) => {
  const cert = db.certificates.find(c => c.id === parseInt(req.params.id));
  if (!cert) return res.status(404).json({ error: 'Topilmadi' });
  const filePath = path.join(uploadDir, cert.filePath);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Fayl topilmadi' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'inline; filename="' + cert.fileName + '"');
  fs.createReadStream(filePath).pipe(res);
});

// IMPORT
app.post('/api/import', admin, (req, res) => {
  const { materials } = req.body;
  let imported = 0, updated = 0;
  const today = new Date().toISOString().split('T')[0];
  
  for (const m of materials) {
    if (!m.code || !m.name) continue;
    const exist = db.materials.find(x => x.code === m.code);
    let matId;
    
    if (exist) {
      Object.assign(exist, { name: m.name, unit: m.unit || 'litr', expiryMonths: m.expiryMonths || 12 });
      matId = exist.id;
      updated++;
    } else {
      matId = ++db.counters.materials;
      db.materials.push({ id: matId, code: m.code, name: m.name, unit: m.unit || 'litr', minQty: 10, expiryMonths: m.expiryMonths || 12, category: 'oil', createdAt: new Date().toISOString() });
      imported++;
    }
    
    if (m.initialQty > 0) {
      const endDate = new Date();
      endDate.setMonth(endDate.getMonth() + (m.expiryMonths || 12));
      const partiyaId = ++db.counters.partiyalar;
      db.partiyalar.push({ id: partiyaId, materialId: matId, expiryStart: today, expiryEnd: endDate.toISOString().split('T')[0], initialQty: m.initialQty, currentQty: m.initialQty, renewed: 0, isInitialStock: 1, createdAt: new Date().toISOString() });
      const opId = ++db.counters.operations;
      db.operations.push({ id: opId, materialId: matId, partiyaId, type: 'initial', qty: m.initialQty, date: today, note: 'Boshlang\'ich qoldiq', createdAt: new Date().toISOString() });
    }
  }
  saveDB();
  res.json({ success: true, imported, updated });
});

// DELETE ALL OPERATIONS
app.post('/api/delete-all-operations', admin, (req, res) => {
  const { confirmation } = req.body;
  if (confirmation !== "o'chirib yuborilsin") {
    return res.status(400).json({ error: "Tasdiqlash noto'g'ri! \"o'chirib yuborilsin\" deb yozing" });
  }
  
  // Reset all data
  db.partiyalar = [];
  db.operations = [];
  db.ngRecords = [];
  db.certificates = [];
  db.counters.partiyalar = 0;
  db.counters.operations = 0;
  db.counters.ngRecords = 0;
  db.counters.certificates = 0;
  
  // Delete uploaded certificate files
  try {
    const files = fs.readdirSync(uploadDir);
    files.forEach(file => {
      fs.unlinkSync(path.join(uploadDir, file));
    });
  } catch (e) {
    console.error('Error deleting files:', e);
  }
  
  saveDB();
  res.json({ success: true, message: "Barcha operatsiyalar o'chirildi!" });
});

// BACKUP/RESTORE
app.get('/api/backup', admin, (req, res) => res.json({ ...db, exportedAt: new Date().toISOString() }));

app.post('/api/restore', admin, (req, res) => {
  const { materials, partiyalar, operations, ngRecords, certificates, counters } = req.body;
  db.materials = materials || [];
  db.partiyalar = partiyalar || [];
  db.operations = operations || [];
  db.ngRecords = ngRecords || [];
  db.certificates = certificates || [];
  db.counters = counters || { materials: Math.max(0, ...db.materials.map(m => m.id), 0), partiyalar: Math.max(0, ...db.partiyalar.map(p => p.id), 0), operations: Math.max(0, ...db.operations.map(o => o.id), 0), ngRecords: Math.max(0, ...db.ngRecords.map(n => n.id), 0), certificates: Math.max(0, ...db.certificates.map(c => c.id), 0) };
  saveDB();
  res.json({ success: true });
});

// Statistics
app.get('/api/statistics', auth, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const activeNG = db.ngRecords.filter(n => !n.restored);
  const stats = { totalMaterials: db.materials.length, totalPartiyalar: db.partiyalar.length, totalOperations: db.operations.length, totalCertificates: db.certificates.length, materialStats: { ok: 0, warning: 0, critical: 0, expired: 0, renewed: 0 }, totalKirim: db.operations.filter(o => o.type === 'kirim').reduce((s, o) => s + (o.qty || 0), 0), totalChiqim: db.operations.filter(o => o.type === 'chiqim').reduce((s, o) => s + (o.qty || 0), 0), activeNGCount: activeNG.length, activeNGQty: activeNG.reduce((s, n) => s + (n.qty || 0), 0), activeNGList: activeNG };
  db.materials.forEach(m => {
    const qty = db.partiyalar.filter(p => p.materialId === m.id).reduce((s, p) => s + (p.currentQty || 0), 0);
    const parts = db.partiyalar.filter(p => p.materialId === m.id && p.currentQty > 0);
    const hasRenewed = parts.some(p => p.renewed);
    const hasExpired = parts.some(p => p.expiryEnd && p.expiryEnd < today && !p.renewed);
    if (hasRenewed) stats.materialStats.renewed++;
    else if (hasExpired) stats.materialStats.expired++;
    else if (qty <= 0 || qty <= m.minQty * 0.5) stats.materialStats.critical++;
    else if (qty <= m.minQty) stats.materialStats.warning++;
    else stats.materialStats.ok++;
  });
  res.json(stats);
});

// Server startup with better error handling
const HOST = process.env.HOST || '0.0.0.0';
const server = app.listen(PORT, HOST, () => {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║  🚗 BYD Kimyoviy Materiallar Saqlash Ombori                     ║');
  console.log('║  📦 JSON Database - Korxona versiyasi v2.3                     ║');
  console.log('╠════════════════════════════════════════════════════════════════╣');
  console.log('║  📍 http://' + HOST + ':' + PORT + '                                      ║');
  console.log('╠════════════════════════════════════════════════════════════════╣');
  console.log('║  👤 Admin:    Kimyo / 123456                                   ║');
  console.log('║  👥 Viewer:   bydombor / 0035                                  ║');
  console.log('╠════════════════════════════════════════════════════════════════╣');
  console.log('║  💾 Auto backup: Har kuni (30 kunlik)                          ║');
  console.log('║  💾 Auto save: Har daqiqa                                      ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');
});

// Keep-alive for corporate networks
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

// Error handling
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error('❌ Port ' + PORT + ' band. Boshqa portdan foydalaning.');
  } else {
    console.error('❌ Server xatoligi:', e);
  }
});

process.on('SIGINT', () => { saveDB(); process.exit(); });
process.on('SIGTERM', () => { saveDB(); process.exit(); });
