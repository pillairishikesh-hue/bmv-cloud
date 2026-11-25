// BookMyValuer API + web app server (v2)
// Roles: ho (head office), glo (gold loan officer), valuer, agency
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Serve the BookMyValuer web app at the main URL
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// DB connection string is read from the MONGODB_URI environment variable set in Render. Never put the password in code.
const mongoURI = process.env.MONGODB_URI;
mongoose.connect(mongoURI)
  .then(() => console.log('Database connected.'))
  .catch(err => console.error('Database connection failed:', err.message));

// Token signing secret: TOKEN_SECRET if set, otherwise derived from the DB connection string (stable across restarts).
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.createHash('sha256').update('bmv:' + (mongoURI || 'local')).digest('hex');
const DEFAULT_PASSWORD = 'demo123';

// ---------- Schemas ----------
const branchSchema = new mongoose.Schema({
  branchCode: { type: String, unique: true, required: true },
  branchName: { type: String, required: true },
  bankName: String,
  locality: String,
  city: String,
  location: { type: { type: String, default: 'Point' }, coordinates: [Number] }, // [lng, lat]
  geofenceRadiusThreshold: String,
  operatingHoursWindow: String
}, { collection: 'branches' });
const Branch = mongoose.model('Branch', branchSchema);

const gloSchema = new mongoose.Schema({
  employeeId: { type: String, unique: true, required: true },
  fullName: { type: String, required: true },
  contactMobile: String,
  email: String,
  roleDesignation: String,
  allocatedBranchCode: String,
  passwordHash: String
}, { collection: 'GLO' });
const GloUser = mongoose.model('GLO', gloSchema);

const agencySchema = new mongoose.Schema({
  agencyId: { type: String, unique: true, required: true },
  agencyName: { type: String, required: true },
  officerName: String,
  contactMobile: String,
  email: String,
  passwordHash: String
}, { collection: 'Valuer Agency' });
const Agency = mongoose.model('Agency', agencySchema);

const valuerSchema = new mongoose.Schema({
  sysId: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  contactMobile: String,
  lat: Number,
  lng: Number,
  agencyId: { type: String, default: null }, // null = independent
  status: { type: String, default: 'available' }, // available | engaged | offline
  rejectionsCount: { type: Number, default: 0 },
  blacklistedBranchCodes: { type: [String], default: [] },
  passwordHash: String
}, { collection: 'Valuer' });
const Valuer = mongoose.model('Valuer', valuerSchema);

const hoSchema = new mongoose.Schema({
  userId: { type: String, unique: true, required: true },
  fullName: String,
  passwordHash: String
}, { collection: 'HO' });
const HoUser = mongoose.model('HO', hoSchema);

const bookingSchema = new mongoose.Schema({
  bookingId: { type: String, unique: true, required: true },
  branchCode: String,
  gloId: String,
  valuerSysId: String,
  agencyId: String,
  lan: String,
  goldWeightGrams: String,
  distanceKm: Number,
  status: { type: String, default: 'requested' }, // requested | accepted | rejected | completed
  etaMins: Number,
  valuationAmount: Number,
  rating: Number,
  ratingComment: String,
  requestedAt: { type: Date, default: Date.now },
  respondedAt: Date,
  completedAt: Date,
  ratedAt: Date,
  timestamp: { type: Date, default: Date.now }
}, { collection: 'Booking' });
const Booking = mongoose.model('Booking', bookingSchema);

const eventSchema = new mongoose.Schema({
  audience: [String], // e.g. "glo:GLO101", "valuer:VAL001", "agency:AG01", "ho"
  type: String,
  title: String,
  message: String,
  bookingId: String,
  createdAt: { type: Date, default: Date.now }
}, { collection: 'Event' });
eventSchema.index({ audience: 1, createdAt: 1 });
const EventLog = mongoose.model('Event', eventSchema);

// ---------- Helpers ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 32).toString('hex');
  return `${salt}:${hash}`;
}
function checkPassword(pw, stored) {
  if (!stored) return false;
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(String(pw), salt, 32);
  return crypto.timingSafeEqual(test, Buffer.from(hash, 'hex'));
}
function signToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 12 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function readToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const data = JSON.parse(Buffer.from(body, 'base64url').toString());
  return data.exp > Date.now() ? data : null;
}
function auth(...roles) {
  return (req, res, next) => {
    const user = readToken((req.headers.authorization || '').replace('Bearer ', ''));
    if (!user) return res.status(401).json({ message: 'Please log in again.' });
    if (roles.length && !roles.includes(user.role)) return res.status(403).json({ message: 'Your role cannot do this.' });
    req.user = user;
    next();
  };
}
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error(e);
  res.status(400).json({ message: e.code === 11000 ? 'This ID already exists.' : (e.message || 'Server error.') });
});
function km(lat1, lon1, lat2, lon2) {
  const R = 6371, dLat = (lat2 - lat1) * Math.PI / 180, dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
async function notify(audience, type, title, message, bookingId) {
  await EventLog.create({ audience: [...new Set(audience.filter(Boolean))], type, title, message, bookingId });
}
const strip = doc => { const o = doc.toObject ? doc.toObject() : { ...doc }; delete o.passwordHash; return o; };
const inr = n => '₹' + Number(n).toLocaleString('en-IN');

// ---------- Auth ----------
app.post('/api/login', wrap(async (req, res) => {
  const { role, id, password } = req.body;
  const uid = String(id || '').trim();
  let user = null, profile = null;
  if (role === 'ho') { user = await HoUser.findOne({ userId: uid }); profile = user && { id: user.userId, name: user.fullName }; }
  if (role === 'glo') {
    user = await GloUser.findOne({ employeeId: uid });
    if (user) { const b = await Branch.findOne({ branchCode: user.allocatedBranchCode }); profile = { id: user.employeeId, name: user.fullName, branchCode: user.allocatedBranchCode, branchName: b ? b.branchName : '' }; }
  }
  if (role === 'valuer') { user = await Valuer.findOne({ sysId: uid }); profile = user && { id: user.sysId, name: user.name, agencyId: user.agencyId }; }
  if (role === 'agency') { user = await Agency.findOne({ agencyId: uid }); profile = user && { id: user.agencyId, name: user.agencyName }; }
  if (!user || !checkPassword(password, user.passwordHash)) return res.status(401).json({ message: 'Wrong ID or password.' });
  const session = { role, ...profile };
  res.json({ token: signToken(session), user: session });
}));

// ---------- Directory (any logged-in user) ----------
app.get('/api/branches', auth(), wrap(async (req, res) => res.json(await Branch.find({}).sort({ branchCode: 1 }))));
app.get('/api/glos', auth(), wrap(async (req, res) => res.json((await GloUser.find({}).sort({ employeeId: 1 })).map(strip))));
app.get('/api/agencies', auth(), wrap(async (req, res) => res.json((await Agency.find({}).sort({ agencyId: 1 })).map(strip))));
app.get('/api/valuers', auth(), wrap(async (req, res) => {
  const filter = req.user.role === 'agency' ? { agencyId: req.user.id } : {};
  res.json((await Valuer.find(filter).sort({ sysId: 1 })).map(strip));
}));

// ---------- Onboarding (GLO and HO only) ----------
app.post('/api/branches', auth('ho', 'glo'), wrap(async (req, res) => {
  const b = await Branch.create(req.body);
  res.status(201).json(b);
}));
app.post('/api/glos', auth('ho', 'glo'), wrap(async (req, res) => {
  const g = await GloUser.create({ ...req.body, passwordHash: hashPassword(req.body.password || DEFAULT_PASSWORD) });
  res.status(201).json(strip(g));
}));
app.post('/api/agencies', auth('ho', 'glo'), wrap(async (req, res) => {
  const a = await Agency.create({ ...req.body, passwordHash: hashPassword(req.body.password || DEFAULT_PASSWORD) });
  res.status(201).json(strip(a));
}));
app.post('/api/valuers', auth('ho', 'glo'), wrap(async (req, res) => {
  const v = await Valuer.create({ ...req.body, agencyId: req.body.agencyId || null, passwordHash: hashPassword(req.body.password || DEFAULT_PASSWORD) });
  res.status(201).json(strip(v));
}));

// ---------- Matching: valuers near the GLO's branch ----------
app.get('/api/matches', auth('glo'), wrap(async (req, res) => {
  const branch = await Branch.findOne({ branchCode: req.user.branchCode });
  if (!branch) return res.status(400).json({ message: 'Your branch was not found.' });
  const [bLng, bLat] = branch.location.coordinates;
  // Valuers who rejected this GLO before are not shown to this GLO again
  const rejectedBy = await Booking.distinct('valuerSysId', { gloId: req.user.id, status: 'rejected' });
  const valuers = await Valuer.find({ sysId: { $nin: rejectedBy } });
  const rated = await Booking.aggregate([{ $match: { rating: { $gte: 1 } } }, { $group: { _id: '$valuerSysId', avg: { $avg: '$rating' }, n: { $sum: 1 } } }]);
  const ratingMap = Object.fromEntries(rated.map(r => [r._id, r]));
  const list = valuers.map(v => ({
    ...strip(v),
    distanceKm: km(bLat, bLng, v.lat, v.lng),
    blacklisted: v.blacklistedBranchCodes.includes(branch.branchCode),
    avgRating: ratingMap[v.sysId] ? ratingMap[v.sysId].avg : null,
    ratingCount: ratingMap[v.sysId] ? ratingMap[v.sysId].n : 0
  })).sort((a, b) => a.distanceKm - b.distanceKm);
  res.json({ branch, valuers: list, hiddenAfterRejection: rejectedBy.length });
}));

// ---------- Bookings ----------
app.get('/api/bookings', auth(), wrap(async (req, res) => {
  const u = req.user;
  const filter = u.role === 'glo' ? { branchCode: u.branchCode } : u.role === 'valuer' ? { valuerSysId: u.id } : u.role === 'agency' ? { agencyId: u.id } : {};
  res.json(await Booking.find(filter).sort({ requestedAt: -1 }).limit(200));
}));

app.post('/api/bookings', auth('glo'), wrap(async (req, res) => {
  const { valuerSysId, lan, goldWeightGrams } = req.body;
  if (!lan || !String(lan).trim()) return res.status(400).json({ message: 'Loan Account Number (LAN) is required.' });
  const v = await Valuer.findOne({ sysId: valuerSysId });
  if (!v) return res.status(400).json({ message: 'Valuer not found.' });
  if (v.status !== 'available') return res.status(400).json({ message: `${v.name} is not available right now.` });
  const branch = await Branch.findOne({ branchCode: req.user.branchCode });
  if (v.blacklistedBranchCodes.includes(branch.branchCode)) return res.status(400).json({ message: 'This valuer is blocked for your branch.' });
  const [bLng, bLat] = branch.location.coordinates;
  const booking = await Booking.create({
    bookingId: 'BK-' + Math.floor(100000 + Math.random() * 900000),
    branchCode: branch.branchCode, gloId: req.user.id, valuerSysId: v.sysId, agencyId: v.agencyId,
    lan: String(lan).trim(), goldWeightGrams: goldWeightGrams || '', distanceKm: Math.round(km(bLat, bLng, v.lat, v.lng) * 100) / 100
  });
  v.status = 'engaged'; await v.save();
  await notify([`valuer:${v.sysId}`, v.agencyId && `agency:${v.agencyId}`, 'ho'], 'requested', 'New valuation request',
    `${branch.branchName}: LAN ${booking.lan}, ${booking.goldWeightGrams || '?'} g gold, ${booking.distanceKm} km away. Requested by ${req.user.name}.`, booking.bookingId);
  await notify([`glo:${req.user.id}`], 'sent', 'Request sent', `Request ${booking.bookingId} sent to ${v.name}. Waiting for them to accept.`, booking.bookingId);
  res.status(201).json(booking);
}));

async function loadForValuer(req) {
  const b = await Booking.findOne({ bookingId: req.params.id });
  if (!b) throw new Error('Booking not found.');
  if (b.valuerSysId !== req.user.id) throw new Error('This booking is not assigned to you.');
  return b;
}

app.post('/api/bookings/:id/accept', auth('valuer'), wrap(async (req, res) => {
  const b = await loadForValuer(req);
  if (b.status !== 'requested') return res.status(400).json({ message: 'This request is no longer open.' });
  b.status = 'accepted'; b.respondedAt = new Date(); b.etaMins = Number(req.body.etaMins) || null; await b.save();
  await notify([`glo:${b.gloId}`, b.agencyId && `agency:${b.agencyId}`, 'ho'], 'accepted', 'Valuer accepted',
    `${req.user.name} accepted ${b.bookingId} (LAN ${b.lan})${b.etaMins ? `, arriving in about ${b.etaMins} min` : ''}. Valuation in progress.`, b.bookingId);
  res.json(b);
}));

app.post('/api/bookings/:id/reject', auth('valuer'), wrap(async (req, res) => {
  const b = await loadForValuer(req);
  if (b.status !== 'requested') return res.status(400).json({ message: 'This request is no longer open.' });
  b.status = 'rejected'; b.respondedAt = new Date(); await b.save();
  const v = await Valuer.findOneAndUpdate({ sysId: b.valuerSysId }, { $inc: { rejectionsCount: 1 }, status: 'available' }, { new: true });
  if (v.rejectionsCount >= 3) await Valuer.updateOne({ sysId: v.sysId }, { $addToSet: { blacklistedBranchCodes: b.branchCode } });
  await notify([`glo:${b.gloId}`, b.agencyId && `agency:${b.agencyId}`, 'ho'], 'rejected', 'Valuer declined',
    `${req.user.name} declined ${b.bookingId} (LAN ${b.lan}). Please book another valuer.`, b.bookingId);
  res.json(b);
}));

app.post('/api/bookings/:id/complete', auth('valuer'), wrap(async (req, res) => {
  const b = await loadForValuer(req);
  if (b.status !== 'accepted') return res.status(400).json({ message: 'Only a valuation in progress can be completed.' });
  const amount = Number(String(req.body.valuationAmount || '').replace(/[^0-9.]/g, ''));
  if (!amount || amount <= 0) return res.status(400).json({ message: 'Enter the valuation amount.' });
  b.status = 'completed'; b.valuationAmount = amount; b.completedAt = new Date(); await b.save();
  await Valuer.updateOne({ sysId: b.valuerSysId }, { status: 'available' });
  await notify([`glo:${b.gloId}`, b.agencyId && `agency:${b.agencyId}`, 'ho'], 'completed', 'Valuation completed',
    `${req.user.name} completed ${b.bookingId} (LAN ${b.lan}). Valuation: ${inr(amount)}. Please rate the valuer.`, b.bookingId);
  res.json(b);
}));

app.post('/api/bookings/:id/rate', auth('glo'), wrap(async (req, res) => {
  const b = await Booking.findOne({ bookingId: req.params.id, branchCode: req.user.branchCode });
  if (!b) return res.status(404).json({ message: 'Booking not found.' });
  if (b.status !== 'completed') return res.status(400).json({ message: 'You can rate only after the valuation is completed.' });
  const rating = Math.round(Number(req.body.rating));
  if (!(rating >= 1 && rating <= 5)) return res.status(400).json({ message: 'Rating must be 1 to 5 stars.' });
  b.rating = rating; b.ratingComment = req.body.comment || ''; b.ratedAt = new Date(); await b.save();
  await notify([`valuer:${b.valuerSysId}`, b.agencyId && `agency:${b.agencyId}`, 'ho'], 'rated', 'New rating',
    `${req.user.name} rated ${b.bookingId} (LAN ${b.lan}) ${'★'.repeat(rating)}${'☆'.repeat(5 - rating)}${b.ratingComment ? ': "' + b.ratingComment + '"' : ''}`, b.bookingId);
  res.json(b);
}));

// ---------- Valuer availability ----------
app.post('/api/valuers/me/status', auth('valuer'), wrap(async (req, res) => {
  const status = req.body.status === 'offline' ? 'offline' : 'available';
  const v = await Valuer.findOne({ sysId: req.user.id });
  if (v.status === 'engaged') return res.status(400).json({ message: 'Finish your current valuation first.' });
  v.status = status; await v.save();
  res.json(strip(v));
}));
app.get('/api/valuers/me', auth('valuer'), wrap(async (req, res) => res.json(strip(await Valuer.findOne({ sysId: req.user.id })))));

// ---------- Ratings summary ----------
app.get('/api/ratings', auth(), wrap(async (req, res) => {
  const match = { rating: { $gte: 1 } };
  if (req.user.role === 'agency') match.agencyId = req.user.id;
  const rows = await Booking.aggregate([{ $match: match }, { $group: { _id: '$valuerSysId', avg: { $avg: '$rating' }, n: { $sum: 1 } } }]);
  const valuers = await Valuer.find(req.user.role === 'agency' ? { agencyId: req.user.id } : {});
  const done = await Booking.aggregate([{ $match: { status: 'completed' } }, { $group: { _id: '$valuerSysId', n: { $sum: 1 } } }]);
  const map = Object.fromEntries(rows.map(r => [r._id, r]));
  const doneMap = Object.fromEntries(done.map(r => [r._id, r.n]));
  res.json(valuers.map(v => ({ sysId: v.sysId, name: v.name, agencyId: v.agencyId, avgRating: map[v.sysId] ? map[v.sysId].avg : null, ratingCount: map[v.sysId] ? map[v.sysId].n : 0, completed: doneMap[v.sysId] || 0, rejectionsCount: v.rejectionsCount }))
    .sort((a, b) => (b.avgRating || 0) - (a.avgRating || 0) || b.ratingCount - a.ratingCount));
}));

// ---------- Notifications (popups) ----------
app.get('/api/events', auth(), wrap(async (req, res) => {
  const u = req.user;
  const key = u.role === 'ho' ? 'ho' : `${u.role}:${u.id}`;
  const after = req.query.after ? new Date(req.query.after) : new Date(Date.now() - 60 * 1000);
  res.json(await EventLog.find({ audience: key, createdAt: { $gt: after } }).sort({ createdAt: 1 }).limit(50));
}));

// ---------- Demo data reset (HO only) ----------
const CITY = 'Bengaluru';
const DEMO_BRANCHES = [
  ['DEMO0001', 'Koramangala', 12.9352, 77.6245], ['DEMO0002', 'Indiranagar', 12.9719, 77.6412],
  ['DEMO0003', 'Jayanagar', 12.9250, 77.5938], ['DEMO0004', 'Whitefield', 12.9698, 77.7500],
  ['DEMO0005', 'Malleshwaram', 13.0035, 77.5709]
];
const GLO_NAMES = ['Ananya Rao', 'Vikram Shetty', 'Priya Nair', 'Rahul Menon', 'Divya Iyer', 'Karthik Gowda', 'Sneha Kulkarni', 'Arjun Reddy', 'Meera Pillai', 'Rohan Desai'];
const AGENCIES = [['AG01', 'Swarna Valuers Pvt Ltd', 'Suresh Kumar'], ['AG02', 'Kanaka Appraisal Services', 'Lakshmi Prasad'], ['AG03', 'Hallmark Gold Assessors', 'Imran Khan']];
const VALUER_NAMES = ['Ramesh Acharya', 'Ganesh Bhat', 'Manjunath S', 'Kavitha R', 'Prakash Jain', 'Sunil Hegde', 'Deepa Murthy', 'Naveen Kumar', 'Shobha Rani', 'Venkatesh Rao',
  'Farhan Ali', 'Lokesh Gowda', 'Asha Devi', 'Mohan Das', 'Rekha Shenoy', 'Harish Patil', 'Nandini M', 'Sanjay Soni', 'Tara Joseph', 'Girish Naik'];

async function seedDemo() {
  await Promise.all([Branch, GloUser, Agency, Valuer, HoUser, Booking, EventLog].map(m => m.deleteMany({})));
  const pw = () => hashPassword(DEFAULT_PASSWORD);
  await HoUser.create({ userId: 'HO001', fullName: 'Head Office Admin', passwordHash: pw() });
  await Branch.insertMany(DEMO_BRANCHES.map(([code, area, lat, lng]) => ({
    branchCode: code, branchName: `${area} Branch`, bankName: 'BMV Demo Bank', locality: `${area}, ${CITY}`, city: CITY,
    location: { type: 'Point', coordinates: [lng, lat] }, geofenceRadiusThreshold: '50', operatingHoursWindow: '09:30 AM - 04:30 PM'
  })));
  const glos = [];
  DEMO_BRANCHES.forEach(([code], i) => [0, 1].forEach(j => {
    const n = i * 2 + j;
    glos.push({ employeeId: `GLO${101 + n}`, fullName: GLO_NAMES[n], contactMobile: `+91 98450 ${String(10001 + n)}`, roleDesignation: j === 0 ? 'Primary GLO' : 'Backup GLO', allocatedBranchCode: code, passwordHash: pw() });
  }));
  await GloUser.insertMany(glos);
  await Agency.insertMany(AGENCIES.map(([id, name, officer], i) => ({ agencyId: id, agencyName: name, officerName: officer, contactMobile: `+91 99000 2000${i + 1}`, passwordHash: pw() })));
  // 15 agency valuers + 5 independent, spread around the branches (0.5 to 6 km away)
  const valuers = VALUER_NAMES.map((name, i) => {
    const [, , lat, lng] = DEMO_BRANCHES[i % 5];
    const angle = (i * 137) % 360 * Math.PI / 180, dist = 0.005 + (i % 7) * 0.008;
    return {
      sysId: `VAL${String(i + 1).padStart(3, '0')}`, name, contactMobile: `+91 97400 ${String(30001 + i)}`,
      lat: Math.round((lat + dist * Math.cos(angle)) * 10000) / 10000, lng: Math.round((lng + dist * Math.sin(angle)) * 10000) / 10000,
      agencyId: i < 15 ? AGENCIES[Math.floor(i / 5)][0] : null, status: 'available', passwordHash: pw()
    };
  });
  await Valuer.insertMany(valuers);
  return { branches: 5, glos: glos.length, agencies: AGENCIES.length, valuers: valuers.length, password: DEFAULT_PASSWORD };
}

app.post('/api/admin/reset-demo', auth('ho'), wrap(async (req, res) => res.json(await seedDemo())));

// One-time bootstrap: if there is no HO user yet, create the demo data so someone can log in.
mongoose.connection.once('open', async () => {
  try {
    if (!(await HoUser.countDocuments())) { console.log('No HO user found, seeding demo data.'); console.log(await seedDemo()); }
  } catch (e) { console.error('Seed failed:', e.message); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`BookMyValuer running on port ${PORT}`));
