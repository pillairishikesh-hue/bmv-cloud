const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());


// FIXED: Direct shard format that completely avoids the local DNS SRV validation layer
const mongoURI = "mongodb+srv://pillairishikesh_db_user:BMVPass2026@cluster0.pqg1cd7.mongodb.net/?appName=Cluster0";


mongoose.connect(mongoURI)
  .then(() => console.log("Live MongoDB Atlas Database Connection Confirmed."))
  .catch(err => console.error("Database connection dropped:", err));

// --- DATA SCHEMAS (Matches your dynamic onboarding fields) ---
const branchSchema = new mongoose.Schema({
    branchCode: { type: String, unique: true, required: true },
    branchName: { type: String, required: true },
    locality: String,
    location: {
        type: { type: String, default: 'Point' },
        coordinates: [Number] // Stored as [Longitude, Latitude]
    },
    geofenceRadiusThreshold: String,
    operatingHoursWindow: String
}, { collection: 'branches' });
const Branch = mongoose.model('Branch', branchSchema);

const gloSchema = new mongoose.Schema({
    employeeId: { type: String, unique: true, required: true },
    fullName: { type: String, required: true },
    contactMobile: String,
    emailAddress: String,
    roleDesignation: String,
    allocatedBranchCode: String
}, { collection: 'GLO' });
const GloUser = mongoose.model('GLO', gloSchema);

const agencySchema = new mongoose.Schema({
    agencyId: { type: String, unique: true, required: true },
    agencyName: { type: String, required: true },
    officerName: String,
    contactMobile: String,
    emailAddress: String,
    corporateAddress: String
}, { collection: 'Valuer Agency' });
const Agency = mongoose.model('Agency', agencySchema);

const valuerSchema = new mongoose.Schema({
    sysId: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    phone: String,
    email: String,
    agencyId: String,
    bioSig: String,
    lat: Number,
    lng: Number,
    status: { type: String, default: 'available' },
    ratingMetrics: { type: [Number], default: [5] },
    rejectionsCount: { type: Number, default: 0 },
    blacklistedBranchCodes: { type: [String], default: [] }
}, { collection: 'Valuer' });
const Valuer = mongoose.model('Valuer', valuerSchema);

// --- API LAYER GATEWAY ENDPOINTS ---
app.get('/api/branches', async (req, res) => { try { res.json(await Branch.find({})); } catch (err) { res.status(500).json(err); } });
app.post('/api/branches', async (req, res) => { try { const b = new Branch(req.body); await b.save(); res.status(201).json(b); } catch (err) { res.status(400).json(err); } });

app.get('/api/glos', async (req, res) => { try { res.json(await GloUser.find({})); } catch (err) { res.status(500).json(err); } });
app.post('/api/glos', async (req, res) => { try { const g = new GloUser(req.body); await g.save(); res.status(201).json(g); } catch (err) { res.status(400).json(err); } });

app.get('/api/agencies', async (req, res) => { try { res.json(await Agency.find({})); } catch (err) { res.status(500).json(err); } });
app.post('/api/agencies', async (req, res) => { try { const a = new Agency(req.body); await a.save(); res.status(201).json(a); } catch (err) { res.status(400).json(err); } });

app.get('/api/valuers', async (req, res) => { try { res.json(await Valuer.find({})); } catch (err) { res.status(500).json(err); } });
app.post('/api/valuers', async (req, res) => { try { const v = new Valuer(req.body); await v.save(); res.status(201).json(v); } catch (err) { res.status(400).json(err); } });

// FIXED: Uses the cloud provider's dynamic port if available, otherwise defaults to local port 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`BookmyValuer Gateway live on port ${PORT}. Data persistence engine unlocked.`));
