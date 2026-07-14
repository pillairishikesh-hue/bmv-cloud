const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ⚠️ Ensure your correct alphanumerical password parameter remains active here
const mongoURI = "mongodb+srv://pillairishikesh_db_user:MBVPass2026@cluster0.pqg1cd7.mongodb.net/BookmyValuer?retryWrites=true&w=majority";

mongoose.connect(mongoURI)
  .then(() => console.log("Production Storage Loop Connection Confirmed."))
  .catch(err => console.error("Database socket drop caught:", err));

// --- COLLECTION SCHEMAS ---
const branchSchema = new mongoose.Schema({
    branchCode: { type: String, unique: true, required: true },
    branchName: { type: String, required: true },
    locality: String,
    location: { type: { type: String, default: 'Point' }, coordinates: [Number] },
    geofenceRadiusThreshold: String,
    operatingHoursWindow: String
}, { collection: 'branches' });
const Branch = mongoose.model('Branch', branchSchema);

const gloSchema = new mongoose.Schema({
    employeeId: { type: String, unique: true, required: true },
    fullName: { type: String, required: true },
    contactMobile: String,
    allocatedBranchCode: String
}, { collection: 'GLO' });
const GloUser = mongoose.model('GLO', gloSchema);

const agencySchema = new mongoose.Schema({
    agencyId: { type: String, unique: true, required: true },
    agencyName: { type: String, required: true },
    officerName: String,
    contactMobile: String
}, { collection: 'Valuer Agency' });
const Agency = mongoose.model('Agency', agencySchema);

const valuerSchema = new mongoose.Schema({
    sysId: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    lat: Number,
    lng: Number,
    agencyId: String,
    status: { type: String, default: 'available' },
    rejectionsCount: { type: Number, default: 0 },
    blacklistedBranchCodes: { type: [String], default: [] }
}, { collection: 'Valuer' });
const Valuer = mongoose.model('Valuer', valuerSchema);

const bookingSchema = new mongoose.Schema({
    bookingId: { type: String, unique: true, required: true },
    branchCode: String,
    valuerSysId: String,
    goldWeightGrams: String,
    status: { type: String, default: 'assigned' },
    timestamp: { type: Date, default: Date.now }
}, { collection: 'Booking' });
const Booking = mongoose.model('Booking', bookingSchema);

// --- REST API ENDPOINTS CONTROLLERS LAYER ---

// Branches Routing
app.get('/api/branches', async (req, res) => { try { res.json(await Branch.find({})); } catch(e) { res.status(500).json(e); } });
app.post('/api/branches', async (req, res) => { try { const b = new Branch(req.body); await b.save(); res.status(201).json(b); } catch(e) { res.status(400).json(e); } });

// GLO Routing
app.get('/api/glos', async (req, res) => { try { res.json(await GloUser.find({})); } catch(e) { res.status(500).json(e); } });
app.post('/api/glos', async (req, res) => { try { const g = new GloUser(req.body); await g.save(); res.status(201).json(g); } catch(e) { res.status(400).json(e); } });

// Agency Routing
app.get('/api/agencies', async (req, res) => { try { res.json(await Agency.find({})); } catch(e) { res.status(500).json(e); } });
app.post('/api/agencies', async (req, res) => { try { const a = new Agency(req.body); await a.save(); res.status(201).json(a); } catch(e) { res.status(400).json(e); } });

// Valuers Routing
app.get('/api/valuers', async (req, res) => { try { res.json(await Valuer.find({})); } catch(e) { res.status(500).json(e); } });
app.post('/api/valuers', async (req, res) => { try { const v = new Valuer(req.body); await v.save(); res.status(201).json(v); } catch(e) { res.status(400).json(e); } });

// Booking Allocation Transactions Routing
app.get('/api/bookings', async (req, res) => { try { res.json(await Booking.find({}).sort({ timestamp: -1 })); } catch(e) { res.status(500).json(e); } });
app.post('/api/bookings', async (req, res) => {
    try {
        const uniqueId = "BK-" + Math.floor(100000 + Math.random() * 900000);
        const b = new Booking({ ...req.body, bookingId: uniqueId });
        await b.save();
        
        // Lock Valuer Availability status on match lock
        await Valuer.findOneAndUpdate({ sysId: req.body.valuerSysId }, { status: 'engaged' });
        
        res.status(201).json(b);
    } catch(e) { res.status(400).json(e); }
});

// Update Lifecycle Actions and HO Fraud Threshold Triggers
app.put('/api/bookings/status', async (req, res) => {
    const { bookingId, status } = req.body;
    try {
        const booking = await Booking.findOneAndUpdate({ bookingId: bookingId }, { status: status }, { new: true });
        
        if (status === 'completed') {
            // Free the valuer asset back to the marketplace pool
            await Valuer.findOneAndUpdate({ sysId: booking.valuerSysId }, { status: 'available' });
        } else if (status === 'rejected') {
            // Increment the operational failure count flag and release them
            const updatedValuer = await Valuer.findOneAndUpdate(
                { sysId: booking.valuerSysId }, 
                { $inc: { rejectionsCount: 1 }, status: 'available' },
                { new: true }
            );
            
            // HO Rule Automation: Auto-blacklist valuer from this specific branch if they exceed 3 structural rejections
            if (updatedValuer.rejectionsCount >= 3) {
                await Valuer.findOneAndUpdate(
                    { sysId: booking.valuerSysId },
                    { $addToSet: { blacklistedBranchCodes: booking.branchCode } }
                );
            }
        }
        res.json(booking);
    } catch(e) { res.status(400).json(e); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Active Enterprise Tunnel open running on port ${PORT}`));
