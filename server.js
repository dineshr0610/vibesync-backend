const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
require('dotenv').config();
const { getRecommendations } = require('./services/recommender');
const Brevo = require('@getbrevo/brevo');

const apiInstance = new Brevo.TransactionalEmailsApi();
apiInstance.setApiKey(
    Brevo.TransactionalEmailsApiApiKeys.apiKey,
    process.env.BREVO_API_KEY
);
const cron = require('node-cron');
const morgan = require('morgan');
const fs = require('fs');
const app = express();
app.use(morgan('dev'));
app.use(cors());
app.use(express.json());

// Global Error Handler for Unhandled Rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

// Connect to MongoDB
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB Atlas!');
    })
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
    });

// Define Schemas
const SongSchema = new mongoose.Schema({
    title: String,
    artist: String,
    audioUrl: String,
    coverImage: String,
    genre: String
});

const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, sparse: true },
    phone: { type: String, unique: true, sparse: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] },
    otp: String,
    otpExpires: Date,
    lastActive: { type: Date, default: Date.now },
    warningSent: { type: Boolean, default: false },
    favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Song' }],
    recentlyPlayed: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Song' }]
});

const PlaylistSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    songs: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Song' }]
});

const Song = mongoose.model('Song', SongSchema, 'song');
const User = mongoose.model('User', UserSchema, 'users');
const Playlist = mongoose.model('Playlist', PlaylistSchema, 'playlists');

// --- EMAIL TRANSPORTER ---
// --- EMAIL TRANSPORTER REMOVED ---
// Resend is now used directly via the `resend` instance initialized at the top.

// --- CRON JOBS ---
// Run every day at midnight (0 0 * * *)
// NOTE: For testing purposes, you can change this to '* * * * *' to run every minute
cron.schedule('0 0 * * *', async () => {
    console.log('[CRON] Running daily user maintenance...');
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
    const fifteenDaysAgo = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);

    try {
        // 1. Send warning to users inactive for 10 days
        const usersToWarn = await User.find({ lastActive: { $lt: tenDaysAgo }, warningSent: false });
        for (const user of usersToWarn) {
            if (user.email) {
                console.log(`[EMAIL] Sending warning to ${user.email}`);
                try {
                    const sendSmtpEmail = new Brevo.SendSmtpEmail();
                    sendSmtpEmail.subject = "Urgent: Your VibeSync account will be deleted in 5 days";
                    sendSmtpEmail.htmlContent = `<p>Hi,</p><p>You haven't logged in for 10 days. Please log in within 5 days to keep your account active!</p>`;
                    sendSmtpEmail.sender = { name: "VibeSync", email: "bobby06102005@gmail.com" };
                    sendSmtpEmail.to = [{ email: user.email }];

                    const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
                    console.log("Brevo Response:", response);
                } catch (emailError) {
                    console.error("Brevo Email Error:", emailError.response?.body || emailError);
                }
            } else {
                console.log(`[WARNING] User ${user._id} has no email, skipping notification.`);
            }
            user.warningSent = true;
            await user.save();
        }

        // 2. Delete users inactive for 15 days
        const result = await User.deleteMany({ lastActive: { $lt: fifteenDaysAgo } });
        if (result.deletedCount > 0) {
            console.log(`[CLEANUP] Deleted ${result.deletedCount} inactive accounts.`);
        }
    } catch (err) {
        console.error('[CRON] Error:', err);
    }
});


// --- ROUTES ---

// Middleware: Admin Check
const ADMIN_EMAILS = ['dinesh2370049@ssn.edu.in', 'bobby06102005@gmail.com'];

const isAdmin = async (req, res, next) => {
    const userId = req.headers['x-user-id'];
    if (!userId) return res.status(401).json({ error: "Unauthorized: No User ID" });

    try {
        const user = await User.findById(userId);
        // Allow if role is admin OR email is in allowable list
        const isEmailAdmin = user && (user.email && ADMIN_EMAILS.includes(user.email));

        if (!user || (user.role !== 'admin' && !isEmailAdmin)) {
            return res.status(403).json({ error: "Access Denied: Admins Only" });
        }

        // Auto-promote if strictly email match but role is user (optional, but good for consistency)
        if (isEmailAdmin && user.role !== 'admin') {
            user.role = 'admin';
            await user.save();
        }

        req.user = user; // Attach user to request
        next();
    } catch (e) {
        res.status(500).json({ error: "Server Error during Auth" });
    }
};

// Root route
app.get('/', (req, res) => {
    res.send('VibeSync Backend is Running! 🚀');
});

// Song Routes
app.get('/songs', async (req, res) => {
    try {
        const songs = await Song.find();
        return res.json(songs);
    } catch (error) {
        console.error("[ERROR] GET /songs failed:", error);
        res.status(500).json({ message: 'Error fetching songs', error });
    }
});

app.post('/songs', async (req, res) => {
    try {
        const { title, artist, audioUrl, coverImage } = req.body;
        const newSong = new Song({ title, artist, audioUrl, coverImage });
        await newSong.save();
        res.status(201).json({ message: 'Song added successfully', song: newSong });
    } catch (error) {
        res.status(500).json({ message: 'Error adding song', error });
    }
});

// Get all unique genres
app.get('/genres', async (req, res) => {
    try {
        const genres = await Song.distinct('genre');
        // Filter out null/empty genres and sort alphabestically
        const cleanGenres = genres.filter(g => g).sort();
        res.json(cleanGenres);
    } catch (error) {
        console.error("Error fetching genres:", error);
        res.status(500).json({ message: 'Error fetching genres', error });
    }
});

// Auth Routes
app.post('/auth/send-otp', async (req, res) => {
    try {
        const { email, phone } = req.body;
        if (!email && !phone) return res.status(400).json({ error: "Email or Phone required" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 5 * 60 * 1000);

        // Advanced Logic: Find by Email OR Phone to prevent duplicates
        // If a user exists with either, update that user.
        let user = await User.findOne({
            $or: [
                { email: email || "nomatch" },
                { phone: phone || "nomatch" }
            ]
        });

        const isReturningUser = !!user;
        const greetingLine = isReturningUser
            ? "Welcome back to VibeSync."
            : "Welcome to VibeSync.";
        const purposeLine = isReturningUser
            ? "Use this one-time passcode to sign in and continue your music journey."
            : "Thanks for joining VibeSync. Use this one-time passcode to verify your account and get started.";
        const emailSubject = isReturningUser
            ? "Your VibeSync sign-in OTP"
            : "Welcome to VibeSync - verify your account";

        if (user) {
            // Update existing
            user.otp = otp;
            user.otpExpires = expires;
            // Link missing fields if provided
            if (email && !user.email) user.email = email;
            if (phone && !user.phone) user.phone = phone;
            await user.save();
        } else {
            // Create new
            user = await User.create({
                email,
                phone,
                otp,
                otpExpires: expires
            });
        }

        // Send Email if email is present
        // Send Email if email is present
        if (email) {
            const templatePath = path.join(__dirname, 'templates', 'otp-email.html');
            let htmlContent = fs.readFileSync(templatePath, 'utf8');
            htmlContent = htmlContent.replace('{{OTP_CODE}}', otp);
            htmlContent = htmlContent.replace('{{GREETING_LINE}}', greetingLine);
            htmlContent = htmlContent.replace('{{PURPOSE_LINE}}', purposeLine);

            const sendSmtpEmail = new Brevo.SendSmtpEmail();
            sendSmtpEmail.subject = emailSubject;
            sendSmtpEmail.htmlContent = htmlContent;
            sendSmtpEmail.sender = {
                name: "VibeSync",
                email: "bobby06102005@gmail.com"
            };
            sendSmtpEmail.to = [{ email }];

            try {
                const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
                console.log("Brevo Response:", response);
            } catch (emailError) {
                console.error("Brevo Email Error:", emailError.response?.body || emailError);
                return res.status(500).json({ error: "Email delivery failed." });
            }
        }

        // (Mock) Send SMS if phone is present
        if (phone) {
            console.log(`[SMS MOCK] Sending OTP ${otp} to ${phone}`);
        }

        res.json({
            message: isReturningUser
                ? "OTP sent. Welcome back to VibeSync."
                : "OTP sent. Welcome to VibeSync."
        });
    } catch (err) {
        console.error("Auth Error:", err);
        res.status(500).json({ error: "Failed to process auth request." });
    }
});

app.post('/auth/verify-otp', async (req, res) => {
    try {
        const { phone, email, otp } = req.body;
        const user = await User.findOne({
            $or: [{ phone }, { email }],
            otp,
            otpExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ error: "Invalid or expired OTP" });

        user.otp = undefined; // Clear OTP
        user.otpExpires = undefined;
        user.lastActive = Date.now();
        user.warningSent = false;
        await user.save();

        res.json({ message: "Login successful", userId: user._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- RECENTLY PLAYED ROUTES ---
app.get('/users/:userId/recently-played', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).populate('recentlyPlayed');
        res.json(user ? user.recentlyPlayed : []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/users/:userId/recently-played', async (req, res) => {
    try {
        const { songId } = req.body;
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        // 1. Remove if already exists (FILO)
        user.recentlyPlayed = user.recentlyPlayed.filter(id => id.toString() !== songId);

        // 2. Add to start
        user.recentlyPlayed.unshift(songId);

        // 3. Strict cap of 25
        if (user.recentlyPlayed.length > 25) {
            user.recentlyPlayed = user.recentlyPlayed.slice(0, 25);
        }

        await user.save();
        res.json(user.recentlyPlayed);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- FAVORITES ROUTES ---
app.post('/favorites/toggle', async (req, res) => {
    try {
        const { userId, songId } = req.body;
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        const index = user.favorites.indexOf(songId);
        if (index === -1) {
            user.favorites.push(songId); // Add
        } else {
            user.favorites.splice(index, 1); // Remove
        }
        await user.save();
        res.json({ message: "Favorites updated", favorites: user.favorites });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/favorites/:userId', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).populate('favorites');
        res.json(user ? user.favorites : []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PLAYLIST ROUTES ---
app.post('/playlists', async (req, res) => {
    try {
        const { userId, name } = req.body;
        const newPlaylist = new Playlist({ userId, name, songs: [] });
        await newPlaylist.save();
        res.json(newPlaylist);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/playlists/:userId', async (req, res) => {
    try {
        const playlists = await Playlist.find({ userId: req.params.userId }).populate('songs');
        res.json(playlists);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Add song to playlist
app.post('/playlists/:id/add', async (req, res) => {
    try {
        const { songId } = req.body;
        const playlist = await Playlist.findById(req.params.id);
        if (!playlist.songs.includes(songId)) {
            playlist.songs.push(songId);
            await playlist.save();
        }
        res.json(playlist);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Remove song from playlist
app.delete('/playlists/:id/songs/:songId', async (req, res) => {
    try {
        const playlist = await Playlist.findById(req.params.id);
        playlist.songs = playlist.songs.filter(id => id.toString() !== req.params.songId);
        await playlist.save();
        res.json(playlist);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Rename Playlist
app.put('/playlists/:id', async (req, res) => {
    try {
        const { name } = req.body;
        const playlist = await Playlist.findByIdAndUpdate(req.params.id, { name }, { new: true });
        res.json(playlist);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete Playlist
app.delete('/playlists/:id', async (req, res) => {
    try {
        await Playlist.findByIdAndDelete(req.params.id);
        res.json({ message: "Playlist deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Recommendations Route (Using Hybrid Logic)
app.get('/recommendations/:userId', async (req, res) => {
    try {
        const recommendations = await getRecommendations(req.params.userId, Song, User, Playlist);
        res.json(recommendations);
    } catch (error) {
        console.error("Recs Error:", error);
        res.status(500).json({ message: 'Error fetching recommendations', error: error.message });
    }
});



// --- ADMIN CRUD ROUTES ---
app.use('/admin', isAdmin); // Protect all /admin routes

// --- SONG MANAGEMENT ---
// Add a new song
app.post('/admin/songs', async (req, res) => {
    try {
        const newSong = new Song(req.body);
        await newSong.save();
        res.status(201).json(newSong);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update an existing song
app.put('/admin/songs/:id', async (req, res) => {
    try {
        const updated = await Song.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(updated);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete a song
app.delete('/admin/songs/:id', async (req, res) => {
    try {
        await Song.findByIdAndDelete(req.params.id);
        res.json({ message: "Song removed" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- USER MANAGEMENT ---
// Get all users for the dashboard list
app.get('/admin/users', async (req, res) => {
    try {
        const users = await User.find({}, '-otp -otpExpires'); // Exclude sensitive OTP data
        res.json(users);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update user details manually
app.put('/admin/users/:id', async (req, res) => {
    try {
        const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(updatedUser);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete a specific user account
app.delete('/admin/users/:id', async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: "User account deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Wipe all users (Caution)
app.delete('/admin/wipe-users', async (req, res) => {
    try {
        await User.deleteMany({});
        res.json({ message: "All user data deleted successfully." });
    } catch (err) {
        res.status(500).send(err);
    }
});

app.get('/admin/dashboard', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);

        // Count users who haven't logged in for 10+ days
        const inactiveUsers = await User.countDocuments({ lastActive: { $lt: tenDaysAgo } });
        const totalSongs = await Song.countDocuments();

        // Calculate uptime
        const uptimeSeconds = process.uptime();
        const uptimeHours = Math.floor(uptimeSeconds / 3600);
        const uptimeMinutes = Math.floor((uptimeSeconds % 3600) / 60);

        res.json({
            status: "Success",
            stats: {
                total_users: totalUsers,
                inactive_at_risk: inactiveUsers,
                total_songs: totalSongs,
                server_uptime: `${uptimeHours}h ${uptimeMinutes}m`,
                database_host: "cluster0.kyfx7xc.mongodb.net" // Your Atlas cluster
            }
        });
    } catch (error) {
        res.status(500).json({ error: "Could not load dashboard stats", details: error.message });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
