/**
 * ServerAdmin - Quản lý tài khoản người dùng
 * Chạy trên port 5000
 */
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const db = require('./db');

const app = express();
const PORT = process.env.ADMIN_PORT || 5000;

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
    secret: process.env.SESSION_SECRET || 'admin-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// Auth middleware
function requireAdmin(req, res, next) {
    if (req.session && req.session.adminId) {
        return next();
    }
    if (req.xhr || req.headers.accept?.includes('application/json') || req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Chưa đăng nhập' });
    }
    return res.redirect('/login');
}

// ========================
// PUBLIC AUTH API
// ========================

app.post('/api/auth/register', async (req, res) => {
    console.log('[ServerAdmin] Register request:', req.body);
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ success: false, message: 'Vui lòng điền đủ thông tin!' });
        }
        const existing = db.findUserByEmail(email);
        if (existing) {
            return res.status(400).json({ success: false, message: 'Email đã tồn tại!' });
        }
        const user = db.createUser({ username, email, password, role: 'user' });
        console.log('[ServerAdmin] User registered:', user.id);
        res.status(201).json({ success: true, message: 'Đăng ký thành công!' });
    } catch (err) {
        console.error('[ServerAdmin] Register error:', err);
        res.status(500).json({ success: false, message: 'Lỗi Server: ' + err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, deviceId } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Vui lòng nhập email và mật khẩu!' });
        }
        const user = db.findUserByEmail(email);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Email không tồn tại!' });
        }
        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Sai mật khẩu!' });
        }
        if (deviceId) {
            db.upsertDevice(user.id, {
                deviceId,
                userAgent: req.headers['user-agent'] || '',
                platform: req.body.platform || '',
                ipAddress: req.ip || ''
            });
        }
        console.log('[ServerAdmin] User logged in:', user.id);
        res.json({
            success: true, message: 'Đăng nhập thành công!',
            user: { _id: user.id, username: user.username, email: user.email, role: user.role, avatarUrl: user.avatarUrl, phoneNumber: user.phoneNumber, language: user.language, createdAt: user.createdAt }
        });
    } catch (err) {
        console.error('[ServerAdmin] Login error:', err);
        res.status(500).json({ success: false, message: 'Lỗi Server: ' + err.message });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: 'Vui lòng nhập email!' });
        const user = db.findUserByEmail(email);
        if (!user) return res.status(404).json({ success: false, message: 'Email không tồn tại!' });
        const crypto = require('crypto');
        const resetToken = crypto.randomUUID();
        const expires = Date.now() + 15 * 60 * 1000;
        db.updateUser(user.id, { resetPasswordToken: resetToken, resetPasswordExpires: expires });
        const resetUrl = `http://localhost:4000/auth/reset-password/${resetToken}`;
        console.log('[ServerAdmin] Reset URL:', resetUrl);
        res.json({ success: true, message: 'Link khôi phục đã được tạo!', resetUrl });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Lỗi Server: ' + err.message });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(400).json({ success: false, message: 'Thiếu token hoặc mật khẩu mới!' });
        const d = db.getDb();
        const user = d.prepare('SELECT * FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > ?').get(token, Date.now());
        if (!user) return res.status(400).json({ success: false, message: 'Token hết hạn hoặc không hợp lệ!' });
        db.updateUserPassword(user.id, newPassword);
        db.updateUser(user.id, { resetPasswordToken: null, resetPasswordExpires: null });
        res.json({ success: true, message: 'Đặt lại mật khẩu thành công!' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Lỗi Server: ' + err.message });
    }
});

app.put('/api/auth/change-password', async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;
        if (!userId || !currentPassword || !newPassword) return res.status(400).json({ success: false, message: 'Thiếu thông tin!' });
        const user = db.findUserById(userId);
        if (!user) return res.status(404).json({ success: false, message: 'Người dùng không tồn tại!' });
        const fullUser = db.getDb().prepare('SELECT * FROM users WHERE id = ?').get(userId);
        const isMatch = bcrypt.compareSync(currentPassword, fullUser.password);
        if (!isMatch) return res.status(401).json({ success: false, message: 'Mật khẩu hiện tại không đúng!' });
        db.updateUserPassword(userId, newPassword);
        res.json({ success: true, message: 'Đổi mật khẩu thành công!' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Lỗi Server: ' + err.message });
    }
});

app.get('/api/auth/profile/:id', async (req, res) => {
    try {
        const user = db.findUserById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, user: { _id: user.id, ...user } });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/auth/profile/:id', async (req, res) => {
    try {
        const { username, phoneNumber, avatarUrl, language } = req.body;
        const updateData = {};
        if (username) updateData.username = username;
        if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;
        if (avatarUrl) updateData.avatarUrl = avatarUrl;
        if (language) updateData.language = language;
        db.updateUser(req.params.id, updateData);
        const user = db.findUserById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, user: { _id: user.id, ...user } });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/auth/device', async (req, res) => {
    try {
        const { userId, deviceId, platform } = req.body;
        if (!userId || !deviceId) return res.status(400).json({ success: false, message: 'Missing userId or deviceId' });
        const user = db.findUserById(userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        db.upsertDevice(userId, { deviceId, userAgent: req.headers['user-agent'] || '', platform: platform || '', ipAddress: req.ip || '' });
        const devices = db.getUserDevices(userId);
        res.json({ success: true, deviceCount: devices.length });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ========================
// AUTH ROUTES (Admin login)
// ========================
app.get('/login', (req, res) => {
    if (req.session && req.session.adminId) return res.redirect('/');
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.render('login', { error: 'Vui lòng nhập email và mật khẩu' });
        const user = db.findUserByEmail(email);
        if (!user) return res.render('login', { error: 'Email hoặc mật khẩu không đúng' });
        if (user.role !== 'admin') return res.render('login', { error: 'Tài khoản không có quyền admin' });
        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) return res.render('login', { error: 'Email hoặc mật khẩu không đúng' });
        req.session.adminId = user.id;
        req.session.adminName = user.username;
        req.session.adminEmail = user.email;
        res.redirect('/');
    } catch (err) {
        res.render('login', { error: 'Lỗi hệ thống: ' + err.message });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// ========================
// FEATURE VISIBILITY API
// ========================

app.get('/api/features', async (req, res) => {
    try {
        res.json(db.getFeatures());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/features', requireAdmin, async (req, res) => {
    try {
        const features = db.updateFeatures(req.body);
        res.json({ message: 'Cập nhật thành công', features });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========================
// FEEDBACK API
// ========================

app.post('/api/feedback', async (req, res) => {
    try {
        const { userId, feature, type, title, description, priority } = req.body;
        if (!userId || !title || !description) {
            return res.status(400).json({ success: false, error: 'Thiếu thông tin bắt buộc' });
        }
        const feedback = db.createFeedback({ userId, feature, type, title, description, priority });
        console.log('[ServerAdmin] Feedback created:', feedback.id);
        res.status(201).json({ success: true, feedback });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put('/api/feedback/sync/:id', async (req, res) => {
    try {
        const { title, description, type, priority, feature, status } = req.body;
        const updates = {};
        if (title) updates.title = title;
        if (description) updates.description = description;
        if (type) updates.type = type;
        if (priority) updates.priority = priority;
        if (feature) updates.feature = feature;
        if (status) updates.status = status;
        db.updateFeedback(req.params.id, updates);
        const feedback = db.getFeedbackDetail(req.params.id);
        if (!feedback) return res.status(404).json({ success: false, error: 'Feedback not found' });
        console.log('[ServerAdmin] Feedback synced:', req.params.id);
        res.json({ success: true, feedback });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete('/api/feedback/sync/:id', async (req, res) => {
    try {
        const feedback = db.getFeedbackDetail(req.params.id);
        if (!feedback) return res.status(404).json({ success: false, error: 'Feedback not found' });
        db.deleteFeedback(req.params.id);
        console.log('[ServerAdmin] Feedback deleted (sync):', req.params.id);
        res.json({ success: true, message: 'Deleted' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/feedback', requireAdmin, async (req, res) => {
    try {
        const { search = '', status = '', type = '', priority = '' } = req.query;
        const feedbacks = db.getFeedbacks({ search, status, type, priority });
        res.json({ feedbacks });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/feedback/detail/:id', requireAdmin, async (req, res) => {
    try {
        const feedback = db.getFeedbackDetail(req.params.id);
        if (!feedback) return res.status(404).json({ error: 'Feedback not found' });
        res.json(feedback);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/feedback/:id', requireAdmin, async (req, res) => {
    try {
        const { status, priority, adminNote } = req.body;
        const updates = {};
        if (status) updates.status = status;
        if (priority) updates.priority = priority;
        if (adminNote !== undefined) updates.adminNote = adminNote;
        const feedback = db.updateFeedback(req.params.id, updates);
        res.json({ message: 'Cập nhật thành công', feedback });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/feedback/:id', requireAdmin, async (req, res) => {
    try {
        const feedback = db.getFeedbackDetail(req.params.id);
        if (!feedback) return res.status(404).json({ error: 'Feedback not found' });
        db.deleteFeedback(req.params.id);
        res.json({ message: 'Xóa thành công' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========================
// ADMIN API
// ========================

app.get('/api/stats', requireAdmin, async (req, res) => {
    try {
        res.json(db.getStats());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const search = req.query.search || '';
        const role = req.query.role || '';
        const sortBy = req.query.sortBy || 'createdAt';
        const sortOrder = req.query.sortOrder === 'asc' ? 'asc' : 'desc';
        const result = db.getUsers({ page, limit, search, role, sortBy, sortOrder });
        // Convert id to _id for frontend
        result.users = result.users.map(u => ({ _id: u.id, ...u }));
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users/:id', requireAdmin, async (req, res) => {
    try {
        const user = db.findUserById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ _id: user.id, ...user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
    try {
        const { username, email, phoneNumber, role, language } = req.body;
        const updateData = {};
        if (username) updateData.username = username;
        if (email) updateData.email = email;
        if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;
        if (role) updateData.role = role;
        if (language) updateData.language = language;
        db.updateUser(req.params.id, updateData);
        const user = db.findUserById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'Cập nhật thành công', user: { _id: user.id, ...user } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/users/:id/password', requireAdmin, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Mật khẩu phải có ít nhất 6 ký tự' });
        db.updateUserPassword(req.params.id, newPassword);
        res.json({ message: 'Đổi mật khẩu thành công' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
    try {
        const user = db.findUserById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        db.deleteUser(req.params.id);
        res.json({ message: 'Xóa user thành công' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users', requireAdmin, async (req, res) => {
    try {
        const { username, email, password, phoneNumber, role } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin' });
        const existing = db.findUserByEmail(email);
        if (existing) return res.status(400).json({ error: 'Email đã tồn tại' });
        const user = db.createUser({ username, email, password, phoneNumber: phoneNumber || '', role: role || 'user' });
        res.status(201).json({ message: 'Tạo user thành công', user: { _id: user.id, ...user, password: undefined } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/users/:id/devices/:deviceId', requireAdmin, async (req, res) => {
    try {
        const user = db.findUserById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        db.removeDevice(req.params.id, req.params.deviceId);
        res.json({ message: 'Xóa device thành công' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========================
// LANDING PAGE ROUTES
// ========================

app.get('/', (req, res) => {
    if (req.session && req.session.adminId) {
        return res.render('dashboard', {
            adminName: req.session.adminName || 'Admin',
            adminEmail: req.session.adminEmail || ''
        });
    }
    res.render('landing/index');
});

app.get('/features/schedule', (req, res) => { res.render('landing/features/schedule'); });
app.get('/features/ai-content', (req, res) => { res.render('landing/features/ai-content'); });
app.get('/features/auto-comment', (req, res) => { res.render('landing/features/auto-comment'); });
app.get('/features/ai-scan', (req, res) => { res.render('landing/features/ai-scan'); });
app.get('/features/analytics', (req, res) => { res.render('landing/features/analytics'); });

app.get('/about', (req, res) => { res.render('landing/about'); });
app.get('/blog', (req, res) => { res.render('landing/blog'); });
app.get('/careers', (req, res) => { res.render('landing/careers'); });
app.get('/privacy', (req, res) => { res.render('landing/privacy'); });
app.get('/terms', (req, res) => { res.render('landing/terms'); });
app.get('/download', (req, res) => { res.render('landing/download'); });
app.get('/pricing', (req, res) => { res.render('landing/pricing'); });
app.get('/docs', (req, res) => { res.render('landing/docs'); });

app.get('/dashboard', requireAdmin, (req, res) => {
    res.render('dashboard', {
        adminName: req.session.adminName || 'Admin',
        adminEmail: req.session.adminEmail || ''
    });
});

app.get('/feedback', requireAdmin, (req, res) => {
    res.render('feedback', {
        adminName: req.session.adminName || 'Admin',
        adminEmail: req.session.adminEmail || ''
    });
});

// ========================
// AUTO-SEED ADMIN ACCOUNT
// ========================
function seedAdmin() {
    const email = 'nluat134@gmail.com';
    const existing = db.findUserByEmail(email);
    if (existing) {
        db.updateUser(existing.id, { role: 'admin', username: 'nluat134' });
        db.updateUserPassword(existing.id, 'anhluat165');
        console.log('✅ Admin account synced');
    } else {
        db.createUser({ username: 'nluat134', email, password: 'anhluat165', role: 'admin' });
        console.log('✅ Admin account created');
    }
}

// ========================
// START SERVER
// ========================
seedAdmin();
app.listen(PORT, () => {
    console.log(`🚀 [ServerAdmin] Đang chạy tại http://localhost:${PORT}`);
});
