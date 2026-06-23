const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH || (process.env.VERCEL ? '/tmp/server-admin.db' : path.join(__dirname, 'data', 'server-admin.db'));

let db;

function getDb() {
    if (!db) {
        const fs = require('fs');
        const dir = path.dirname(DB_PATH);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        db = new Database(DB_PATH);
        db.pragma('journal_mode = WAL');
        db.pragma('foreign_keys = ON');
        initSchema();
    }
    return db;
}

function initSchema() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL UNIQUE,
            phoneNumber TEXT DEFAULT '',
            avatarUrl TEXT DEFAULT '',
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user' CHECK(role IN ('user','admin')),
            language TEXT DEFAULT 'vi' CHECK(language IN ('vi','en')),
            resetPasswordToken TEXT,
            resetPasswordExpires INTEGER,
            createdAt TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            deviceId TEXT NOT NULL,
            userAgent TEXT DEFAULT '',
            platform TEXT DEFAULT '',
            lastLogin TEXT DEFAULT (datetime('now')),
            isActive INTEGER DEFAULT 1,
            ipAddress TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS feature_visibility (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dashboard INTEGER DEFAULT 1,
            channels INTEGER DEFAULT 1,
            storage INTEGER DEFAULT 1,
            shopeeLink INTEGER DEFAULT 1,
            schedule_manager INTEGER DEFAULT 1,
            schedule_post INTEGER DEFAULT 1,
            schedule_reels INTEGER DEFAULT 1,
            schedule_archive INTEGER DEFAULT 1,
            schedule_groups INTEGER DEFAULT 1,
            ai_scan INTEGER DEFAULT 1,
            ai_comments INTEGER DEFAULT 1,
            comment_crawler INTEGER DEFAULT 1,
            comment_play INTEGER DEFAULT 1,
            ai_reply_messenger INTEGER DEFAULT 1,
            ai_content INTEGER DEFAULT 1,
            feedback INTEGER DEFAULT 1,
            profile INTEGER DEFAULT 1,
            settings INTEGER DEFAULT 1,
            createdAt TEXT DEFAULT (datetime('now')),
            updatedAt TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS feedbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            feature TEXT NOT NULL,
            type TEXT DEFAULT 'bug' CHECK(type IN ('bug','feature','improvement','question')),
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','resolved','closed')),
            priority TEXT DEFAULT 'medium' CHECK(priority IN ('low','medium','high','critical')),
            attachments TEXT DEFAULT '[]',
            adminNote TEXT DEFAULT '',
            createdAt TEXT DEFAULT (datetime('now')),
            updatedAt TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS feedback_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feedbackId INTEGER NOT NULL REFERENCES feedbacks(id) ON DELETE CASCADE,
            text TEXT NOT NULL,
            isAdmin INTEGER DEFAULT 0,
            userName TEXT DEFAULT '',
            createdAt TEXT DEFAULT (datetime('now'))
        );
    `);
}

// ============== USER OPERATIONS ==============

function createUser({ username, email, password, role = 'user', phoneNumber = '' }) {
    const d = getDb();
    const hashed = bcrypt.hashSync(password, 10);
    const stmt = d.prepare('INSERT INTO users (username, email, password, role, phoneNumber) VALUES (?, ?, ?, ?, ?)');
    const result = stmt.run(username, email, hashed, role, phoneNumber);
    return { id: result.lastInsertRowid, username, email, role };
}

function findUserByEmail(email) {
    const d = getDb();
    return d.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function findUserById(id) {
    const d = getDb();
    return d.prepare('SELECT id, username, email, phoneNumber, avatarUrl, role, language, createdAt FROM users WHERE id = ?').get(id);
}

function updateUser(id, fields) {
    const d = getDb();
    const setClauses = [];
    const values = [];
    for (const [key, val] of Object.entries(fields)) {
        if (val !== undefined) {
            setClauses.push(`${key} = ?`);
            values.push(val);
        }
    }
    if (setClauses.length === 0) return;
    values.push(id);
    d.prepare(`UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);
}

function updateUserPassword(id, newPassword) {
    const d = getDb();
    const hashed = bcrypt.hashSync(newPassword, 10);
    d.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashed, id);
}

function deleteUser(id) {
    const d = getDb();
    d.prepare('DELETE FROM users WHERE id = ?').run(id);
}

function countUsers(roleFilter = '') {
    const d = getDb();
    if (roleFilter) {
        return d.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get(roleFilter).count;
    }
    return d.prepare('SELECT COUNT(*) as count FROM users').get().count;
}

function getUsers({ page = 1, limit = 20, search = '', role = '', sortBy = 'createdAt', sortOrder = 'desc' }) {
    const d = getDb();
    const offset = (page - 1) * limit;
    const orderDir = sortOrder === 'asc' ? 'ASC' : 'DESC';
    const allowedSort = ['createdAt', 'username', 'email', 'role'];
    const sortCol = allowedSort.includes(sortBy) ? sortBy : 'createdAt';

    let where = '';
    const params = [];
    if (search) {
        where = 'WHERE (username LIKE ? OR email LIKE ? OR phoneNumber LIKE ?)';
        const s = `%${search}%`;
        params.push(s, s, s);
    }
    if (role) {
        where = where ? `${where} AND role = ?` : 'WHERE role = ?';
        params.push(role);
    }

    const total = d.prepare(`SELECT COUNT(*) as count FROM users ${where}`).get(...params).count;
    const users = d.prepare(`SELECT id, username, email, phoneNumber, avatarUrl, role, language, createdAt FROM users ${where} ORDER BY ${sortCol} ${orderDir} LIMIT ? OFFSET ?`).all(...params, limit, offset);

    return { users, pagination: { page, limit, total, totalPages: Math.ceil(total / limit) } };
}

function getRegistrationChart(days = 30) {
    const d = getDb();
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
    return d.prepare(`SELECT date(createdAt) as _id, COUNT(*) as count FROM users WHERE createdAt >= ? GROUP BY _id ORDER BY _id ASC`).all(since);
}

function getActiveDevicesCount() {
    const d = getDb();
    const row = d.prepare('SELECT COUNT(*) as total FROM devices WHERE isActive = 1').get();
    return row.total;
}

// ============== DEVICE OPERATIONS ==============

function upsertDevice(userId, { deviceId, userAgent, platform, ipAddress }) {
    const d = getDb();
    const existing = d.prepare('SELECT * FROM devices WHERE userId = ? AND deviceId = ?').get(userId, deviceId);
    if (existing) {
        d.prepare('UPDATE devices SET lastLogin = datetime("now"), userAgent = ?, platform = ?, ipAddress = ? WHERE id = ?').run(userAgent || '', platform || '', ipAddress || '', existing.id);
    } else {
        d.prepare('INSERT INTO devices (userId, deviceId, userAgent, platform, ipAddress) VALUES (?, ?, ?, ?, ?)').run(userId, deviceId, userAgent || '', platform || '', ipAddress || '');
    }
}

function removeDevice(userId, deviceId) {
    const d = getDb();
    d.prepare('DELETE FROM devices WHERE userId = ? AND deviceId = ?').run(userId, deviceId);
}

function getUserDevices(userId) {
    const d = getDb();
    return d.prepare('SELECT deviceId, userAgent, platform, lastLogin, isActive, ipAddress FROM devices WHERE userId = ?').all(userId);
}

// ============== FEATURE VISIBILITY ==============

function getFeatures() {
    const d = getDb();
    let row = d.prepare('SELECT * FROM feature_visibility ORDER BY id DESC LIMIT 1').get();
    if (!row) {
        d.prepare('INSERT INTO feature_visibility DEFAULT VALUES').run();
        row = d.prepare('SELECT * FROM feature_visibility ORDER BY id DESC LIMIT 1').get();
    }
    // Convert snake_case to camelCase/feature names
    const map = {
        schedule_manager: 'schedule-manager',
        schedule_post: 'schedule-post',
        schedule_reels: 'schedule-reels',
        schedule_archive: 'schedule-archive',
        schedule_groups: 'schedule-groups',
        ai_scan: 'ai-scan',
        ai_comments: 'ai-comments',
        comment_crawler: 'comment-crawler',
        comment_play: 'comment-play',
        ai_reply_messenger: 'ai-reply-messenger',
        ai_content: 'ai-content'
    };
    const result = {};
    for (const [key, val] of Object.entries(row)) {
        if (key === 'id' || key === 'createdAt' || key === 'updatedAt') continue;
        const mapped = map[key] || key;
        result[mapped] = !!val;
    }
    return result;
}

function updateFeatures(updates) {
    const d = getDb();
    const map = {
        'schedule-manager': 'schedule_manager',
        'schedule-post': 'schedule_post',
        'schedule-reels': 'schedule_reels',
        'schedule-archive': 'schedule_archive',
        'schedule-groups': 'schedule_groups',
        'ai-scan': 'ai_scan',
        'ai-comments': 'ai_comments',
        'comment-crawler': 'comment_crawler',
        'comment-play': 'comment_play',
        'ai-reply-messenger': 'ai_reply_messenger',
        'ai-content': 'ai_content'
    };
    const allowed = ['dashboard','channels','storage','shopeeLink','feedback','profile','settings',
        'schedule_manager','schedule_post','schedule_reels','schedule_archive','schedule_groups',
        'ai_scan','ai_comments','comment_crawler','comment_play','ai_reply_messenger','ai_content'];

    let row = d.prepare('SELECT id FROM feature_visibility ORDER BY id DESC LIMIT 1').get();
    if (!row) {
        d.prepare('INSERT INTO feature_visibility DEFAULT VALUES').run();
        row = d.prepare('SELECT id FROM feature_visibility ORDER BY id DESC LIMIT 1').get();
    }

    const setClauses = ['updatedAt = datetime("now")'];
    const values = [];
    for (let [key, val] of Object.entries(updates)) {
        const col = map[key] || key;
        if (allowed.includes(col)) {
            setClauses.push(`${col} = ?`);
            values.push(val === true || val === 'true' ? 1 : 0);
        }
    }
    if (setClauses.length > 1) {
        values.push(row.id);
        d.prepare(`UPDATE feature_visibility SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);
    }
    return getFeatures();
}

// ============== FEEDBACK OPERATIONS ==============

function createFeedback({ userId, feature, type, title, description, priority }) {
    const d = getDb();
    const stmt = d.prepare('INSERT INTO feedbacks (userId, feature, type, title, description, priority) VALUES (?, ?, ?, ?, ?, ?)');
    const result = stmt.run(userId, feature, type || 'bug', title, description, priority || 'medium');
    return d.prepare('SELECT * FROM feedbacks WHERE id = ?').get(result.lastInsertRowid);
}

function getFeedbacks({ search, status, type, priority }) {
    const d = getDb();
    const where = [];
    const params = [];
    if (search) {
        where.push('(f.title LIKE ? OR f.description LIKE ?)');
        const s = `%${search}%`;
        params.push(s, s);
    }
    if (status) { where.push('f.status = ?'); params.push(status); }
    if (type) { where.push('f.type = ?'); params.push(type); }
    if (priority) { where.push('f.priority = ?'); params.push(priority); }

    const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const rows = d.prepare(`
        SELECT f.*, u.email as userEmail, u.username as userName
        FROM feedbacks f LEFT JOIN users u ON f.userId = u.id
        ${whereClause} ORDER BY f.createdAt DESC
    `).all(...params);

    return rows.map(r => ({
        ...r,
        attachments: JSON.parse(r.attachments || '[]')
    }));
}

function getFeedbackDetail(id) {
    const d = getDb();
    const fb = d.prepare(`
        SELECT f.*, u.email as userEmail, u.username as userName
        FROM feedbacks f LEFT JOIN users u ON f.userId = u.id
        WHERE f.id = ?
    `).get(id);
    if (!fb) return null;
    fb.attachments = JSON.parse(fb.attachments || '[]');
    fb.messages = d.prepare('SELECT * FROM feedback_messages WHERE feedbackId = ? ORDER BY createdAt ASC').all(id);
    return fb;
}

function updateFeedback(id, updates) {
    const d = getDb();
    const setClauses = ['updatedAt = datetime("now")'];
    const values = [];
    for (const [key, val] of Object.entries(updates)) {
        if (val !== undefined && ['status','priority','adminNote'].includes(key)) {
            setClauses.push(`${key} = ?`);
            values.push(val);
        }
    }
    if (setClauses.length > 1) {
        values.push(id);
        d.prepare(`UPDATE feedbacks SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);
    }
    return getFeedbackDetail(id);
}

function deleteFeedback(id) {
    const d = getDb();
    d.prepare('DELETE FROM feedbacks WHERE id = ?').run(id);
}

// ============== STATS ==============

function getStats() {
    const d = getDb();
    const totalUsers = countUsers();
    const adminCount = countUsers('admin');
    const userCount = countUsers('user');

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const newUsersWeek = d.prepare('SELECT COUNT(*) as count FROM users WHERE createdAt >= ?').get(sevenDaysAgo).count;

    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const newUsersMonth = d.prepare('SELECT COUNT(*) as count FROM users WHERE createdAt >= ?').get(thirtyDaysAgo).count;

    const activeDevices = getActiveDevicesCount();
    const registrationChart = getRegistrationChart(30);

    return { totalUsers, adminCount, userCount, newUsersWeek, newUsersMonth, activeDevices, registrationChart };
}

module.exports = {
    getDb,
    createUser,
    findUserByEmail,
    findUserById,
    updateUser,
    updateUserPassword,
    deleteUser,
    countUsers,
    getUsers,
    getRegistrationChart,
    getActiveDevicesCount,
    upsertDevice,
    removeDevice,
    getUserDevices,
    getFeatures,
    updateFeatures,
    createFeedback,
    getFeedbacks,
    getFeedbackDetail,
    updateFeedback,
    deleteFeedback,
    getStats
};