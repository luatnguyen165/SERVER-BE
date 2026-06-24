const mongoose = require('mongoose');

// ============== MONGOOSE SCHEMAS ==============

const userSchema = new mongoose.Schema({
    username: { type: String, default: '' },
    email: { type: String, required: true, unique: true },
    phoneNumber: { type: String, default: '' },
    avatarUrl: { type: String, default: '' },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    language: { type: String, enum: ['vi', 'en'], default: 'vi' },
    resetPasswordToken: { type: String, default: null },
    resetPasswordExpires: { type: Number, default: null },
    createdAt: { type: Date, default: Date.now }
}, { collection: 'users' });

const deviceSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'users', required: true },
    deviceId: { type: String, required: true },
    userAgent: { type: String, default: '' },
    platform: { type: String, default: '' },
    lastLogin: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    ipAddress: { type: String, default: '' }
}, { collection: 'devices' });

const featureVisibilitySchema = new mongoose.Schema({
    dashboard: { type: Boolean, default: true },
    channels: { type: Boolean, default: true },
    storage: { type: Boolean, default: true },
    shopeeLink: { type: Boolean, default: true },
    'schedule-manager': { type: Boolean, default: true },
    'schedule-post': { type: Boolean, default: true },
    'schedule-reels': { type: Boolean, default: true },
    'schedule-archive': { type: Boolean, default: true },
    'schedule-groups': { type: Boolean, default: true },
    'ai-scan': { type: Boolean, default: true },
    'ai-comments': { type: Boolean, default: true },
    'comment-crawler': { type: Boolean, default: true },
    'comment-play': { type: Boolean, default: true },
    'ai-reply-messenger': { type: Boolean, default: true },
    'ai-content': { type: Boolean, default: true },
    feedback: { type: Boolean, default: true },
    profile: { type: Boolean, default: true },
    settings: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
}, { collection: 'feature_visibility' });

const feedbackSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'users', required: true },
    feature: { type: String, required: true },
    type: { type: String, enum: ['bug', 'feature', 'improvement', 'question'], default: 'bug' },
    title: { type: String, required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
    priority: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
    attachments: { type: Array, default: [] },
    adminNote: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
}, { collection: 'feedbacks' });

const feedbackMessageSchema = new mongoose.Schema({
    feedbackId: { type: mongoose.Schema.Types.ObjectId, ref: 'feedbacks', required: true },
    text: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    userName: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
}, { collection: 'feedback_messages' });

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Device = mongoose.models.Device || mongoose.model('Device', deviceSchema);
const FeatureVisibility = mongoose.models.FeatureVisibility || mongoose.model('FeatureVisibility', featureVisibilitySchema);
const Feedback = mongoose.models.Feedback || mongoose.model('Feedback', feedbackSchema);
const FeedbackMessage = mongoose.models.FeedbackMessage || mongoose.model('FeedbackMessage', feedbackMessageSchema);

// ============== DB CONNECTION ==============

let _connPromise = null;

async function connectDb() {
    if (_connPromise) return _connPromise;
    const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/reelsflow';
    _connPromise = mongoose.connect(uri);
    await _connPromise;
    console.log('[ServerAdmin DB] Connected to MongoDB');
    return mongoose.connection;
}

async function getDb() {
    await connectDb();
    return mongoose.connection;
}

// ============== USER OPERATIONS ==============

async function createUser({ username, email, password, role = 'user', phoneNumber = '' }) {
    await connectDb();
    const bcrypt = require('bcryptjs');
    const hashed = bcrypt.hashSync(password, 10);
    const user = await User.create({ username, email, password: hashed, role, phoneNumber });
    return { id: user._id.toString(), username, email, role };
}

async function findUserByEmail(email) {
    await connectDb();
    const user = await User.findOne({ email }).lean();
    if (!user) return null;
    return { ...user, id: user._id.toString() };
}

async function findUserById(id) {
    await connectDb();
    const user = await User.findById(id).select('username email phoneNumber avatarUrl role language createdAt').lean();
    if (!user) return null;
    return { ...user, id: user._id.toString() };
}

async function updateUser(id, fields) {
    await connectDb();
    const update = {};
    for (const [key, val] of Object.entries(fields)) {
        if (val !== undefined) update[key] = val;
    }
    if (Object.keys(update).length === 0) return;
    await User.findByIdAndUpdate(id, update);
}

async function updateUserPassword(id, newPassword) {
    await connectDb();
    const bcrypt = require('bcryptjs');
    const hashed = bcrypt.hashSync(newPassword, 10);
    await User.findByIdAndUpdate(id, { password: hashed });
}

async function deleteUser(id) {
    await connectDb();
    await User.findByIdAndDelete(id);
    await Device.deleteMany({ userId: id });
}

async function countUsers(roleFilter = '') {
    await connectDb();
    const filter = roleFilter ? { role: roleFilter } : {};
    return await User.countDocuments(filter);
}

async function getUsers({ page = 1, limit = 20, search = '', role = '', sortBy = 'createdAt', sortOrder = 'desc' }) {
    await connectDb();
    const filter = {};
    if (search) {
        const regex = new RegExp(search, 'i');
        filter.$or = [{ username: regex }, { email: regex }, { phoneNumber: regex }];
    }
    if (role) filter.role = role;

    const order = sortOrder === 'asc' ? 1 : -1;
    const total = await User.countDocuments(filter);
    const users = await User.find(filter)
        .select('username email phoneNumber avatarUrl role language createdAt')
        .sort({ [sortBy]: order })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean();

    return {
        users: users.map(u => ({ _id: u._id.toString(), ...u })),
        pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    };
}

async function getRegistrationChart(days = 30) {
    await connectDb();
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const data = await User.aggregate([
        { $match: { createdAt: { $gte: since } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
    ]);
    return data.map(r => ({ _id: r._id, count: r.count }));
}

async function getActiveDevicesCount() {
    await connectDb();
    return await Device.countDocuments({ isActive: true });
}

// ============== DEVICE OPERATIONS ==============

async function upsertDevice(userId, { deviceId, userAgent, platform, ipAddress }) {
    await connectDb();
    const existing = await Device.findOne({ userId, deviceId });
    if (existing) {
        await Device.findByIdAndUpdate(existing._id, {
            lastLogin: new Date(),
            userAgent: userAgent || '',
            platform: platform || '',
            ipAddress: ipAddress || ''
        });
    } else {
        await Device.create({ userId, deviceId, userAgent: userAgent || '', platform: platform || '', ipAddress: ipAddress || '' });
    }
}

async function removeDevice(userId, deviceId) {
    await connectDb();
    await Device.deleteOne({ userId, deviceId });
}

async function getUserDevices(userId) {
    await connectDb();
    return await Device.find({ userId }).select('deviceId userAgent platform lastLogin isActive ipAddress').lean();
}

// ============== FEATURE VISIBILITY ==============

async function getFeatures() {
    await connectDb();
    let row = await FeatureVisibility.findOne().sort({ createdAt: -1 }).lean();
    if (!row) {
        row = await FeatureVisibility.create({});
        row = row.toObject();
    }
    const result = {};
    for (const [key, val] of Object.entries(row)) {
        if (key === '_id' || key === '__v' || key === 'createdAt' || key === 'updatedAt') continue;
        result[key] = !!val;
    }
    return result;
}

async function updateFeatures(updates) {
    await connectDb();
    const allowed = ['dashboard', 'channels', 'storage', 'shopeeLink', 'feedback', 'profile', 'settings',
        'schedule-manager', 'schedule-post', 'schedule-reels', 'schedule-archive', 'schedule-groups',
        'ai-scan', 'ai-comments', 'comment-crawler', 'comment-play', 'ai-reply-messenger', 'ai-content'];

    let row = await FeatureVisibility.findOne().sort({ createdAt: -1 });
    if (!row) {
        row = await FeatureVisibility.create({});
    }

    const update = {};
    for (const [key, val] of Object.entries(updates)) {
        if (allowed.includes(key)) {
            update[key] = val === true || val === 'true' ? true : false;
        }
    }
    update.updatedAt = new Date();
    if (Object.keys(update).length > 0) {
        await FeatureVisibility.findByIdAndUpdate(row._id, update);
    }
    return await getFeatures();
}

// ============== FEEDBACK OPERATIONS ==============

async function createFeedback({ userId, feature, type, title, description, priority }) {
    await connectDb();
    const fb = await Feedback.create({ userId, feature, type: type || 'bug', title, description, priority: priority || 'medium' });
    return fb.toObject();
}

async function getFeedbacks({ search, status, type, priority }) {
    await connectDb();
    const filter = {};
    if (search) {
        const regex = new RegExp(search, 'i');
        filter.$or = [{ title: regex }, { description: regex }];
    }
    if (status) filter.status = status;
    if (type) filter.type = type;
    if (priority) filter.priority = priority;

    const rows = await Feedback.aggregate([
        { $match: filter },
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'user' } },
        { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
        { $addFields: { userEmail: '$user.email', userName: '$user.username' } },
        { $project: { user: 0, __v: 0 } },
        { $sort: { createdAt: -1 } }
    ]);
    return rows;
}

async function getFeedbackDetail(id) {
    await connectDb();
    const fb = await Feedback.aggregate([
        { $match: { _id: new mongoose.Types.ObjectId(id) } },
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'user' } },
        { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
        { $addFields: { userEmail: '$user.email', userName: '$user.username' } },
        { $project: { user: 0, __v: 0 } },
        { $limit: 1 }
    ]);
    if (!fb.length) return null;
    const messages = await FeedbackMessage.find({ feedbackId: id }).sort({ createdAt: 1 }).lean();
    return { ...fb[0], messages };
}

async function updateFeedback(id, updates) {
    await connectDb();
    const allowed = ['status', 'priority', 'adminNote'];
    const update = {};
    for (const [key, val] of Object.entries(updates)) {
        if (val !== undefined && allowed.includes(key)) update[key] = val;
    }
    update.updatedAt = new Date();
    if (Object.keys(update).length > 0) {
        await Feedback.findByIdAndUpdate(id, update);
    }
    return getFeedbackDetail(id);
}

async function deleteFeedback(id) {
    await connectDb();
    await Feedback.findByIdAndDelete(id);
    await FeedbackMessage.deleteMany({ feedbackId: id });
}

// ============== STATS ==============

async function getStats() {
    await connectDb();
    const totalUsers = await countUsers();
    const adminCount = await countUsers('admin');
    const userCount = await countUsers('user');

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const newUsersWeek = await User.countDocuments({ createdAt: { $gte: sevenDaysAgo } });

    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const newUsersMonth = await User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } });

    const activeDevices = await getActiveDevicesCount();
    const registrationChart = await getRegistrationChart(30);

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