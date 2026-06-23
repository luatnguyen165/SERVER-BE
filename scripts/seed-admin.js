const db = require('../db');

const email = 'nluat134@gmail.com';
const existing = db.findUserByEmail(email);

if (existing) {
    db.updateUser(existing.id, { role: 'admin', username: 'nluat134' });
    db.updateUserPassword(existing.id, 'anhluat165');
    console.log('✅ Updated existing user to admin');
} else {
    db.createUser({ username: 'nluat134', email, password: 'anhluat165', role: 'admin' });
    console.log('✅ Admin account created successfully');
}

console.log('   Email: nluat134@gmail.com');
console.log('   Password: anhluat165');
console.log('   Role: admin');