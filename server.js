// =====================================================================
//  ACCESS SERVER  -  logins for the Bet Sync Browser
//  No dependencies: only Node's built-in modules.   Run:  node server.js
//
//  - POST /login                         {username, password}  -> {token, ...}
//  - GET  /session                       (Bearer token)        -> still valid?
//  - POST /logout
//  - GET    /admin/users                 (admin)  list accounts
//  - POST   /admin/users                 (admin)  {username, password, role}  create
//  - POST   /admin/users/:name/disable   (admin)  revoke access (kicks them out)
//  - POST   /admin/users/:name/enable    (admin)  restore access
//  - POST   /admin/users/:name/password  (admin)  {password}  reset (kicks them out)
//  - DELETE /admin/users/:name           (admin)  delete account
//
//  Settings (environment variables, all optional):
//    PORT (3000)  DATA_DIR (./data)  TOKEN_TTL_HOURS (12)  SINGLE_SESSION (true)
//    ADMIN_USER (admin)  ADMIN_PASS (random, printed once on first start)  SECRET
//    UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN  -> keep the accounts in a free Upstash Redis
//      database instead of a file (needed on hosts whose disk is wiped on restart, e.g. Render free)
// =====================================================================
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TOKEN_TTL_MS = parseFloat(process.env.TOKEN_TTL_HOURS || '12') * 3600 * 1000;
const SINGLE_SESSION = (process.env.SINGLE_SESSION || 'true').toLowerCase() !== 'false';
const ONLINE_WINDOW_MS = 2 * 60 * 1000;
const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');

// ---------- where the accounts are kept ----------
//  - default: users.json in DATA_DIR (needs a disk that survives restarts)
//  - or a free Upstash Redis database over HTTPS (set the two UPSTASH_* variables)
const REMOTE_URL = process.env.UPSTASH_REDIS_REST_URL;
const REMOTE_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const REMOTE_KEY = process.env.STORE_KEY || 'betsync:accounts';
const useRemote = !!(REMOTE_URL && REMOTE_TOKEN);

async function redis(command) {
    const res = await fetch(REMOTE_URL, {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + REMOTE_TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify(command)
    });
    let data = {};
    try { data = await res.json(); } catch (e) {}
    if (!res.ok || data.error) throw new Error(data.error || ('HTTP ' + res.status));
    return data.result;
}

let db = { users: [] };
let SECRET = process.env.SECRET || null;
let writeChain = Promise.resolve();
let secretIsNew = false;

async function loadDb() {
    if (useRemote) {
        const raw = await redis(['GET', REMOTE_KEY]);      // if this fails we stop: never start empty and overwrite real accounts
        if (raw) db = JSON.parse(raw);
    } else if (fs.existsSync(USERS_FILE)) {
        db = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    }
    if (!Array.isArray(db.users)) db.users = [];
    if (!SECRET) {
        if (useRemote) { if (!db.secret) { db.secret = crypto.randomBytes(32).toString('hex'); secretIsNew = true; } SECRET = db.secret; }
        else if (fs.existsSync(SECRET_FILE)) SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
        else { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SECRET_FILE, SECRET, { mode: 0o600 }); }
    }
}

// always call as:  await save();
function save() {
    if (!useRemote) {
        const tmp = USERS_FILE + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
        fs.renameSync(tmp, USERS_FILE);
        return Promise.resolve();
    }
    const snapshot = JSON.stringify(db);
    const p = writeChain.catch(() => {}).then(() => redis(['SET', REMOTE_KEY, snapshot]));   // writes go out one at a time, in order
    writeChain = p;
    return p.catch(err => {
        console.error('[store] could not save to the database: ' + err.message);
        const e = new Error('Could not save to the database. Try again.'); e.status = 503; throw e;
    });
}
const findUser = (name) => db.users.find(u => u.username.toLowerCase() === String(name || '').toLowerCase());
const lastSeen = new Map();   // username(lower) -> timestamp (memory only)

// ---------- passwords & tokens ----------
function hashPassword(password, salt) {
    salt = salt || crypto.randomBytes(16).toString('hex');
    return { salt: salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function checkPassword(password, user) {
    const a = crypto.scryptSync(password, user.salt, 64);
    const b = Buffer.from(user.hash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const b64u = (s) => Buffer.from(s).toString('base64url');
function signToken(payload) {
    const body = b64u(JSON.stringify(payload));
    return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
}
function readToken(token) {
    if (typeof token !== 'string' || !token.includes('.')) return null;
    const [body, sig] = token.split('.');
    const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    const A = Buffer.from(sig), B = Buffer.from(good);
    if (A.length !== B.length || !crypto.timingSafeEqual(A, B)) return null;
    try { return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch (e) { return null; }
}

// ---------- helpers ----------
const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Cache-Control': 'no-store'
};
function send(res, status, obj) {
    res.writeHead(status, Object.assign({ 'Content-Type': 'application/json' }, CORS));
    res.end(JSON.stringify(obj));
}
function readBody(req) {
    return new Promise((resolve, reject) => {
        let size = 0, chunks = [];
        req.on('data', c => { size += c.length; if (size > 10000) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
        req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(new Error('bad json')); } });
        req.on('error', reject);
    });
}
const clientIp = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const validName = (n) => typeof n === 'string' && /^[A-Za-z0-9._-]{3,32}$/.test(n);
const validPass = (p) => typeof p === 'string' && p.length >= 8 && p.length <= 100;

// login brute-force protection
const attempts = new Map();
function lockedFor(key) { const a = attempts.get(key); return a && a.lockedUntil > Date.now() ? Math.ceil((a.lockedUntil - Date.now()) / 60000) : 0; }
function noteFail(key) {
    const a = attempts.get(key) || { count: 0, first: Date.now(), lockedUntil: 0 };
    if (Date.now() - a.first > LOCK_MS) { a.count = 0; a.first = Date.now(); }
    a.count++;
    if (a.count >= MAX_FAILS) { a.lockedUntil = Date.now() + LOCK_MS; a.count = 0; }
    attempts.set(key, a);
}

// check the bearer token AND the live account state (this is what makes revoking work)
function authenticate(req) {
    const h = req.headers.authorization || '';
    const p = readToken(h.startsWith('Bearer ') ? h.slice(7) : '');
    if (!p) return { status: 401, code: 'invalid', error: 'Please sign in again.' };
    if (p.exp < Date.now()) return { status: 401, code: 'expired', error: 'Your session expired. Please sign in again.' };
    const user = findUser(p.u);
    if (!user || user.disabled) return { status: 401, code: 'revoked', error: 'Your access has been revoked by the administrator.' };
    if (SINGLE_SESSION && user.sid !== p.sid) return { status: 401, code: 'signed_in_elsewhere', error: 'This account was signed in somewhere else.' };
    lastSeen.set(user.username.toLowerCase(), Date.now());
    return { user: user };
}
const publicUser = (u) => ({
    username: u.username, role: u.role, disabled: !!u.disabled, createdAt: u.createdAt, lastLogin: u.lastLogin,
    online: (lastSeen.get(u.username.toLowerCase()) || 0) > Date.now() - ONLINE_WINDOW_MS && !u.disabled
});
const activeAdmins = (except) => db.users.filter(u => u.role === 'admin' && !u.disabled && (!except || u !== except)).length;

// ---------- routes ----------
async function handle(req, res) {
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
    const url = new URL(req.url, 'http://x');
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);

    if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, { ok: true });

    if (req.method === 'POST' && url.pathname === '/login') {
        const b = await readBody(req);
        const key = clientIp(req) + '|' + String(b.username || '').toLowerCase();
        const wait = lockedFor(key);
        if (wait) return send(res, 429, { code: 'locked', error: 'Too many wrong attempts. Try again in ' + wait + ' minute(s).' });

        const user = findUser(b.username);
        if (!user || typeof b.password !== 'string' || !checkPassword(b.password, user)) {
            noteFail(key);
            console.log('[login] failed for "' + String(b.username).slice(0, 40) + '" from ' + clientIp(req));
            return send(res, 401, { code: 'bad_login', error: 'Wrong username or password.' });
        }
        if (user.disabled) return send(res, 403, { code: 'revoked', error: 'This access has been revoked by the administrator.' });

        attempts.delete(key);
        user.sid = crypto.randomBytes(12).toString('hex');   // a new login replaces any older session
        user.lastLogin = Date.now();
        await save();
        lastSeen.set(user.username.toLowerCase(), Date.now());
        console.log('[login] ' + user.username + ' signed in from ' + clientIp(req));
        const exp = Date.now() + TOKEN_TTL_MS;
        return send(res, 200, { token: signToken({ u: user.username, r: user.role, sid: user.sid, exp: exp }), username: user.username, role: user.role, expiresAt: exp });
    }

    const auth = authenticate(req);
    if (auth.error) return send(res, auth.status, { code: auth.code, error: auth.error });
    const me = auth.user;

    if (req.method === 'GET' && url.pathname === '/session') return send(res, 200, { username: me.username, role: me.role });
    if (req.method === 'POST' && url.pathname === '/logout') { me.sid = null; await save(); lastSeen.delete(me.username.toLowerCase()); return send(res, 200, { done: true }); }

    // ---- everything below is admin only ----
    if (parts[0] !== 'admin' || parts[1] !== 'users') return send(res, 404, { error: 'Not found' });
    if (me.role !== 'admin') return send(res, 403, { code: 'forbidden', error: 'Admins only.' });

    if (req.method === 'GET' && parts.length === 2) return send(res, 200, { users: db.users.map(publicUser) });

    if (req.method === 'POST' && parts.length === 2) {
        const b = await readBody(req);
        if (!validName(b.username)) return send(res, 400, { error: 'Username: 3-32 characters, letters, numbers, dot, dash or underscore.' });
        if (!validPass(b.password)) return send(res, 400, { error: 'Password must be at least 8 characters.' });
        if (findUser(b.username)) return send(res, 409, { error: 'That username already exists.' });
        const role = b.role === 'admin' ? 'admin' : 'user';
        db.users.push(Object.assign({ username: b.username, role: role, disabled: false, createdAt: Date.now(), lastLogin: null, sid: null }, hashPassword(b.password)));
        await save();
        console.log('[admin] ' + me.username + ' created ' + role + ' "' + b.username + '"');
        return send(res, 201, { created: b.username });
    }

    const target = findUser(parts[2]);
    if (!target) return send(res, 404, { error: 'No such user.' });
    const action = parts[3];

    if (req.method === 'DELETE' && parts.length === 3) {
        if (target === me) return send(res, 400, { error: 'You cannot delete your own account.' });
        if (target.role === 'admin' && !target.disabled && activeAdmins(target) < 1) return send(res, 400, { error: 'There must be at least one active admin.' });
        db.users = db.users.filter(u => u !== target); await save();
        console.log('[admin] ' + me.username + ' deleted "' + target.username + '"');
        return send(res, 200, { deleted: target.username });
    }
    if (req.method === 'POST' && action === 'disable') {
        if (target === me) return send(res, 400, { error: 'You cannot disable your own account.' });
        if (target.role === 'admin' && activeAdmins(target) < 1) return send(res, 400, { error: 'There must be at least one active admin.' });
        target.disabled = true; target.sid = null; await save();
        console.log('[admin] ' + me.username + ' REVOKED "' + target.username + '"');
        return send(res, 200, { disabled: target.username });
    }
    if (req.method === 'POST' && action === 'enable') {
        target.disabled = false; await save();
        console.log('[admin] ' + me.username + ' re-enabled "' + target.username + '"');
        return send(res, 200, { enabled: target.username });
    }
    if (req.method === 'POST' && action === 'password') {
        const b = await readBody(req);
        if (!validPass(b.password)) return send(res, 400, { error: 'Password must be at least 8 characters.' });
        Object.assign(target, hashPassword(b.password)); target.sid = null; await save();
        console.log('[admin] ' + me.username + ' reset the password of "' + target.username + '"');
        return send(res, 200, { reset: target.username });
    }
    return send(res, 404, { error: 'Not found' });
}

async function init() {
    await loadDb();

    if (!db.users.length) {
        const name = process.env.ADMIN_USER || 'admin';
        const pass = process.env.ADMIN_PASS || crypto.randomBytes(9).toString('base64url');
        db.users.push(Object.assign({ username: name, role: 'admin', disabled: false, createdAt: Date.now(), lastLogin: null, sid: null }, hashPassword(pass)));
        await save();
        console.log('\n==============================================');
        console.log(' FIRST START: admin account created');
        console.log('   username: ' + name);
        console.log('   password: ' + pass + (process.env.ADMIN_PASS ? '   (from ADMIN_PASS)' : '   (write it down, it is not shown again)'));
        console.log('==============================================\n');
    } else if (secretIsNew) {
        await save();    // store the freshly generated signing secret
    }

    http.createServer((req, res) => {
        handle(req, res).catch(err => {
            if (!res.headersSent) send(res, err.status || 400, { error: String(err.message || err) });
        });
    }).listen(PORT, () => console.log('Access server listening on port ' + PORT + '  (accounts kept in: ' + (useRemote ? 'Upstash Redis' : USERS_FILE) + ')'));
}

init().catch(err => { console.error('START-UP FAILED: ' + err.message); process.exit(1); });
