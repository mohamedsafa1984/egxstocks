import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { run, get, all, dbInfo, isPostgres } from "./db/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// In production, don't allow the default JWT secret.
if (String(process.env.NODE_ENV || "").toLowerCase() === "production") {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "supersecretkey") {
    console.error("[SECURITY] Missing/weak JWT_SECRET. Set a strong JWT_SECRET in the environment.");
    process.exit(1);
  }
}

function isStrongPassword(pw) {
  if (!pw) return false;
  const s = String(pw);
  // Minimum viable password policy for go-live
  if (s.length < 8) return false;
  if (s.length > 128) return false;
  return true;
}

// --- Basic profanity filter (block save) ---
const BANNED_WORDS = [
  // English
  "fuck","shit","bitch","asshole","bastard","motherfucker","cunt",
  // Arabic common insults (expand later)
  "كسم","كس ام","شرموط","شرموطة","منيوك","عرص","ابن متناكة","متناك","خول","حيوان"
];
function containsBanned(text){
  if(!text) return false;
  const t = String(text).toLowerCase();
  return BANNED_WORDS.some(w => t.includes(String(w).toLowerCase()));
}

function calcProfitPct(entry_price, take_profit){
  const e = parseFloat(entry_price);
  const t = parseFloat(take_profit);
  if (!isFinite(e) || !isFinite(t) || e <= 0) return null;
  return ((t - e) / e) * 100;
}

function withComputedFields(rows){
  return (rows || []).map(r => ({
    ...r,
    profit_pct: (r && r.profit_pct != null) ? r.profit_pct : calcProfitPct(r?.entry_price, r?.take_profit)
  }));
}

// Standard blocked-user message (used across login/signup/actions)
function blockedMsg(){
  return "حسابك محظور حاليًا. لو ده بالخطأ تواصل مع إدارة الموقع.";
}



async function isRegistrationOpen(){
  try{
    const row = await get("SELECT value FROM settings WHERE key='registration_open'");
    if (!row) return true;
    return String(row.value) === "1";
  }catch{
    return true;
  }
}

async function setRegistrationOpen(open){
  const v = open ? "1" : "0";
  await run("INSERT INTO settings (key, value) VALUES ('registration_open', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [v]);
}

// Bootstrap users (change via env in production)
// NOTE: These are just defaults for local MVP testing.
const CEO_EMAIL = (process.env.CEO_EMAIL || "elbasha@elbasha.com").trim().toLowerCase();
const CEO_PASSWORD = process.env.CEO_PASSWORD || "kingoftheworld1994";
const CEO_USERNAME = (process.env.CEO_USERNAME || "elbasha").trim();

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@egx.local").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123456";
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "admin").trim();

// NOTE: DB access is abstracted in ./db so we can switch between SQLite (default) and Postgres
// without changing UI or API routes.

async function initDb() {
  // Dialect-specific schema bootstrap
  if (isPostgres) {
    await initDbPostgres();
    return;
  }
  await initDbSqlite();
}

async function initDbSqlite() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      analyst_grade TEXT,
      is_blocked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS recommendations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      analyst_confidence TEXT,
      rec_grade TEXT,
      analyst TEXT NOT NULL,
      stock TEXT NOT NULL,
      entry_price REAL,
      take_profit REAL,
      rec_date TEXT,
      entry_date TEXT,
      exit_date TEXT,
      expected_time TEXT,
      notes TEXT,
      hidden INTEGER NOT NULL DEFAULT 0,
      hidden_basic INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);

  // --- Prices table (for future automation / scoring) ---
  // Not used by the UI yet. This is just a DB foundation so we can later
  // import daily prices and auto-evaluate recommendations.
  await run(`
    CREATE TABLE IF NOT EXISTS prices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      symbol TEXT NOT NULL,
      date TEXT NOT NULL,
      open REAL,
      high REAL,
      low REAL,
      close REAL,
      volume REAL,
      source TEXT,
      created_at TEXT NOT NULL,
      UNIQUE(symbol, date)
    )
  `);


  // --- Site settings ---
  await run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);

  // Default: registration open
  const regRow = await get("SELECT value FROM settings WHERE key='registration_open'");
  if (!regRow) {
    await run("INSERT INTO settings (key, value) VALUES ('registration_open','1')");
  }
  // --- Migrations for older DB files ---
  const userCols = await all("PRAGMA table_info(users)");
  const hasRoleCol = userCols.some((c) => c.name === "role");
  if (hasRoleCol) {
    // normalize old role values (keep 'basic' as a valid role)
    await run("UPDATE users SET role='basic' WHERE role IS NULL OR role='' ");
    // migrate legacy role
    await run("UPDATE users SET role='admin_rcmd' WHERE role='admin_junior'");
  }
  const hasAnalystGrade = userCols.some((c) => c.name === "analyst_grade");
  if (!hasAnalystGrade) {
    await run("ALTER TABLE users ADD COLUMN analyst_grade TEXT");
  }

  const hasBlocked = userCols.some((c) => c.name === "is_blocked");
  if (!hasBlocked) {
    await run("ALTER TABLE users ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0");
  }

  const recCols = await all("PRAGMA table_info(recommendations)");
  const hasHidden = recCols.some((c) => c.name === "hidden");
  if (!hasHidden) {
    await run("ALTER TABLE recommendations ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0");
  }
  const hasHiddenBasic = recCols.some((c) => c.name === "hidden_basic");
  if (!hasHiddenBasic) {
    await run("ALTER TABLE recommendations ADD COLUMN hidden_basic INTEGER NOT NULL DEFAULT 0");
  }
  const hasConf = recCols.some((c) => c.name === "analyst_confidence");
  if (!hasConf) {
    await run("ALTER TABLE recommendations ADD COLUMN analyst_confidence TEXT");
  }
  const hasRecGrade = recCols.some((c) => c.name === "rec_grade");
  if (!hasRecGrade) {
    await run("ALTER TABLE recommendations ADD COLUMN rec_grade TEXT");
  }

  // Ensure CEO account exists
  const ceo = await get("SELECT id FROM users WHERE email = ?", [CEO_EMAIL]);
  if (!ceo) {
    const password_hash = await bcrypt.hash(String(CEO_PASSWORD), 10);
    await run(
      "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'ceo', ?)",
      [CEO_USERNAME, CEO_EMAIL, password_hash, new Date().toISOString()]
    );
  }

  // Ensure Admin account exists (for UI DB management)
  const admin = await get("SELECT id FROM users WHERE email = ?", [ADMIN_EMAIL]);
  if (!admin) {
    const password_hash = await bcrypt.hash(String(ADMIN_PASSWORD), 10);
    await run(
      "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
      [ADMIN_USERNAME, ADMIN_EMAIL, password_hash, new Date().toISOString()]
    );
  }
}

async function initDbPostgres() {
  // Users
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      analyst_grade TEXT,
      is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Recommendations
  await run(`
    CREATE TABLE IF NOT EXISTS recommendations (
      id SERIAL PRIMARY KEY,
      analyst_confidence TEXT,
      rec_grade TEXT,
      analyst TEXT NOT NULL,
      stock TEXT NOT NULL,
      entry_price DOUBLE PRECISION,
      take_profit DOUBLE PRECISION,
      rec_date TEXT,
      entry_date TEXT,
      exit_date TEXT,
      expected_time TEXT,
      notes TEXT,
      hidden BOOLEAN NOT NULL DEFAULT FALSE,
      hidden_basic BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Prices (future automation)
  await run(`
    CREATE TABLE IF NOT EXISTS prices (
      id SERIAL PRIMARY KEY,
      symbol TEXT NOT NULL,
      date TEXT NOT NULL,
      open DOUBLE PRECISION,
      high DOUBLE PRECISION,
      low DOUBLE PRECISION,
      close DOUBLE PRECISION,
      volume DOUBLE PRECISION,
      source TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(symbol, date)
    )
  `);

  // Settings
  await run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);

  // Default: registration open
  const regRow = await get("SELECT value FROM settings WHERE key='registration_open'");
  if (!regRow) {
    await run("INSERT INTO settings (key, value) VALUES ('registration_open','1')");
  }

  // Ensure CEO/Admin accounts exist
  // Migrate legacy role name
  await run("UPDATE users SET role='admin_rcmd' WHERE role='admin_junior'");
  const ceo = await get("SELECT id FROM users WHERE email = ?", [CEO_EMAIL]);
  if (!ceo) {
    const password_hash = await bcrypt.hash(String(CEO_PASSWORD), 10);
    await run(
      "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'ceo')",
      [CEO_USERNAME, CEO_EMAIL, password_hash]
    );
  }

  const admin = await get("SELECT id FROM users WHERE email = ?", [ADMIN_EMAIL]);
  if (!admin) {
    const password_hash = await bcrypt.hash(String(ADMIN_PASSWORD), 10);
    await run(
      "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
      [ADMIN_USERNAME, ADMIN_EMAIL, password_hash]
    );
  }
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function optionalAuth(req, _res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return next();
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch {
    // ignore
  }
  next();
}

const app = express();
// Behind a proxy (common on cloud), this ensures rate-limit uses real client IP.
app.set("trust proxy", 1);
// --- Security headers (reasonable defaults) ---
app.use(helmet({
  // TradingView widget may use iframes/scripts; keep defaults and avoid breaking UI.
  contentSecurityPolicy: false
}));

// --- CORS: allow same-origin by default; optionally allow a specific origin ---
const CORS_ORIGIN = (process.env.CORS_ORIGIN || "").trim();
app.use(cors({
  origin: (origin, cb) => {
    // no Origin header => same-origin / curl / server-to-server
    if (!origin) return cb(null, true);
    if (!CORS_ORIGIN) return cb(null, true);
    return cb(null, origin === CORS_ORIGIN);
  }
}));

// --- Rate limiting (MVP-grade) ---
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 600,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api", apiLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 25,
  standardHeaders: true,
  legacyHeaders: false,
});
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/login", authLimiter);
app.use("/api/signup", authLimiter);

app.use(express.json());

// serve static UI
app.use(express.static(path.join(__dirname, "public")));

// health
app.get("/api/health", (req, res) => res.json({ ok: true }));

// signup
app.post("/api/signup", async (req, res) => {
  try {
    const open = await isRegistrationOpen();
    if (!open) return res.status(403).json({ message: "التسجيل مغلق حالياً" });

    const { username, email, password } = req.body || {};
    if (!username || !email || !password) return res.status(400).json({ message: "Missing fields" });

    if (!isStrongPassword(password)) {
      return res.status(400).json({ message: "كلمة السر يجب ألا تقل عن 8 حروف/أرقام" });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({ message: "كلمة المرور ضعيفة: حد أدنى 8 أحرف" });
    }

    const exists = await get("SELECT id, is_blocked FROM users WHERE email = ?", [email.trim().toLowerCase()]);
    if (exists) {
      if (Number(exists.is_blocked) === 1) {
        return res.status(403).json({ message: blockedMsg(), code: "USER_BLOCKED" });
      }
      return res.status(409).json({ message: "Email already exists" });
    }

    const password_hash = await bcrypt.hash(String(password), 10);
    await run(
      "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
      [String(username).trim(), email.trim().toLowerCase(), password_hash, "user", new Date().toISOString()]
    );

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Signup failed", error: String(e.message || e) });
  }
});

// login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Missing fields" });

    const u = await get("SELECT id, username, email, password_hash, role, is_blocked FROM users WHERE email = ?", [email.trim().toLowerCase()]);
    if (!u) return res.status(401).json({ message: "Invalid email or password" });

    if (Number(u.is_blocked) === 1) {
      return res.status(403).json({ message: blockedMsg(), code: "USER_BLOCKED" });
    }

    const ok = await bcrypt.compare(String(password), u.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign({ id: u.id, email: u.email, username: u.username, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ token, user: { id: u.id, email: u.email, username: u.username, role: u.role } });
  } catch (e) {
    return res.status(500).json({ message: "Login failed", error: String(e.message || e) });
  }
});

// current user
app.get("/api/me", authRequired, async (req, res) => {
  res.json({ user: req.user });
});

// change password (requires login)
app.post("/api/change_password", authRequired, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Missing fields" });
    }
    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({ message: "كلمة السر يجب ألا تقل عن 8 حروف/أرقام" });
    }

    const u = await get("SELECT id, username, email, password_hash, role FROM users WHERE id = ?", [Number(req.user.id)]);
    if (!u) return res.status(404).json({ message: "User not found" });

    const ok = await bcrypt.compare(String(currentPassword), u.password_hash);
    if (!ok) return res.status(401).json({ message: "كلمة السر الحالية غير صحيحة" });

    const password_hash = await bcrypt.hash(String(newPassword), 10);
    await run("UPDATE users SET password_hash = ? WHERE id = ?", [password_hash, u.id]);

    // Rotate token so the client keeps working without forcing logout.
    const token = jwt.sign({ id: u.id, email: u.email, username: u.username, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ ok: true, token, user: { id: u.id, email: u.email, username: u.username, role: u.role } });
  } catch (e) {
    return res.status(500).json({ message: "Change password failed", error: String(e.message || e) });
  }
});

// public recommendations list
app.get("/api/recommendations", optionalAuth, async (req, res) => {
  try {
    // hide hidden recs from public
    // additionally: hide recommendations flagged for 'basic' users from basic/non-logged visitors
    const role = (req.user?.role || 'basic').toLowerCase();
    // SQLite stores booleans as 0/1; Postgres stores them as true/false
    const hiddenFalse = isPostgres ? "FALSE" : "0";
    const basicFilter = (role === 'basic') ? ` AND hidden_basic = ${hiddenFalse}` : "";
    const rows = await all(`SELECT * FROM recommendations WHERE hidden = ${hiddenFalse}${basicFilter} ORDER BY id DESC LIMIT 500`);
    res.json(withComputedFields(rows));
  } catch (e) {
    res.status(500).json({ message: "Fetch failed", error: String(e.message || e) });
  }
});

// Admin/CEO: hide/unhide recommendation for BASIC users only
app.put("/api/recommendations/:id/hide_basic", authRequired, requireRole("admin", "ceo"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const hidden_basic = req.body?.hidden_basic ? (isPostgres ? true : 1) : (isPostgres ? false : 0);
    await run("UPDATE recommendations SET hidden_basic = ? WHERE id = ?", [hidden_basic, id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Update failed", error: String(e.message || e) });
  }
});

function requireRole(...roles) {
  return (req, res, next) => {
    const r = req.user?.role;
    if (!r || !roles.includes(r)) return res.status(403).json({ message: "Forbidden" });
    next();
  };
}

// Roles/Permissions (8 total)
// - basic: read-only basic user
// - user: normal user (can add recommendations)
// - admin_add: can create users (basic/user only)
// - admin_del: can delete users (basic/user only)
// - admin_rcmd: can edit ONLY (analyst_confidence, rec_grade, notes) in recommendations
// - admin_block: can block/unblock users (basic/user only)
// - admin: full admin
// - ceo: full access
const VALID_ROLES = ['basic','user','admin_add','admin_del','admin_rcmd','admin_block','admin','ceo'];

// Admin/CEO: site settings
app.get("/api/admin/settings", authRequired, requireRole("admin", "ceo"), async (req, res) => {
  try {
    const open = await isRegistrationOpen();
    res.json({ registration_open: open });
  } catch (e) {
    res.status(500).json({ message: "Settings fetch failed" });
  }
});

app.put("/api/admin/settings/registration", authRequired, requireRole("admin", "ceo"), async (req, res) => {
  try {
    const { open } = req.body || {};
    await setRegistrationOpen(!!open);
    res.json({ ok: true, registration_open: !!open });
  } catch (e) {
    res.status(500).json({ message: "Settings update failed" });
  }
});


// admin/ceo: list all recs (including hidden)
app.get("/api/admin/recommendations", authRequired, requireRole("admin", "admin_rcmd", "ceo"), async (req, res) => {
  try {
    const rows = await all("SELECT * FROM recommendations ORDER BY id DESC LIMIT 1000");
    res.json(withComputedFields(rows));
  } catch (e) {
    res.status(500).json({ message: "Fetch failed", error: String(e.message || e) });
  }
});

// admin: hide/unhide recommendation
app.put("/api/recommendations/:id/hide", authRequired, requireRole("admin", "ceo"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const hidden = req.body?.hidden ? (isPostgres ? true : 1) : (isPostgres ? false : 0);
    await run("UPDATE recommendations SET hidden = ? WHERE id = ?", [hidden, id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Update failed", error: String(e.message || e) });
  }
});

// CEO: list users
app.get("/api/admin/users", authRequired, requireRole("admin", "admin_add", "admin_del", "admin_block", "ceo"), async (req, res) => {
  try {
    const users = await all("SELECT id, username, email, role, is_blocked, created_at FROM users ORDER BY id ASC");
    res.json(users);
  } catch (e) {
    res.status(500).json({ message: "Fetch failed", error: String(e.message || e) });
  }
});

// CEO: create admin user
// Create user
// - admin_add: can create ONLY basic/user
// - admin/ceo: can create any role except ceo
app.post("/api/admin/users", authRequired, requireRole("admin", "admin_add", "ceo"), async (req, res) => {
  try {
    const { username, email, password, role } = req.body || {};
    const newRole = String(role || "user").toLowerCase();
    if (!username || !email || !password) return res.status(400).json({ message: "Missing fields" });
    if (!VALID_ROLES.includes(newRole)) return res.status(400).json({ message: "Invalid role" });
    if (newRole === 'ceo') return res.status(400).json({ message: "Cannot create CEO from UI" });

    const myRole = String(req.user?.role || "").toLowerCase();
    if (myRole === "admin_add") {
      if (newRole !== "basic" && newRole !== "user") {
        return res.status(403).json({ message: "Forbidden" });
      }
    }

    const e = String(email).trim().toLowerCase();
    const exists = await get("SELECT id FROM users WHERE email = ?", [e]);
    if (exists) return res.status(409).json({ message: "Email already exists" });

    const password_hash = await bcrypt.hash(String(password), 10);
    await run(
      "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
      [String(username).trim(), e, password_hash, newRole, new Date().toISOString()]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Create failed", error: String(e.message || e) });
  }
});

// Admin/CEO: update user role/username (cannot update CEO)
// Update user role/username (admin/ceo only)
app.put("/api/admin/users/:id", authRequired, requireRole("admin", "ceo"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { username, role } = req.body || {};
    const u = await get("SELECT id, role FROM users WHERE id = ?", [id]);
    if (!u) return res.status(404).json({ message: "User not found" });
    if (u.role === 'ceo') return res.status(400).json({ message: "Cannot update CEO" });
    const newRole = role ? String(role).toLowerCase() : u.role;
    if (!VALID_ROLES.includes(newRole) || newRole === 'ceo') {
      return res.status(400).json({ message: "Invalid role" });
    }
    const newUsername = username ? String(username).trim() : null;
    if (newUsername) {
      await run("UPDATE users SET username=?, role=? WHERE id=?", [newUsername, newRole, id]);
    } else {
      await run("UPDATE users SET role=? WHERE id=?", [newRole, id]);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Update failed", error: String(e.message || e) });
  }
});

// Block/unblock user
// - admin_block: can block/unblock ONLY basic/user
// - admin/ceo: can block/unblock any non-ceo user (except self)
app.put("/api/admin/users/:id/block", authRequired, requireRole("admin", "admin_block", "ceo"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { blocked } = req.body || {};
    const meId = Number(req.user.id);

    const target = await get("SELECT id, role FROM users WHERE id = ?", [id]);
    if (!target) return res.status(404).json({ message: "User not found" });
    if (target.role === "ceo") return res.status(403).json({ message: "لا يمكن حظر CEO" });
    if (id === meId) return res.status(403).json({ message: "لا يمكن حظر نفسك" });

    const myRole = String(req.user?.role || "").toLowerCase();
    if (myRole === "admin_block") {
      if (target.role !== "basic" && target.role !== "user") {
        return res.status(403).json({ message: "Forbidden" });
      }
    }

    const v = blocked ? (isPostgres ? true : 1) : (isPostgres ? false : 0);
    await run("UPDATE users SET is_blocked = ? WHERE id = ?", [v, id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Block update failed" });
  }
});

// Admin/CEO: delete user (cannot delete self / cannot delete CEO)
// Delete user
// - admin_del: can delete ONLY basic/user
// - admin/ceo: can delete any non-ceo user (except self)
app.delete("/api/admin/users/:id", authRequired, requireRole("admin", "admin_del", "ceo"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (id === Number(req.user?.id)) return res.status(400).json({ message: "Cannot delete yourself" });
    const u = await get("SELECT id, role FROM users WHERE id = ?", [id]);
    if (!u) return res.status(404).json({ message: "User not found" });
    if (u.role === 'ceo') return res.status(400).json({ message: "Cannot delete CEO" });

    const myRole = String(req.user?.role || "").toLowerCase();
    if (myRole === "admin_del") {
      if (u.role !== "basic" && u.role !== "user") {
        return res.status(403).json({ message: "Forbidden" });
      }
    }
    await run("DELETE FROM users WHERE id = ?", [id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Delete failed", error: String(e.message || e) });
  }
});

// Admin/CEO: update recommendation
// Update recommendation
// - admin_rcmd: can update ONLY analyst_confidence, rec_grade, notes
// - admin/ceo: full edit
app.put("/api/admin/recommendations/:id", authRequired, requireRole("admin", "admin_rcmd", "ceo"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const {
      analyst, stock, entry_price, take_profit, expected_time,
      notes, hidden, hidden_basic,
      rec_date, entry_date, exit_date,
      analyst_confidence, rec_grade
    } = req.body || {};
    const r = await get("SELECT id FROM recommendations WHERE id=?", [id]);
    if (!r) return res.status(404).json({ message: "Recommendation not found" });

    if (containsBanned(notes)) {
      return res.status(400).json({ message: "ممنوع استخدام ألفاظ أو شتائم في الملاحظات." });
    }

    const myRole = String(req.user?.role || "").toLowerCase();
    const isRcmdOnly = myRole === "admin_rcmd";

    // admin_rcmd is limited to confidence/grade/notes only
    const newAnalyst = (!isRcmdOnly && analyst !== undefined) ? String(analyst).trim() : null;
    const newStock = (!isRcmdOnly && stock !== undefined) ? String(stock).trim().toUpperCase() : null;
    const newEntry = (!isRcmdOnly && entry_price !== undefined && entry_price !== "") ? Number(entry_price) : null;
    const newTarget = (!isRcmdOnly && take_profit !== undefined && take_profit !== "") ? Number(take_profit) : null;
    const newTime = (!isRcmdOnly && expected_time !== undefined) ? String(expected_time) : null;
    const newNotes = (notes !== undefined) ? String(notes) : null;
    const newHidden = (!isRcmdOnly && hidden !== undefined) ? (hidden ? (isPostgres ? true : 1) : (isPostgres ? false : 0)) : null;
    const newHiddenBasic = (!isRcmdOnly && hidden_basic !== undefined) ? (hidden_basic ? (isPostgres ? true : 1) : (isPostgres ? false : 0)) : null;

    const newRecDate = (!isRcmdOnly && rec_date !== undefined) ? (rec_date ? String(rec_date) : null) : undefined;
    const newEntryDate = (!isRcmdOnly && entry_date !== undefined) ? (entry_date ? String(entry_date) : null) : undefined;
    const newExitDate = (!isRcmdOnly && exit_date !== undefined) ? (exit_date ? String(exit_date) : null) : undefined;

    const newConf = analyst_confidence !== undefined ? String(analyst_confidence || "").trim() : undefined;
    const newRecGrade = rec_grade !== undefined ? String(rec_grade || "").trim() : undefined;

    const sets = [];
    const params = [];
    if (newAnalyst !== null) { sets.push("analyst=?"); params.push(newAnalyst); }
    if (newStock !== null) { sets.push("stock=?"); params.push(newStock); }
    if (!isRcmdOnly && entry_price !== undefined) { sets.push("entry_price=?"); params.push(newEntry); }
    if (!isRcmdOnly && take_profit !== undefined) { sets.push("take_profit=?"); params.push(newTarget); }
    if (newTime !== null) { sets.push("expected_time=?"); params.push(newTime); }
    if (newNotes !== null) { sets.push("notes=?"); params.push(newNotes); }
    if (newHidden !== null) { sets.push("hidden=?"); params.push(newHidden); }
    if (newHiddenBasic !== null) { sets.push("hidden_basic=?"); params.push(newHiddenBasic); }

    if (newRecDate !== undefined) { sets.push("rec_date=?"); params.push(newRecDate); }
    if (newEntryDate !== undefined) { sets.push("entry_date=?"); params.push(newEntryDate); }
    if (newExitDate !== undefined) { sets.push("exit_date=?"); params.push(newExitDate); }

    if (newConf !== undefined) { sets.push("analyst_confidence=?"); params.push(newConf); }
    if (newRecGrade !== undefined) { sets.push("rec_grade=?"); params.push(newRecGrade); }

    if (!sets.length) return res.status(400).json({ message: "Nothing to update" });
    params.push(id);
    await run(`UPDATE recommendations SET ${sets.join(", ")} WHERE id=?`, params);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Update failed", error: String(e.message || e) });
  }
});

// Admin/CEO: delete recommendation
app.delete("/api/admin/recommendations/:id", authRequired, requireRole("admin", "ceo"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    await run("DELETE FROM recommendations WHERE id=?", [id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Delete failed", error: String(e.message || e) });
  }
});

// add recommendation (requires login)
app.post("/api/recommendations", authRequired, async (req, res) => {
  try {
    const me = await get("SELECT is_blocked FROM users WHERE id = ?", [Number(req.user.id)]);
    if (me && Number(me.is_blocked) === 1) return res.status(403).json({ message: blockedMsg(), code: "USER_BLOCKED" });

    const { stock, entry_price, take_profit, expected_time, notes, rec_date, entry_date, exit_date } = req.body || {};
    if (!stock) return res.status(400).json({ message: "Stock is required" });

    // Daily rate limit: max 10 recommendations/day per non-admin user.
    // Admin/CEO can post unlimited.
    const role = (req.user?.role || "user").toLowerCase();
    if (role !== "admin" && role !== "ceo") {
      const analystKey = req.user?.username || "";
      // Portable "today" range (works for both SQLite TEXT timestamps and Postgres TIMESTAMPTZ)
      const start = new Date();
      start.setHours(0, 0, 0, 0);
      const end = new Date(start);
      end.setDate(end.getDate() + 1);
      const row = await get(
        `SELECT COUNT(*) AS total
         FROM recommendations
         WHERE analyst = ?
           AND created_at >= ?
           AND created_at < ?`,
        [analystKey, start.toISOString(), end.toISOString()]
      );
      const total = Number(row?.total || 0);
      if (total >= 10) {
        return res.status(429).json({ message: "الحد الأقصى اليومي للتوصيات هو 10" });
      }
    }

    if (containsBanned(notes)) {
      return res.status(400).json({ message: "ممنوع استخدام ألفاظ أو شتائم في الملاحظات." });
    }

    const analyst = req.user?.username || "analyst";
    await run(
      `INSERT INTO recommendations (
         analyst, stock, entry_price, take_profit,
         rec_date, entry_date, exit_date,
         expected_time, notes, created_at
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        analyst,
        String(stock).trim().toUpperCase(),
        entry_price !== undefined && entry_price !== "" ? Number(entry_price) : null,
        take_profit !== undefined && take_profit !== "" ? Number(take_profit) : null,
        rec_date ? String(rec_date) : null,
        entry_date ? String(entry_date) : null,
        exit_date ? String(exit_date) : null,
        expected_time ? String(expected_time) : null,
        notes ? String(notes) : null,
        new Date().toISOString()
      ]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Insert failed", error: String(e.message || e) });
  }
});

// fallback to index.html for root
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
      console.log(`DB: ${JSON.stringify(dbInfo())}`);
    });
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });
