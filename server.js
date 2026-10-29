const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === "production";

// Secret used to sign login tokens. Set JWT_SECRET in production.
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (IS_PROD) {
    console.error("JWT_SECRET must be set in production.");
    process.exit(1);
  }
  JWT_SECRET = crypto.randomBytes(32).toString("hex");
  console.warn("JWT_SECRET not set: using a temporary one (logins reset on restart).");
}

const app = express();
app.set("trust proxy", 1); // behind Render's proxy
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "connect-src": ["'self'"],
        "upgrade-insecure-requests": null,
      },
    },
  })
);
app.use(express.json({ limit: "10kb" }));

// ---------- Validation (mirrors the frontend rules) ----------
const NAME_RE = /^[\p{L}]+(?:[ ’'-][\p{L}]+)*$/u;
const PHONE_RE = /^(07|01)\d{8}$/;

function cleanName(v) {
  return String(v ?? "").trim().replace(/\s+/g, " ");
}
function validName(n) {
  return n.length > 0 && n.length <= 60 && NAME_RE.test(n);
}
function validPassword(p) {
  return typeof p === "string" && p.length >= 4 && p.length <= 10;
}

// ---------- Auth helpers ----------
function signToken(member) {
  return jwt.sign({ sub: member.id }, JWT_SECRET, { expiresIn: "7d" });
}
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const member = await db.findById(payload.sub);
    if (!member) return res.status(401).json({ error: "Please log in again." });
    req.member = member;
    next();
  } catch {
    res.status(401).json({ error: "Session expired. Please log in again." });
  }
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again in a few minutes." },
});

// ---------- API ----------
app.get("/api/health", (req, res) => res.json({ ok: true, database: db.kind }));

app.post("/api/signup", authLimiter, async (req, res) => {
  try {
    const name = cleanName(req.body.name);
    const phone = String(req.body.phone ?? "").trim();
    const password = req.body.password;

    if (!validName(name))
      return res.status(400).json({ error: "Enter a valid real name using letters and spaces only." });
    if (!PHONE_RE.test(phone))
      return res.status(400).json({ error: "Enter exactly 10 digits, starting with 07 or 01." });
    if (!validPassword(password))
      return res.status(400).json({ error: "Password must be between 4 and 10 characters." });

    const passwordHash = await bcrypt.hash(password, 10);
    let member;
    try {
      member = await db.createMember({ name, phone, passwordHash });
    } catch (err) {
      if (db.isUniqueViolation(err))
        return res.status(409).json({ error: "That phone number is already registered. Please log in." });
      throw err;
    }
    res.status(201).json({
      token: signToken(member),
      member: { id: member.id, name: member.name, phone: member.phone },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const phone = String(req.body.phone ?? "").trim();
    const password = req.body.password;
    if (!PHONE_RE.test(phone) || typeof password !== "string" || !password)
      return res.status(400).json({ error: "Enter your phone number and password." });

    const member = await db.findByPhone(phone);
    const ok = member && (await bcrypt.compare(password, member.password_hash));
    if (!ok) return res.status(401).json({ error: "Wrong phone number or password." });

    res.json({
      token: signToken(member),
      member: { id: member.id, name: member.name, phone: member.phone },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

// Members list: only for logged-in members. Passwords/hashes are never returned.
app.get("/api/members", requireAuth, async (req, res) => {
  try {
    const rows = await db.listMembers();
    res.json({
      me: req.member,
      count: rows.length,
      members: rows.map((m) => ({ id: m.id, name: m.name, phone: m.phone })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

// ---------- Frontend ----------
app.use(express.static(path.join(__dirname, "public")));

db.init()
  .then(() => {
    app.listen(PORT, () => console.log(`Pink Members running on port ${PORT} (${db.kind})`));
  })
  .catch((err) => {
    console.error("Database init failed:", err);
    process.exit(1);
  });
