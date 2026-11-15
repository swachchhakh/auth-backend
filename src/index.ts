import "dotenv/config";
import crypto from "crypto";
import express, { NextFunction, Request, Response } from "express";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { Pool } from "pg";
import { z } from "zod";
import { OAuth2Client } from "google-auth-library"; // NEW: verifies Google ID tokens

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
const isProd = process.env.NODE_ENV === "production";
const SESSION_DAYS = 7;
// Comma-separated list of allowed frontend origins, e.g. "http://localhost:5173,https://myapp.vercel.app"
const allowedOrigins = (process.env.CORS_ORIGIN ?? "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

// NEW: Google Client ID (public value, NOT the client secret)
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// NEW: without a client ID, Google tokens would not be checked against this app
if (!process.env.GOOGLE_CLIENT_ID) throw new Error("GOOGLE_CLIENT_ID is not set");

app.set("trust proxy", 1); // Render sits behind a proxy
app.use(helmet());
if (allowedOrigins.length) {
  // CORS_ORIGIN=* means "allow any website" (reflects the caller's origin).
  // Convenient for demos, but any site can then use a logged-in user's cookie.
  const allowAny = allowedOrigins.includes("*");
  app.use(cors({ origin: allowAny ? true : allowedOrigins, credentials: true }));
}
app.use(express.json());
app.use(cookieParser());

const hash = (t: string) => crypto.createHash("sha256").update(t).digest("hex");

const credentials = z.object({
  email: z.string().email().max(254),
  password: z.string().min(10).max(200),
});

// NEW: register also accepts an optional display name
const registerBody = credentials.extend({
  name: z.string().trim().min(2).max(100).optional(),
});

// NEW: body for Google sign-in
const googleBody = z.object({
  credential: z.string().min(20).max(4000),
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });

// NEW: shared by /auth/login and /auth/google so both create the same kind of session
async function startSession(res: Response, userId: string | number) {
  await db.query("delete from sessions where expires_at < now()"); // cleanup
  const token = crypto.randomBytes(32).toString("hex");
  await db.query(
    `insert into sessions(token_hash, user_id, expires_at)
     values($1, $2, now() + ($3 || ' days')::interval)`,
    [hash(token), userId, String(SESSION_DAYS)]
  );
  res.cookie("sid", token, {
    httpOnly: true,
    secure: isProd,
    // a frontend on another site (e.g. localhost -> onrender.com) needs "none"
    sameSite: isProd && allowedOrigins.length ? "none" : "lax",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
  });
}

// ---------- KAN-22: health ----------
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// ---------- KAN-30: register / login / logout ----------
app.post("/auth/register", authLimiter, async (req, res) => {
  const { email, password, name } = registerBody.parse(req.body);
  const password_hash = await bcrypt.hash(password, 12);
  await db.query("insert into users(email, password_hash, name) values($1, $2, $3)", [
    email.toLowerCase(),
    password_hash,
    name ?? null,
  ]);
  res.status(201).json({ ok: true });
});

app.post("/auth/login", authLimiter, async (req, res) => {
  const { email, password } = credentials.parse(req.body);
  const { rows } = await db.query("select * from users where email = $1", [email.toLowerCase()]);
  const user = rows[0];
  // same error for wrong email or wrong password
  // CHANGED: Google-only accounts have no password_hash, so they cannot log in with a password
  if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  await startSession(res, user.id);
  res.json({ ok: true });
});

// ---------- NEW: Sign in / register with Google ----------
app.post("/auth/google", authLimiter, async (req, res) => {
  const { credential } = googleBody.parse(req.body);

  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } catch {
    return res.status(401).json({ error: "Invalid Google token" });
  }
  if (!payload?.sub || !payload.email || !payload.email_verified) {
    return res.status(401).json({ error: "Google account email is not verified" });
  }

  const email = payload.email.toLowerCase();
  const name = payload.name ?? null;
  const picture = payload.picture ?? null;

  // 1) returning Google user  2) existing email account -> link  3) brand new -> register
  let { rows } = await db.query("select * from users where google_id = $1", [payload.sub]);
  let user = rows[0];
  if (!user) {
    ({ rows } = await db.query("select * from users where email = $1", [email]));
    user = rows[0];
    if (user) {
      await db.query(
        `update users set google_id = $1, name = coalesce(name, $2), picture = coalesce(picture, $3)
          where id = $4`,
        [payload.sub, name, picture, user.id]
      );
    } else {
      const created = await db.query(
        `insert into users(email, google_id, name, picture) values($1, $2, $3, $4) returning *`,
        [email, payload.sub, name, picture]
      );
      user = created.rows[0];
    }
  }

  await startSession(res, user.id);
  res.json({ ok: true });
});

app.post("/auth/logout", async (req, res) => {
  if (req.cookies?.sid) {
    await db.query("delete from sessions where token_hash = $1", [hash(req.cookies.sid)]);
  }
  res.clearCookie("sid").json({ ok: true });
});

// ---------- KAN-39: auth + admin middleware ----------
async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const { rows } = await db.query(
    `select u.id, u.email, u.role, u.name, u.picture
       from sessions s join users u on u.id = s.user_id
      where s.token_hash = $1 and s.expires_at > now()`,
    [hash(req.cookies?.sid ?? "")]
  );
  if (!rows[0]) return res.status(401).json({ error: "Not authenticated" });
  res.locals.user = rows[0];
  next();
}

function requireAdmin(_req: Request, res: Response, next: NextFunction) {
  if (res.locals.user?.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  next();
}

app.get("/auth/me", requireAuth, (_req, res) => {
  res.json(res.locals.user);
});

app.get("/admin/users", requireAuth, requireAdmin, async (_req, res) => {
  const { rows } = await db.query(
    "select id, email, role, created_at from users order by id"
  );
  res.json(rows);
});

// ---------- error handler ----------
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  if (err?.name === "ZodError") {
    return res.status(400).json({ error: "Invalid input", details: err.issues });
  }
  if (err?.code === "23505") {
    return res.status(409).json({ error: "Email already registered" });
  }
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));