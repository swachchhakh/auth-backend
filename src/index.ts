import "dotenv/config";
import crypto from "crypto";
import express, { NextFunction, Request, Response } from "express";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Pool } from "pg";
import { z } from "zod";

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
const isProd = process.env.NODE_ENV === "production";
const SESSION_DAYS = 7;

app.set("trust proxy", 1); // Render sits behind a proxy
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

const hash = (t: string) => crypto.createHash("sha256").update(t).digest("hex");

const credentials = z.object({
  email: z.string().email().max(254),
  password: z.string().min(10).max(200),
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });

// ---------- KAN-22: health ----------
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// ---------- KAN-30: register / login / logout ----------
app.post("/auth/register", authLimiter, async (req, res) => {
  const { email, password } = credentials.parse(req.body);
  const password_hash = await bcrypt.hash(password, 12);
  await db.query("insert into users(email, password_hash) values($1, $2)", [
    email.toLowerCase(),
    password_hash,
  ]);
  res.status(201).json({ ok: true });
});

app.post("/auth/login", authLimiter, async (req, res) => {
  const { email, password } = credentials.parse(req.body);
  const { rows } = await db.query("select * from users where email = $1", [email.toLowerCase()]);
  const user = rows[0];
  // same error for wrong email or wrong password
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  await db.query("delete from sessions where expires_at < now()"); // cleanup
  const token = crypto.randomBytes(32).toString("hex");
  await db.query(
    `insert into sessions(token_hash, user_id, expires_at)
     values($1, $2, now() + ($3 || ' days')::interval)`,
    [hash(token), user.id, String(SESSION_DAYS)]
  );
  res.cookie("sid", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
  });
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
    `select u.id, u.email, u.role
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
