# Auth Backend

Registration, login, logout and admin-only routes. Node + TypeScript + Express, Neon Postgres, hosted on Render.

**Live base URL:** `https://auth-backend-lb6o.onrender.com`
**Local base URL:** `http://localhost:3000`

> The free Render service sleeps after ~15 minutes idle. The first request after that can take about a minute. This is normal.

## How authentication works

- `POST /auth/login` sets a cookie named `sid`. It is `HttpOnly`, so JavaScript cannot read it and you never handle a token yourself.
- The browser or client sends the cookie back automatically on later requests.
- A session lasts 7 days. `POST /auth/logout` deletes it immediately.
- In a browser, every `fetch` must include `credentials: "include"`, or the cookie is not sent.
- In curl, save the cookie with `-c jar.txt` and send it with `-b jar.txt`.

## Endpoints

| Method | Path | Auth | Success |
|---|---|---|---|
| GET | `/health` | none | 200 |
| POST | `/auth/register` | none | 201 |
| POST | `/auth/login` | none | 200 + cookie |
| POST | `/auth/logout` | cookie (optional) | 200 |
| GET | `/auth/me` | cookie | 200 |
| GET | `/admin/users` | cookie + admin role | 200 |

Passwords must be 10-200 characters. Emails are stored in lowercase.

---

## Using the API from the terminal (curl)

```bash
BASE=https://auth-backend-lb6o.onrender.com
```

**Health**
```bash
curl $BASE/health
```
```json
{ "ok": true }
```

**Register**
```bash
curl -X POST $BASE/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"a-long-password-123"}'
```
`201 Created`
```json
{ "ok": true }
```

**Login** (`-c` saves the cookie)
```bash
curl -c jar.txt -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"a-long-password-123"}'
```
`200 OK`
```json
{ "ok": true }
```
Response header (this is the session):
```
Set-Cookie: sid=<random token>; Max-Age=604800; Path=/; HttpOnly; Secure; SameSite=Lax
```

**Current user** (`-b` sends the cookie)
```bash
curl -b jar.txt $BASE/auth/me
```
`200 OK`
```json
{ "id": 1, "email": "user@example.com", "role": "user" }
```

**Admin: list users**
```bash
curl -b jar.txt $BASE/admin/users
```
`200 OK` (admin only)
```json
[
  { "id": 1, "email": "admin@example.com", "role": "admin", "created_at": "2026-11-03T10:15:00.000Z" },
  { "id": 2, "email": "user@example.com", "role": "user", "created_at": "2026-11-03T10:22:00.000Z" }
]
```

**Logout**
```bash
curl -b jar.txt -c jar.txt -X POST $BASE/auth/logout
```
`200 OK`
```json
{ "ok": true }
```

---

## Using the API from React

### 1. Configure CORS on the server

A React app on a different origin (for example `http://localhost:5173`) is blocked by the browser unless the server allows it.

Set this environment variable on the backend (Render: **Environment** tab, then **Save Changes**; locally: `.env`):

```
CORS_ORIGIN=http://localhost:5173
```

Use a comma-separated list for several origins, for example `http://localhost:5173,https://your-app.vercel.app`.

To allow **any** website, set `CORS_ORIGIN=*`. The server then echoes back whichever origin calls it. This is fine for demos, but any website can then use a logged-in user's cookie to call the API, so use an explicit list for anything real.

When `CORS_ORIGIN` is set in production, the cookie is sent with `SameSite=None; Secure` so it works across sites.

### 2. API helper (`src/api.js`)

```js
const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:3000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    credentials: "include", // required so the cookie is sent and stored
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error ?? "Request failed");
    err.status = res.status;
    err.details = data.details;
    throw err;
  }
  return data;
}

export const api = {
  register: (email, password) =>
    request("/auth/register", { method: "POST", body: JSON.stringify({ email, password }) }),
  login: (email, password) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => request("/auth/logout", { method: "POST" }),
  me: () => request("/auth/me"),
  adminUsers: () => request("/admin/users"),
};
```

Add this to your React project's `.env`:
```
VITE_API_URL=https://auth-backend-lb6o.onrender.com
```

### 3. Example login component

```jsx
import { useState } from "react";
import { api } from "./api";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [user, setUser] = useState(null);
  const [error, setError] = useState("");

  async function handleLogin(e) {
    e.preventDefault();
    setError("");
    try {
      await api.login(email, password);
      setUser(await api.me()); // { id, email, role }
    } catch (err) {
      setError(err.message); // "Invalid credentials", "Invalid input", ...
    }
  }

  async function handleLogout() {
    await api.logout();
    setUser(null);
  }

  if (user) {
    return (
      <div>
        <p>Signed in as {user.email} ({user.role})</p>
        <button onClick={handleLogout}>Log out</button>
      </div>
    );
  }

  return (
    <form onSubmit={handleLogin}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" />
      <button type="submit">Log in</button>
      {error && <p style={{ color: "red" }}>{error}</p>}
    </form>
  );
}
```

### Restoring the session on page load

The cookie survives a refresh, so call `api.me()` when the app starts:

```js
useEffect(() => {
  api.me().then(setUser).catch(() => setUser(null));
}, []);
```

A `401` here just means nobody is logged in.

---

## Error responses

All errors are JSON, except rate-limit errors (`429`), which return plain text.

| Status | When | Body |
|---|---|---|
| 400 | Invalid email, or password shorter than 10 characters | `{ "error": "Invalid input", "details": [ ... ] }` |
| 401 | Wrong email or password on login | `{ "error": "Invalid credentials" }` |
| 401 | No cookie, expired session, or logged out | `{ "error": "Not authenticated" }` |
| 403 | Logged in but not an admin | `{ "error": "Forbidden" }` |
| 409 | Email already registered | `{ "error": "Email already registered" }` |
| 429 | More than 10 register/login attempts in 15 minutes from one IP | `Too many requests, please try again later.` |
| 500 | Unexpected server error | `{ "error": "Server error" }` |

Example `400` body:
```json
{
  "error": "Invalid input",
  "details": [
    { "code": "too_small", "minimum": 10, "type": "string", "inclusive": true, "message": "String must contain at least 10 character(s)", "path": ["password"] }
  ]
}
```

Login returns the same `401` message for a wrong email and a wrong password, on purpose, so attackers cannot find out which emails exist.

---

## Making someone an admin

Registration never sets a role. Run this in the Neon SQL Editor:

```sql
update users set role = 'admin' where email = 'admin@example.com';
```

The change takes effect on the next request, so the user does not need to log in again.

---

## Running locally

```bash
npm install
cp .env.example .env     # then paste your Neon DATABASE_URL
npm run dev
```

Create the tables once by running `schema.sql` in the Neon SQL Editor.

### Environment variables

| Name | Required | Example |
|---|---|---|
| `DATABASE_URL` | yes | `postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require` |
| `NODE_ENV` | on Render | `production` |
| `PORT` | no | `3000` (Render sets it for you) |
| `CORS_ORIGIN` | only for a browser frontend | `http://localhost:5173`, or `*` for any site (demo only) |

## Deployment

Render redeploys automatically on every push to `main`.

| Setting | Value |
|---|---|
| Build command | `npm ci && npm run build` |
| Start command | `npm start` |
| Instance type | Free |
