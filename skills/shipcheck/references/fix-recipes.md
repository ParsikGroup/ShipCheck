# Fix recipes

Correct, conservative implementations for the fixes shipcheck asks for. Use these
rather than inventing one. Each finding in `FIXME.md` names the recipe it needs.

**Rules for whoever is applying these — human or AI:**

1. **Open the file and read it before changing it.** Every shipcheck code finding
   comes from pattern matching. Pattern matching is wrong sometimes. If the code
   does not actually have the problem described, say so and move on — do not
   "fix" it anyway.
2. **Match the project's existing style.** If it uses ESM, write ESM. If it uses
   TypeScript, write TypeScript. Do not introduce a new pattern for one fix.
3. **Start permissive, then tighten.** A rate limit that locks out real users, or
   a CSP that blanks the page, is worse than the problem it solved. Every number
   below is a starting point chosen to be safe.
4. **Test after each change.** Not "it compiles" — actually exercise the feature.
5. **You cannot rotate a key.** Only the owner can. When a fix involves a leaked
   credential, make the code change and then tell them plainly which keys to
   rotate and where.

---

## RATE LIMITING

The goal: an attacker cannot guess passwords endlessly, and one person cannot
exhaust your API or your email sending quota.

Apply **two** limiters. A strict one on authentication routes, a loose one on
everything else. Do not apply the strict one globally — you will break normal use.

### Express

```bash
npm install express-rate-limit
```

```js
// src/middleware/rateLimit.js
import rateLimit from 'express-rate-limit';

// Strict: login, signup, password reset, OTP, magic links.
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  limit: 5,                   // 5 attempts per window per key
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skipSuccessfulRequests: true, // only failures count — a real user logging in
                                // repeatedly is not an attack
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
});

// Loose: everything else.
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});
```

```js
// where the routes are defined
import { authLimiter, apiLimiter } from './middleware/rateLimit.js';

app.use('/api', apiLimiter);
app.post('/auth/login',  authLimiter, loginHandler);
app.post('/auth/register', authLimiter, registerHandler);
app.post('/auth/forgot-password', authLimiter, forgotHandler);
```

**If you are behind a proxy** (nginx, Cloudflare, Vercel, Railway, Fly, Heroku),
you MUST tell Express to trust it or every request looks like it comes from one
IP and the limiter will lock out everybody at once:

```js
app.set('trust proxy', 1);   // 1 = one proxy in front. Do not use `true`.
```

Verify it worked: `curl` the login route 20 times quickly and confirm later
requests return 429.

### Next.js (App Router)

`express-rate-limit` does not work here. Two options:

**Serverless / Vercel — use a shared store.** In-memory counters do not work
across serverless invocations.

```bash
npm install @upstash/ratelimit @upstash/redis
```

```ts
// src/lib/rateLimit.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

export const authLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '15 m'),
  prefix: 'rl:auth',
});
```

```ts
// src/app/api/auth/login/route.ts
import { authLimiter } from '@/lib/rateLimit';

export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'anon';
  const { success, reset } = await authLimiter.limit(ip);
  if (!success) {
    return Response.json(
      { error: 'Too many attempts. Try again shortly.' },
      { status: 429, headers: { 'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)) } },
    );
  }
  // ... existing login logic
}
```

**Single long-running server (self-hosted, Docker, a VPS):** an in-memory Map is
fine and needs no extra service.

```ts
// src/lib/rateLimit.ts — in-memory, single instance only
const hits = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(key: string, limit = 5, windowMs = 15 * 60_000) {
  const now = Date.now();
  const rec = hits.get(key);
  if (!rec || now > rec.resetAt) {
    hits.set(key, { count: 1, resetAt: now + windowMs });
    return { success: true };
  }
  rec.count += 1;
  return { success: rec.count <= limit, retryAfter: Math.ceil((rec.resetAt - now) / 1000) };
}

// stop the map growing forever
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (now > v.resetAt) hits.delete(k);
}, 60_000).unref?.();
```

### FastAPI

```bash
pip install slowapi
```

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/auth/login")
@limiter.limit("5/15minutes")
async def login(request: Request, ...):
    ...
```

The `request: Request` parameter is required — slowapi reads the client address
from it, and the decorator fails without it.

### Flask

```bash
pip install Flask-Limiter
```

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

@app.post("/auth/login")
@limiter.limit("5 per 15 minutes")
def login():
    ...
```

### Django

`pip install django-axes` handles login throttling and lockout properly, and is
the conventional answer. For general endpoints, Django REST Framework has
built-in throttling:

```python
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': ['rest_framework.throttling.AnonRateThrottle'],
    'DEFAULT_THROTTLE_RATES': {'anon': '100/minute'},
}
```

### Laravel / Rails

Both ship with this. Laravel: `Route::middleware('throttle:5,15')`. Rails: add
the `rack-attack` gem and configure `Rack::Attack.throttle`.

### Also worth doing: limit at the proxy

Belt and braces, and it protects you before the request reaches your app:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
location /auth/login {
    limit_req zone=login burst=5 nodelay;
    proxy_pass http://app;
}
```

### Key on more than the IP

An attacker with a botnet has many IPs; a single IP can attack many accounts.
Where you can, limit on **both**: `${ip}:${submittedEmail}`. That stops both the
spray and the focused attack.

---

## FILE UPLOAD

Three controls, all server-side. The browser can lie about all of this.

1. **Type** — an allowlist, checked on the server
2. **Size** — a hard cap
3. **Filename** — generate your own, never reuse theirs

Plus: store uploads where they cannot be executed.

### Express + multer

```js
import multer from 'multer';
import crypto from 'node:crypto';
import path from 'node:path';

const ALLOWED = new Map([
  ['image/jpeg', '.jpg'],
  ['image/png',  '.png'],
  ['image/webp', '.webp'],
]);

export const upload = multer({
  storage: multer.diskStorage({
    // NOT inside your public/ or static/ directory
    destination: (req, file, cb) => cb(null, '/var/app/uploads'),
    filename: (req, file, cb) => {
      const ext = ALLOWED.get(file.mimetype) ?? '';
      cb(null, `${crypto.randomUUID()}${ext}`);   // their filename is discarded
    },
  }),
  limits: {
    fileSize: 5 * 1024 * 1024,  // 5MB
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED.has(file.mimetype)) {
      return cb(new Error('Only JPEG, PNG and WebP images are allowed'));
    }
    cb(null, true);
  },
});
```

```js
app.post('/api/upload', requireAuth, upload.single('photo'), (req, res) => {
  res.json({ id: req.file.filename });   // never echo back a user-supplied name
});
```

**The mimetype multer reports comes from the browser** and can be faked. For
anything that matters, also check the file's magic bytes after upload — the
`file-type` npm package reads the actual header:

```js
import { fileTypeFromFile } from 'file-type';
const real = await fileTypeFromFile(req.file.path);
if (!real || !ALLOWED.has(real.mime)) {
  await fs.unlink(req.file.path);
  return res.status(400).json({ error: 'That file is not a valid image' });
}
```

### FastAPI

```python
import uuid, pathlib
from fastapi import UploadFile, File, HTTPException

ALLOWED = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
MAX_BYTES = 5 * 1024 * 1024
UPLOAD_DIR = pathlib.Path("/var/app/uploads")

@app.post("/api/upload")
async def upload(file: UploadFile = File(...), user=Depends(current_user)):
    if file.content_type not in ALLOWED:
        raise HTTPException(400, "Only JPEG, PNG and WebP images are allowed")

    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "File too large (max 5MB)")

    name = f"{uuid.uuid4()}{ALLOWED[file.content_type]}"
    (UPLOAD_DIR / name).write_bytes(data)
    return {"id": name}
```

### Flask

```python
import uuid, os
from werkzeug.utils import secure_filename

ALLOWED = {"jpg", "jpeg", "png", "webp"}
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024   # Flask enforces this for you

@app.post("/api/upload")
def upload():
    f = request.files.get("photo")
    if not f:
        return {"error": "no file"}, 400
    ext = os.path.splitext(secure_filename(f.filename))[1].lower().lstrip(".")
    if ext not in ALLOWED:
        return {"error": "Only JPEG, PNG and WebP images are allowed"}, 400
    name = f"{uuid.uuid4()}.{ext}"
    f.save(os.path.join("/var/app/uploads", name))
    return {"id": name}
```

### Where uploads are stored matters as much as what you accept

- **Never** write uploads into a directory the web server serves directly. If an
  attacker gets a `.php` or `.jsp` file in there, requesting its URL can run it.
- Serve them back through a route you control, which sets
  `Content-Disposition: attachment` (or a strict `Content-Type`) and checks
  whether this user is allowed this file.
- Better still, use object storage (S3, R2, Supabase Storage) with a presigned
  upload. The file never touches your server. Set a content-type condition and a
  size condition on the presigned policy — a presigned URL with no conditions is
  an open upload endpoint.

### Uploads need authorisation too

Two questions people forget: who is allowed to upload, and who is allowed to read
back what was uploaded. A `/uploads/<uuid>` route with no check means anyone with
the link — or anyone guessing — can read other people's files.

---

## SECRETS AND ENVIRONMENT

### The prefix rule

These prefixes mean "compile this into the JavaScript the browser downloads":

| Framework | Public prefix |
|---|---|
| Next.js | `NEXT_PUBLIC_` |
| Vite | `VITE_` |
| Create React App | `REACT_APP_` |
| Nuxt | `NUXT_PUBLIC_` |
| SvelteKit | `PUBLIC_` |
| Expo | `EXPO_PUBLIC_` |
| Astro | `PUBLIC_` |

Anything with one of those prefixes **is public**. Not "probably fine" — visible
to anyone who opens dev tools. Never put a secret behind one.

**Genuinely fine to be public:** Supabase anon key, Stripe publishable key
(`pk_`), Firebase config, PostHog/analytics project keys, a public API base URL.
These are designed to be public and are protected by server-side rules.

**Never public:** anything named `SECRET`, `SERVICE_ROLE`, `PRIVATE`, a Stripe
`sk_`, a database URL, an SMTP password, an OpenAI or Anthropic key.

### Moving a secret server-side

The pattern is always the same: the browser calls *your* endpoint, and *your
server* holds the key.

```ts
// BEFORE — key is in the browser
const res = await fetch('https://api.openai.com/v1/chat/completions', {
  headers: { Authorization: `Bearer ${process.env.NEXT_PUBLIC_OPENAI_KEY}` },
  ...
});

// AFTER — browser calls your route
const res = await fetch('/api/chat', { method: 'POST', body: JSON.stringify({ prompt }) });
```

```ts
// src/app/api/chat/route.ts — runs on the server, key never leaves it
export async function POST(req: Request) {
  const user = await requireUser(req);        // authenticate
  const { success } = await authLimiter.limit(user.id);  // and rate limit —
  if (!success) return new Response('Too many requests', { status: 429 });
  //                                  ^ your endpoint is now the thing that
  //                                    costs money, so it needs protecting

  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },  // no prefix
    ...
  });
  return new Response(res.body);
}
```

Note the rate limit. Proxying a paid API through your own endpoint without one
just moves the bill rather than removing it.

### .env hygiene

```gitignore
.env
.env.*
!.env.example
```

Commit `.env.example` with the **names** and dummy values, never real ones. New
contributors copy it. Real values go in your host's environment settings
(Vercel, Railway, Fly, systemd `EnvironmentFile`, Docker secrets).

---

## SUPABASE AND FIREBASE

### Supabase: two keys, very different

| Key | Where it may go | What it does |
|---|---|---|
| `anon` | Browser. It is meant to be public. | Subject to Row Level Security |
| `service_role` | **Server only. Never the browser.** | **Bypasses every RLS policy** |

If the service role key reaches the browser, your database is fully readable and
writable by anyone. RLS will not save you — bypassing RLS is what that key is for.

```ts
// src/lib/supabase-server.ts  — server only
import 'server-only';                  // build fails if a client component imports this
import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,   // no NEXT_PUBLIC_ prefix
  { auth: { persistSession: false } },
);
```

```ts
// src/lib/supabase.ts — safe in the browser
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
);
```

**RLS is the actual control.** The anon key with RLS disabled is the same as no
security at all — anyone can read every row.

```sql
alter table public.posts enable row level security;

create policy "read own posts"
  on public.posts for select
  using (auth.uid() = user_id);

create policy "insert own posts"
  on public.posts for insert
  with check (auth.uid() = user_id);
```

Check every table: Supabase dashboard → Table Editor → each table shows whether
RLS is on. A table with RLS off is public.

### Firebase: `if true` is the default and it is wide open

```javascript
// firestore.rules — the dangerous default
match /{document=**} { allow read, write: if true; }
```

```javascript
// signed in only
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{postId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null
                    && request.resource.data.ownerId == request.auth.uid;
      allow update, delete: if request.auth != null
                            && resource.data.ownerId == request.auth.uid;
    }
    match /{document=**} { allow read, write: if false; }  // deny by default
  }
}
```

Deploy with `firebase deploy --only firestore:rules`, and test in the Firebase
console's Rules Playground before and after. Storage rules are a separate file
(`storage.rules`) with the same problem and the same fix.

---

## SQL INJECTION

Never build a query by joining strings. Pass values separately — the driver keeps
data and code apart, which is the whole point.

```js
// WRONG — the user controls part of the query
const user = await db.query("SELECT * FROM users WHERE email = '" + email + "'");
const user = await db.query(`SELECT * FROM users WHERE email = '${email}'`);

// RIGHT — node-postgres
const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email]);

// RIGHT — mysql2
const [rows] = await conn.execute('SELECT * FROM users WHERE email = ?', [email]);
```

```python
# WRONG
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
# RIGHT
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```

With an ORM, use the query builder and avoid the raw escape hatch:

```ts
// Prisma
await prisma.user.findUnique({ where: { email } });          // safe
await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;  // also safe — tagged template
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);  // NOT safe
```

**Table and column names cannot be parameterised.** If one has to be dynamic,
check it against a hardcoded allowlist:

```js
const SORTABLE = ['created_at', 'name', 'price'];
if (!SORTABLE.includes(sortBy)) throw new Error('invalid sort');
```

---

## PASSWORD HANDLING

```bash
npm install bcrypt        # or: npm install argon2
```

```js
import bcrypt from 'bcrypt';

// signing up
const hash = await bcrypt.hash(password, 12);   // 12 rounds; never store `password`
await db.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hash]);

// logging in
const ok = await bcrypt.compare(password, user.password_hash);
if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
```

```python
# Python
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
try:
    ph.verify(hash, password)
except Exception:
    ...  # wrong password
```

Rules:

- Never store the password. Store only the hash.
- Never compare with `==` or `===`. Use the library's `compare`/`verify` — they
  are constant-time.
- **Same error message** for "no such user" and "wrong password". Different
  messages tell an attacker which emails are registered.
- Minimum length 8, and check against a breached-password list if you can. Do not
  enforce "one uppercase, one symbol" — current NIST guidance says length beats
  composition rules, and complexity rules push people toward `Password1!`.
- Never log a password, never email it, never return it in a response.

### Migrating existing plaintext passwords

You cannot un-hash, and you should not keep plaintext another day:

1. Add a `password_hash` column alongside the old one.
2. On the next successful login, hash what they typed, store it, and null the old
   column.
3. After a set period, force a password reset for whoever is left, and drop the
   old column.

---

## JWT AND SESSIONS

```js
import jwt from 'jsonwebtoken';

// WRONG — decode does not check the signature. Anyone can forge this.
const payload = jwt.decode(token);

// RIGHT
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],   // pin it — never allow "none"
  maxAge: '7d',
});
```

- The secret must be long and random: `openssl rand -base64 48`. Not "secret",
  not your app's name, and not committed.
- Pin the algorithm. Accepting `none`, or letting the token choose, is a complete
  auth bypass.
- Never set `ignoreExpiration`.
- Do not put anything secret in a JWT payload — it is base64, not encryption.
  Anyone holding the token can read it.
- You cannot revoke a JWT. If you need logout-everywhere or instant bans, keep a
  server-side session or a token-version column you check on each request.

---

## CORS

```js
// WRONG
app.use(cors());                                     // allows every origin
app.use(cors({ origin: '*', credentials: true }));   // and browsers reject this combination anyway

// RIGHT
const allowed = [
  'https://yourapp.com',
  'https://www.yourapp.com',
  ...(process.env.NODE_ENV !== 'production' ? ['http://localhost:3000'] : []),
];

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);          // curl, mobile apps, same-origin
    cb(null, allowed.includes(origin));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
}));
```

```python
# FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourapp.com"],   # never ["*"] with credentials
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
```

Things worth knowing:

- **CORS is not access control.** It restricts browsers, not `curl`. A private
  endpoint still needs authentication.
- Never reflect the `Origin` header back unchecked — that is a wildcard wearing a
  disguise.
- If your API is only called by your own server, it needs no CORS headers at all.

---

## AUTH MIDDLEWARE

Prefer **deny by default**: protect the router, then explicitly open the routes
that should be public. The other way round, every route someone adds later is
public until they remember.

```js
// src/middleware/auth.js
export async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.session ?? req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not signed in' });
    req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch {
    return res.status(401).json({ error: 'Not signed in' });
  }
}
```

```js
const PUBLIC = ['/api/health', '/api/auth/login', '/api/auth/register'];

app.use('/api', (req, res, next) =>
  PUBLIC.includes(req.path) ? next() : requireAuth(req, res, next));
```

### Authentication is not authorisation

This is the bug that matters most and no scanner reliably finds it:

```js
// authenticated, and still broken — any logged-in user reads any order
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  res.json(await db.order.findUnique({ where: { id: req.params.id } }));
});

// correct — the query is scoped to the caller
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.order.findFirst({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});
```

**Rule: every query that fetches a record by an id from the URL must also filter
on the current user.** Check every one. Return 404 rather than 403 so you do not
confirm the record exists.

### Next.js App Router

```ts
// src/app/api/orders/[id]/route.ts
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession(authOptions);
  if (!session) return Response.json({ error: 'Not signed in' }, { status: 401 });

  const order = await db.order.findFirst({
    where: { id: params.id, userId: session.user.id },
  });
  if (!order) return Response.json({ error: 'Not found' }, { status: 404 });
  return Response.json(order);
}
```

`middleware.ts` is good for redirecting unauthenticated page visits. Do **not**
rely on it as your only API protection — check the session inside each route
handler too.

---

## SECURITY HEADERS

### Express

```bash
npm install helmet
```

```js
import helmet from 'helmet';
app.use(helmet());   // sensible defaults, including a strict CSP
```

If the default CSP breaks your app, tune it rather than removing it:

```js
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https://your-cdn.com'],
      connectSrc: ["'self'", 'https://api.yourapp.com'],
    },
  },
}));
```

### Next.js

```js
// next.config.js
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};
```

### Order of work

1. `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` — break nothing,
   add them now.
2. `Strict-Transport-Security` — safe once HTTPS works everywhere. Do not add
   `preload` until you are certain, it is hard to undo.
3. `Content-Security-Policy` — add as `Content-Security-Policy-Report-Only`
   first, watch the console for a few days, then enforce. A strict CSP will break
   inline scripts, inline styles and third-party widgets until tuned.

---

## CSRF AND COOKIES

```js
res.cookie('session', token, {
  httpOnly: true,                                   // JavaScript cannot read it
  secure: process.env.NODE_ENV === 'production',    // HTTPS only in production
  sameSite: 'lax',                                  // blocks the simple cross-site case
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/',
});
```

- `httpOnly` — an XSS bug can no longer steal the session.
- `secure` — never sent over plain HTTP. Keep it off locally or your dev login
  will silently stop working.
- `sameSite: 'lax'` — good default. `'strict'` breaks links from other sites into
  a logged-in page. `'none'` requires `secure` and reopens CSRF.

### Do you need CSRF tokens?

- **Cookie-based sessions + form posts** → yes.
- **`Authorization: Bearer` header** → no. The browser does not attach it
  automatically, so there is nothing to forge.
- **Cookies + a JSON API that requires `Content-Type: application/json`** →
  largely protected already, because a cross-site form cannot set that header.
  `sameSite: 'lax'` plus an origin check is usually enough.

Use your framework's built-in support rather than writing your own: Django and
Rails and Laravel all ship it on by default. For Express, `csrf-csrf` is the
maintained option (`csurf` is deprecated and should not be added to new code).

---

## DANGEROUS FUNCTIONS

| Pattern | Why | Instead |
|---|---|---|
| `eval(x)`, `new Function(x)` | Runs whatever is in the string | `JSON.parse` for data; a lookup object for dispatch |
| `exec("cmd " + input)` | Shell metacharacters run commands | `execFile('cmd', [arg1, arg2])` — arguments as an array |
| `subprocess.run(..., shell=True)` | Same | `subprocess.run(['cmd', arg], shell=False)` |
| `pickle.loads(data)` | Deserialising runs code | `json.loads` |
| `yaml.load(data)` | Can construct arbitrary objects | `yaml.safe_load` |
| `unserialize($data)` (PHP) | Object injection | `json_decode` |

```js
// WRONG
exec(`convert ${userFilename} out.png`);

// RIGHT — no shell, arguments passed separately
execFile('convert', [userFilename, 'out.png']);
```

If a value must go into a command, validate it against an allowlist first. Never
try to escape it yourself — you will miss a case.

---

## XSS

Your framework escapes by default. These are the opt-outs:

| Framework | The opt-out |
|---|---|
| React | `dangerouslySetInnerHTML` |
| Vue | `v-html` |
| Angular | `bypassSecurityTrust*` |
| Plain JS | `.innerHTML =`, `document.write()` |
| Jinja / Django | `\|safe` |
| Handlebars | `{{{ }}}` |

```jsx
// WRONG
<div dangerouslySetInnerHTML={{ __html: comment.body }} />

// RIGHT — if it is text, render it as text
<div>{comment.body}</div>

// RIGHT — if it genuinely must be HTML, sanitise it, on the server, at write time
import DOMPurify from 'isomorphic-dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />
```

Python: `bleach.clean(html, tags=ALLOWED_TAGS, strip=True)`.

Never put user input into a `<script>` block, a `javascript:` URL, or an event
handler attribute. Escaping does not reliably save you in those contexts.

A Content-Security-Policy is the second layer — it limits the damage when one of
these is missed. See SECURITY HEADERS.

---

## After any fix

1. **Run the app.** Not just a build — click the thing you changed.
2. **Re-run shipcheck** and confirm the finding is gone.
3. **List the credentials the owner must rotate.** A code fix does not revoke a
   leaked key. Name the key and where to rotate it.
4. **Say what you did not do**, and why. A skipped task explained is fine. A
   skipped task reported as done is not.
