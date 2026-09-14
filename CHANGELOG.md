# Changelog

## 0.2.0 — 2026-09-14

Three changes: shipcheck can no longer fail silently, it now reviews the
application code itself, and it works with any AI rather than only Claude.

### A broken check can no longer read as a clean result

This was the most serious weakness in 0.1.0. If a parser did not recognise the
output of `ss`, `sshd -T` or `docker inspect`, the affected checks produced zero
findings with no error — and the report opened with "Nothing urgent" on a server
with Redis wide open.

The collector now records, per source: was the tool present, and did it return
anything. Any source that was present and returned nothing becomes a **high**
finding, and `REPORT.md` leads with a warning block naming exactly what could not
be seen. A run with no findings at all and a coverage gap reads "Nothing found —
but the check was incomplete", never "Nothing found".

`test/contract-test.sh` enforces this: findings marked blind must be warned about
in the first 30 lines of the report, or CI fails.

### Application code review

Fifteen new checks, zero new dependencies, on top of framework auto-detection
(Next.js, Express, Fastify, NestJS, Koa, SvelteKit, Nuxt, Remix, Vite, CRA,
Flask, Django, FastAPI, Laravel, Rails, Go, plus Supabase, Firebase, Prisma,
Mongoose):

- **No rate limiting on login, signup or password reset** — and it distinguishes
  "no limiter anywhere" from "a limiter exists, check it covers auth"
- **File uploads with no type, size or filename validation**
- **Secrets behind a public prefix** (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`,
  `NUXT_PUBLIC_`, `PUBLIC_`, `EXPO_PUBLIC_`) — compiled into the browser bundle
- **Supabase `service_role` key in application code** — bypasses all RLS
- **Firebase rules allowing `if true`** — the init default
- **SQL built by string concatenation**
- **No password hashing library**, and passwords compared with `==`
- **JWTs decoded without verification**, `algorithms: none`, ignored expiry
- **Wildcard CORS**, escalated when combined with credentials
- **Route count vs auth check count** — a density signal, deliberately routed to
  human judgment rather than a blind patch
- **`eval`, shell exec, `pickle.loads`, unsafe `yaml.load`**
- **`dangerouslySetInnerHTML`, `innerHTML =`, `v-html`**
- **No security headers configured**
- **Cookie sessions with no CSRF or SameSite handling**

Every code finding records file and line only — never the matched source text.

### Fix recipes

New `references/fix-recipes.md`: correct, conservative implementations for every
fix above, across Express, Next.js (App Router, serverless and self-hosted),
FastAPI, Flask, Django, Laravel and Rails. Covers the details that get missed —
`trust proxy` behind a reverse proxy, why in-memory rate limiting breaks on
serverless, checking magic bytes rather than the browser's Content-Type,
migrating existing plaintext passwords, why `origin: '*'` with credentials does
not even work.

`report.py` copies the file next to `FIXME.md`, and the contract test fails if
the brief references recipes that are not there — an agent handed a task list
with no recipes will invent implementations, which is the thing this prevents.

### Works with any AI

New `AGENTS.md` at the repo root: how to run shipcheck, how to read the output,
the ten rules it must not break, and how to explain findings to a non-technical
owner. No plugin required and nothing model-specific. Clone the repo and point
Claude, ChatGPT, Cursor, Copilot, Gemini, Windsurf or Aider at it.

### Also

- `fix.sh` tiering audited again: only file modes under `/root` and `/etc/ssh`,
  the Docker socket, sysctls and persistent journald. Application-directory file
  permissions moved to the agent tier, because the right mode depends on which
  user the app runs as.
- Public IP lookup now falls back through DNS (`myip.opendns.com`) before HTTP.

## 0.1.0 — 2026-09-08

First release. Server exposure, firewall, SSH, Docker, accounts, patching and
backups; code checks for committed `.env`, leaked keys, debug mode and source
maps; live-site checks for exposed `/.git` and `/.env`, headers and TLS expiry.
Three-tier safety model (safe / agent / human), `fix.sh` containing no
access-affecting change, and `test/contract-test.sh` enforcing that plus
no-secret-values.
