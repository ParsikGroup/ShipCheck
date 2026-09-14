# What shipcheck looks at

Use this to answer "did you check X?" honestly.

## Your code

| Check | Why it matters |
|---|---|
| `.env` tracked in git | Every key in it is in the repo history and in every clone. The most common serious mistake in small projects. |
| `.env` in git history even if deleted now | Deleting a file does not remove it from history. Still readable with one command. |
| API keys and passwords by pattern | AWS, OpenAI, Stripe live, GitHub, Slack, Google, SendGrid, private key blocks, JWTs, and database URLs with an embedded password. Records file and key type — **never the value**. |
| `.env` missing from `.gitignore` | It has not been committed yet. It will be on the next `git add .`. |
| `.env` file permissions | Other accounts on the box reading your production credentials without needing any exploit. |
| Debug mode on | Stack traces, env vars and file paths served to anyone who triggers an error. Some frameworks expose a code console. |
| Source maps in the build output | Hands anyone your original un-minified source. |
| `npm audit` | Known holes in your dependencies, with fixes already published. Uses npm, which a JS dev already has. |

Optional, only if `install-tools.sh` was run: **gitleaks** (secrets across the
entire git history, not just current files), **trivy** (dependency and container
vulnerabilities, infrastructure misconfig), **semgrep** (static analysis).

## Your application code — how it's built

Pattern-based, zero dependencies. These are **candidates**: open the file and
confirm before changing anything.

| Check | Why it matters |
|---|---|
| **No rate limiting on login/signup/reset** | Unlimited password guessing, unlimited reset emails. Bots find login endpoints automatically. |
| **File upload with no validation** | Upload a script instead of a photo; fill the disk; `../../` in a filename writes outside the folder. |
| **Secrets behind a public prefix** (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`…) | Compiled into the JS every visitor downloads. The app works fine, so nothing looks wrong. |
| **Supabase `service_role` key in app code** | Bypasses every Row Level Security policy. Master key to the whole database. |
| **Firebase rules `if true`** | The `firebase init` default. Anyone with the project ID reads and deletes everything. |
| **SQL built by string concatenation** | `' OR 1=1 --` in a login box becomes part of your query. |
| **No password hashing library** | Passwords likely stored readable. Turns a small breach into a serious one. |
| **Password compared with `==`** | Same problem, plus a timing side channel. |
| **JWT decoded without verifying** | Anyone can forge a token saying they are an admin. |
| **CORS wildcard**, especially with credentials | Any website can call your API from a logged-in user's browser. |
| **Routes vs auth checks** | Counts route handlers against authentication references. Many routes and no checks is a flag for a human to review, not a blind patch. |
| **`eval`, shell exec, `pickle.loads`, `yaml.load`** | Runs attacker code if any input is user-influenced. |
| **`dangerouslySetInnerHTML`, `innerHTML =`, `v-html`** | The places your framework's escaping is opted out of. |
| **No security headers configured** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options. |
| **Cookie sessions with no CSRF handling** | Another site can act as your logged-in user. |

Frameworks auto-detected: Next.js, Express, Fastify, NestJS, Koa, SvelteKit,
Nuxt, Remix, Vite, CRA, Flask, Django, FastAPI, Laravel, Rails, Go web, plus
Supabase, Firebase, Prisma and Mongoose.

Every one of these has a matching implementation in `fix-recipes.md`.

## Your live site

Only runs when `--site` is given.

| Check | Why it matters |
|---|---|
| `/.git/config` returns 200 | Your whole source and history downloadable by anyone. Scanned for constantly. |
| `/.env` returns 200 | Production credentials served as a plain file. |
| Directory listing | A browsable map of everything on the server. |
| Security headers | HSTS, CSP, X-Content-Type-Options, X-Frame-Options. |
| Server version banner | Tells attackers exactly which exploits to try. |
| TLS certificate expiry | Expired means a full-page browser warning for every visitor. |

## Your server

| Area | What it covers |
|---|---|
| Exposure | Every listening socket, its bind address, and public IPv4/IPv6 lookup so the external scan can be run |
| Firewall | ufw / nftables / firewalld / iptables, whether default-deny is set, **whether IPv6 is filtered at all**, and whether Docker is bypassing it |
| SSH | Password auth, root login, host key permissions, authorized_keys, failed login volume |
| Accounts | Extra UID 0 accounts, passwordless sudo, docker group membership |
| Containers | Privileged containers, mounted Docker socket, host networking, published ports, socket permissions |
| Data services | Redis without a password, Postgres `trust` auth, MySQL and MongoDB bind and auth settings |
| Patching | Pending security updates, reboot required, EOL operating system, `needrestart` local root |
| Backups | Whether any backup tool or schedule exists at all |
| Logging | Whether logs survive a reboot |
| Kernel | A set of safe hardening sysctls |
| Credential files | `.env`, private keys and credential stores readable by other accounts |

## What shipcheck does NOT check

Say this plainly whenever someone asks whether they are "secure now."

- **Whether your app's permissions work.** Can user A read user B's data by
  changing an id in the URL? Can a free account hit a paid endpoint? This is the
  single most common serious bug in real applications and it cannot be found
  without testing the running app as two different users. shipcheck counts routes
  and auth checks; it does not test them.
- **Business logic.** Ordering negative quantities, skipping the payment step,
  replaying a request, racing two checkouts.
- **Injection and XSS.** Needs an authenticated crawl of the running app.
- **Whether your backups restore.** It checks that backups exist, not that they work.
- **Your cloud account.** IAM roles, S3 bucket policies, security groups.
- **Kubernetes.** Nothing at all.
- **Windows, macOS, mobile apps, WordPress plugins.**
- **Anything requiring judgment about your specific business.**

A clean shipcheck means the obvious doors are shut. That is genuinely most of
what gets small projects hit. It is not the same as the app being secure.
