#!/usr/bin/env python3
"""
shipcheck analyzer — turns evidence.json into findings a human can read.

    python3 analyze.py ./shipcheck-run --out findings.json

Every finding carries an `automate` level, and that level is the whole safety
model of this tool:

    safe   the fix script does it. Cannot lock you out, cannot break a service.
    agent  an AI coding agent can do it. Code, config and repo changes.
    human  a person must do it. Anything that can lock you out of your own
           server, cost money, or requires judgment — SSH, firewall, rotating
           credentials, buying backups.

Nothing is ever promoted to a safer level because the finding was severe.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# --------------------------------------------------------------------------



def default_run_dir():
    """<repo>/outputs — same default shipcheck.sh uses, so no argument is needed."""
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", "..", ".."))
    cand = os.path.join(repo, "outputs")
    return cand if os.path.isdir(cand) else "./shipcheck-outputs"


def load(path):
    if os.path.isdir(path):
        path = os.path.join(path, "evidence.json")
    with open(path) as fh:
        return json.load(fh), os.path.dirname(path) or "."


class Ev:
    def __init__(self, d):
        self.d = d

    def sec(self, n):
        v = self.d.get(n)
        return v if isinstance(v, dict) else {}

    def L(self, s, k):
        v = self.sec(s).get(k)
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            return v.splitlines()
        return []

    def T(self, s, k):
        v = self.sec(s).get(k)
        if isinstance(v, list):
            return "\n".join(str(x) for x in v)
        return v if isinstance(v, str) else ""

    def B(self, s, k):
        return bool(self.sec(s).get(k))


class Out:
    def __init__(self, app_root=""):
        self.f = []
        self.app_root = app_root or ""

    def abspath(self, p):
        """fix.sh runs from the report dir, so its targets must be absolute."""
        p = str(p)
        if p.startswith("/"):
            return p
        p = p[2:] if p.startswith("./") else p
        return os.path.join(self.app_root, p) if self.app_root else os.path.abspath(p)

    def add(self, sev, title, plain, **kw):
        self.f.append(
            {
                "id": None,
                "severity": sev,
                "domain": kw.get("domain", "server"),
                "title": title,
                "plain": " ".join(plain.split()),
                "where": kw.get("where", []),
                "proof": kw.get("proof", []),
                "fix": {
                    "summary": kw.get("fix", ""),
                    "steps": kw.get("steps", []),
                    "automate": kw.get("automate", "human"),
                    "verify": kw.get("verify", ""),
                    "breaks": kw.get("breaks", ""),
                },
                "auto": kw.get("auto"),
                "recipe": kw.get("recipe"),
                "blind": kw.get("blind", False),
            }
        )
        a = self.f[-1]["auto"]
        if a and a.get("paths"):
            a["paths"] = [self.abspath(x) for x in a["paths"]]

    def done(self):
        self.f.sort(key=lambda x: (SEV.get(x["severity"], 9), x["title"]))
        for i, x in enumerate(self.f, 1):
            x["id"] = "SC-%03d" % i
        return self.f


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------

LISTEN = re.compile(r"^(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)(.*)$")
WILD = {"0.0.0.0", "*", "::", "[::]", ""}

PORTS = {
    "6379": ("Redis", "critical"), "11211": ("Memcached", "critical"),
    "27017": ("MongoDB", "critical"), "9200": ("Elasticsearch", "critical"),
    "2375": ("Docker API", "critical"), "2379": ("etcd", "critical"),
    "5432": ("PostgreSQL", "high"), "3306": ("MySQL", "high"),
    "5984": ("CouchDB", "high"), "1433": ("SQL Server", "high"),
    "5672": ("RabbitMQ", "high"), "15672": ("RabbitMQ admin", "high"),
    "9000": ("Portainer or app admin", "high"), "8006": ("Proxmox", "high"),
    "5900": ("VNC", "high"), "3389": ("RDP", "high"), "445": ("SMB", "high"),
    "9090": ("Prometheus or Cockpit", "medium"), "3000": ("app / Grafana", "medium"),
    "8080": ("app / admin", "medium"), "8081": ("app / admin", "medium"),
    "25": ("mail", "medium"),
}


def listeners(ev):
    out = []
    for line in ev.L("network", "listeners"):
        m = LISTEN.match(line.strip())
        if not m:
            continue
        local = m.group(3)
        if local.startswith("["):
            addr, _, port = local.rpartition("]:")
            addr = addr.lstrip("[")
        else:
            addr, _, port = local.rpartition(":")
        pm = re.search(r'\(\("([^"]+)"', m.group(5) or "")
        out.append({"proto": m.group(1), "addr": addr, "port": port,
                    "proc": pm.group(1) if pm else "", "raw": line.strip()})
    return out


def sshd(ev):
    cfg = {}
    for line in ev.L("ssh", "config"):
        p = line.strip().split(None, 1)
        if p:
            cfg[p[0].lower()] = p[1] if len(p) > 1 else ""
    return cfg


# --------------------------------------------------------------------------
# CODE  — the checks that matter most to someone shipping fast
# --------------------------------------------------------------------------


def check_code(ev, O):
    if not ev.B("shipcheck", "checked_app"):
        return
    app = ev.sec("shipcheck").get("app_path") or "your project"

    tracked = [x for x in ev.L("app", "env_tracked_in_git") if x.strip()]
    if tracked:
        O.add(
            "critical",
            "Your .env file is committed to git",
            """Your .env is tracked by git, which means every key in it is in your repository
            history and in every clone of it. If the repo is public, or ever becomes public, or
            any collaborator's laptop is compromised, those keys are gone. Deleting the file now
            does not help — it stays in the history forever.""",
            domain="code",
            where=tracked,
            proof=["git ls-files | grep -E '(^|/)\\.env'"],
            fix="Rotate every key that was in the file, then remove it from git and ignore it.",
            steps=[
                "Rotate EVERY credential in that file first — assume they are public. "
                "New keys in your provider dashboards (Stripe, OpenAI, AWS, database).",
                "git rm --cached .env",
                "Add `.env` and `.env.*` to .gitignore (keep `!.env.example`).",
                "git commit -m 'remove .env from tracking'",
                "If the repo is public or shared, also purge it from history with "
                "`git filter-repo --path .env --invert-paths`, then force-push and tell "
                "collaborators to re-clone.",
            ],
            automate="human",
            breaks="Nothing, but the rotation step must happen or the fix is cosmetic.",
            verify="git ls-files | grep -c '\\.env' # expect 0",
        )

    hist = [x for x in ev.L("app", "env_in_git_history") if x.strip() and x not in tracked]
    if hist:
        O.add(
            "critical",
            "A .env file exists in your git history even though it is gone now",
            """Someone removed the .env from the project, but git keeps every version of every
            file it has ever tracked. Anyone who clones the repo can read the old contents with
            one command. The keys that were in it are still live unless they were rotated.""",
            domain="code",
            where=hist,
            proof=["git log --all --diff-filter=A --name-only --format='' | grep '\\.env'"],
            fix="Rotate the keys. Purging history only helps if you rotate.",
            steps=[
                "Rotate every credential that was ever in that file.",
                "Optionally purge history: `git filter-repo --path <file> --invert-paths`, "
                "then force-push. Everyone with a clone must re-clone.",
            ],
            automate="human",
            verify="git log --all --diff-filter=A --name-only --format='' | grep -c '\\.env'",
        )

    hits = []
    for h in ev.L("app", "secret_hits"):
        parts = h.split("|")
        if len(parts) == 3:
            hits.append({"file": parts[0], "count": parts[1], "kind": parts[2]})
    live = [h for h in hits if h["kind"] in
            ("AWS access key", "Stripe live key", "GitHub token", "private key block",
             "OpenAI API key", "SendGrid key", "Slack token", "database URL with password")]
    if hits:
        in_code = [h for h in hits if not re.search(r"\.env", h["file"])]
        O.add(
            "critical" if live else "high",
            "Real credentials are sitting in your files (%d place%s)" % (len(hits), "" if len(hits) == 1 else "s"),
            """These files contain things that look like live API keys or passwords. Anything in
            source code ends up in git, in your build output, and sometimes in the JavaScript
            bundle your users download. Keys in code are the single most common way a small
            project gets drained — usually a cloud bill, sometimes the whole database."""
            + (" Some of these are in source files, not just .env, which means they are almost "
               "certainly in your repo." if in_code else ""),
            domain="code",
            where=["%s — %s (%s occurrence%s)" % (h["file"], h["kind"], h["count"],
                                                  "" if h["count"] == "1" else "s") for h in hits],
            proof=["Open each file above and look for the key. shipcheck deliberately did not "
                   "record the value."],
            fix="Rotate each key, then load them from environment variables instead of code.",
            steps=[
                "Rotate every key listed above in its provider dashboard. Assume they are compromised.",
                "Replace each hardcoded value with an environment variable read "
                "(process.env.X / os.environ['X']).",
                "Put the real values in .env locally and in your host's secrets/environment settings "
                "in production.",
                "Confirm .env is in .gitignore.",
                "Commit the code change. Do NOT commit the .env.",
            ],
            automate="agent",
            breaks="The app will fail to start if a variable is missing — set them before deploying.",
            verify="grep -rE 'AKIA|sk_live_|ghp_|BEGIN.*PRIVATE KEY' --exclude-dir=node_modules . | wc -l",
        )

    gi = "\n".join(ev.L("app", "gitignore"))
    envf = [x for x in ev.L("app", "env_files") if x.strip()]
    if envf and ev.B("app", "git") and not re.search(r"^\s*\.?env|\.env", gi, re.M) and not tracked:
        O.add(
            "high",
            ".env is not in your .gitignore",
            """You have a .env file and git is not told to ignore it. It has not been committed
            yet, but it will be the next time someone runs `git add .` — and at that point every
            key in it is in your history permanently.""",
            domain="code",
            where=[x.split()[-1] for x in envf],
            proof=["cat .gitignore"],
            fix="Add .env to .gitignore before your next commit.",
            steps=["Append these lines to .gitignore:", ".env", ".env.*", "!.env.example"],
            automate="agent",
            breaks="Nothing.",
            verify="grep -c '^\\.env' .gitignore",
        )

    loose = [x for x in envf if re.match(r"^[0-7]?[0-7][0-7][1-7]\s|^[0-7]?[0-7][4-7][0-7]\s", x)]
    if loose:
        O.add(
            "medium",
            "Your .env file can be read by other users on the machine",
            """The file holding your production credentials is readable by accounts other than
            yours. On a shared box, or if any other service on this server is compromised, that
            service can read your keys without needing any exploit at all.""",
            domain="code",
            where=loose,
            proof=["stat -c '%a %n' .env*"],
            fix="Make the file readable only by its owner.",
            steps=[
                "Check which user your app runs as — `systemctl show -p User <service>`, "
                "`docker inspect <container> --format '{{.Config.User}}'`, or `ps aux | grep <app>`.",
                "If that user owns the .env: `chmod 600 .env`.",
                "If a different user reads it: `chown <owner>:<appgroup> .env && chmod 640 .env`.",
                "Restart the app and confirm it starts and can still read its config.",
            ],
            automate="agent",
            breaks="If your app runs as a different user than the file's owner, 600 stops it "
                   "reading its own config. Check which user first.",
            verify="stat -c '%a %U:%G' .env",
        )

    dbg = [x for x in ev.L("app", "debug_flags") if x.strip()]
    if dbg:
        O.add(
            "high",
            "Debug mode looks like it is turned on",
            """Debug mode prints stack traces, file paths, environment variables and sometimes
            database queries straight to anyone who triggers an error. On a live site that is a
            free map of your application, and in some frameworks it exposes a console that runs
            code.""",
            domain="code",
            where=dbg,
            proof=["Trigger a 500 on the live site and see whether you get a stack trace."],
            fix="Turn debug off in the production environment.",
            steps=[
                "Set DEBUG=false / NODE_ENV=production / APP_DEBUG=false in the production environment.",
                "Confirm the live site returns a generic error page, not a stack trace.",
            ],
            automate="agent",
            breaks="You lose detailed errors in production — that is the point. Use logs instead.",
            verify="curl -s https://yoursite/nonexistent-path | grep -ci traceback",
        )

    smaps = [x for x in ev.L("app", "sourcemaps") if x.strip()]
    if smaps:
        O.add(
            "low",
            "Source maps are being shipped to production",
            """Source maps let anyone reconstruct your original, un-minified source code from the
            browser. Not dangerous on its own, but it hands an attacker a readable copy of your
            frontend logic, including any keys or endpoints you thought were hidden in the bundle.""",
            domain="code",
            where=smaps,
            proof=["ls dist/**/*.map"],
            fix="Disable source map generation for production builds.",
            steps=["Set `productionBrowserSourceMaps: false` (Next.js), `sourcemap: false` (Vite), "
                   "or `devtool: false` (Webpack) for the production build.",
                   "Delete the existing .map files from the deployed output."],
            automate="agent",
            breaks="Harder to debug production errors in the browser.",
            verify="find dist build .next -name '*.map' 2>/dev/null | wc -l",
        )

    # npm audit, if a lockfile existed
    audit_path = os.path.join(ev.d.get("_run_dir", "."), "npm_audit.json")
    if os.path.exists(audit_path):
        try:
            a = json.load(open(audit_path))
            vul = (a.get("metadata") or {}).get("vulnerabilities") or {}
            crit, high = vul.get("critical", 0), vul.get("high", 0)
            if crit or high:
                O.add(
                    "high" if crit else "medium",
                    "Your dependencies have %d critical and %d high vulnerabilities" % (crit, high),
                    """These are known, published holes in packages your app depends on. Most have
                    a fixed version already released — the fix is usually an upgrade, not a rewrite.
                    Not every one is reachable from your code, but the critical ones are worth an
                    afternoon.""",
                    domain="code",
                    where=["package-lock.json"],
                    proof=["npm audit"],
                    fix="Upgrade the vulnerable packages.",
                    steps=["Run `npm audit fix` for the safe upgrades.",
                           "Run `npm audit` again and look at what is left — those need a major "
                           "version bump, so read the changelog before upgrading.",
                           "Re-run your tests."],
                    automate="agent",
                    breaks="A major version bump can break your build. Test after.",
                    verify="npm audit --audit-level=high",
                )
        except Exception:
            pass




# --------------------------------------------------------------------------
# APPLICATION CODE — what the app itself gets wrong
# Everything here is a CANDIDATE from pattern matching. The agent must open the
# file and confirm before changing anything. Say so in every finding.
# --------------------------------------------------------------------------


def files_of(hits, limit=12):
    """'path:line:match' -> 'path:line' only. Never carry matched source text."""
    out, seen = [], set()
    for h in hits:
        parts = str(h).split(":", 2)
        key = ":".join(parts[:2]) if len(parts) >= 2 else parts[0]
        if key not in seen:
            seen.add(key)
            out.append(key)
        if len(out) >= limit:
            break
    return out


def check_appsec(ev, O):
    if not ev.B("shipcheck", "checked_app"):
        return
    A = ev.sec("appsec")
    fw = [x.strip() for x in ev.L("appsec", "frameworks") if x.strip()]
    stack = ", ".join(fw) if fw else "unknown"

    def L(k):
        return [x for x in ev.L("appsec", k) if str(x).strip()]

    def n(k):
        v = (A.get(k) or "0")
        m = re.search(r"\d+", str(v))
        return int(m.group()) if m else 0

    auth_routes = L("auth_routes") + L("auth_files")
    rate = L("ratelimit_hits") + L("ratelimit_packages") + L("proxy_ratelimit")
    uploads = L("upload_handlers")
    guards = L("upload_guards")

    # ---- 1. login with no rate limit -------------------------------------
    if auth_routes and not rate:
        O.add(
            "high",
            "Your login and signup pages have no rate limiting",
            """Anyone can hit your login endpoint as fast as their connection allows. That means
            unlimited password guessing, unlimited account-enumeration probing, and unlimited
            password-reset emails sent from your account until your email provider suspends you.
            Bots find login endpoints automatically — this is not a question of whether anyone
            will try. Rate limiting is usually about ten lines of code.""",
            domain="code",
            where=files_of(auth_routes),
            proof=["Open one of the files above and look for a rate limiter on the route.",
                   "Or test it: send 50 wrong passwords in a row and see if anything stops you."],
            fix="Add a rate limiter to every authentication route.",
            steps=[
                "Open `fix-recipes.md` and use the RATE LIMITING recipe for your stack (%s)." % stack,
                "Apply the strict limiter to login, signup, password reset and any OTP or "
                "magic-link route. Start generous — 5 attempts per 15 minutes per IP.",
                "Apply a looser global limiter to the rest of the API (100/minute is a "
                "reasonable starting point).",
                "Key the limiter on IP **and** on the submitted email or username where you can, "
                "so one attacker cannot spread guesses across many accounts.",
                "Test it yourself: fire the endpoint repeatedly and confirm you get 429s.",
                "Make sure your real traffic is not being limited — if you are behind a proxy, "
                "configure trust proxy / X-Forwarded-For or every request will look like one IP.",
            ],
            automate="agent",
            breaks="Set the limit too low and real users get locked out. Start generous and tighten.",
            verify="Send 20 rapid requests to your login route and confirm the later ones return 429.",
            recipe="RATE LIMITING",
        )
    elif auth_routes and rate:
        limited = files_of(rate, 6)
        O.add(
            "low",
            "Rate limiting is present — check it actually covers your login routes",
            """Good — a rate limiter exists somewhere in this project. What shipcheck cannot tell
            from pattern matching is whether it is actually applied to the authentication routes,
            or just to one API endpoint someone was worried about. Worth thirty seconds to check.""",
            domain="code",
            where=limited + ["auth routes: " + ", ".join(files_of(auth_routes, 5))],
            proof=["Check that the limiter middleware is attached to the login route specifically."],
            fix="Confirm the limiter covers login, signup and password reset.",
            steps=["Open each auth route and confirm a limiter is applied to it.",
                   "If not, see the RATE LIMITING recipe in `fix-recipes.md`."],
            automate="agent",
            breaks="Nothing.",
            verify="Fire 20 rapid login attempts and confirm you get 429s.",
            recipe="RATE LIMITING",
        )

    # ---- 2. file upload with no validation --------------------------------
    if uploads and not guards:
        O.add(
            "high",
            "You accept file uploads with no checks on what gets uploaded",
            """Your app takes files from users and shipcheck found nothing checking the file type,
            the size, or the filename. That means someone can upload a script instead of a photo,
            upload a 10GB file and fill your disk, or use a filename like `../../.env` to write
            outside the folder you meant. If uploads land somewhere your web server serves, an
            uploaded script can sometimes be executed by requesting its URL.""",
            domain="code",
            where=files_of(uploads),
            proof=["Try uploading a .txt or .html file where you expect a photo. If it succeeds, "
                   "there is no type check."],
            fix="Validate type, size and filename on the server, and store uploads outside the web root.",
            steps=[
                "Use the FILE UPLOAD recipe in `fix-recipes.md` for your stack (%s)." % stack,
                "Check the MIME type **server-side** against an allowlist. Never trust the "
                "Content-Type the browser sends, and never trust the file extension.",
                "Set a maximum file size. Pick a real number — 5MB for images is plenty.",
                "Generate your own filename (a UUID) instead of using the one the user sent. "
                "That kills path traversal and filename collisions in one move.",
                "Store uploads outside the directory your web server serves, or in object storage, "
                "and serve them through a route that sets `Content-Disposition` and a safe "
                "`Content-Type`.",
                "Test it: upload a .html file and confirm it is rejected.",
            ],
            automate="agent",
            breaks="Too strict an allowlist rejects legitimate files. Confirm which types you actually need.",
            verify="Upload a file with a disallowed extension and confirm it is rejected.",
            recipe="FILE UPLOAD",
        )
    elif uploads and guards:
        O.add(
            "low",
            "File uploads have some validation — worth confirming it covers everything",
            """Upload handling exists and there is some validation nearby. The three things that
            matter are: server-side type checking, a size limit, and not reusing the user's
            filename. Check all three are present.""",
            domain="code",
            where=files_of(uploads, 6),
            proof=["Open the upload handler and check for type, size and filename handling."],
            fix="Confirm all three controls are in place.",
            steps=["Check the FILE UPLOAD recipe in `fix-recipes.md` against what you have."],
            automate="agent", breaks="Nothing.",
            verify="Upload a disallowed file type and confirm rejection.",
            recipe="FILE UPLOAD",
        )

    # ---- 3. secrets compiled into the browser bundle ----------------------
    pub = L("public_env_secrets")
    if pub:
        O.add(
            "critical",
            "Secret keys are being compiled into your website's JavaScript",
            """Environment variables with a public prefix — `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`
            and friends — are deliberately baked into the JavaScript bundle that every visitor
            downloads. That is what the prefix means. These ones have names like SECRET, KEY or
            TOKEN, which means the secret is not secret: anyone can press F12 and read it. This
            catches people constantly because the app works perfectly, so nothing looks wrong.""",
            domain="code",
            where=files_of(pub),
            proof=["Open your deployed site, press F12, search the JS bundle for the key name.",
                   "Or: grep -r 'NEXT_PUBLIC_.*SECRET' in your build output."],
            fix="Rotate the keys, then move them server-side.",
            steps=[
                "**Rotate every key listed. Assume they are public — they are.**",
                "Decide whether each value is genuinely public (an anon key, a publishable key, "
                "a project URL — those are fine) or actually secret.",
                "For genuinely secret values: remove the public prefix and read them only in "
                "server code — API routes, server actions, server components, a backend.",
                "If the browser needs the result of something secret, put it behind your own "
                "API route so the key stays on the server.",
                "Rebuild and confirm the key no longer appears anywhere in the bundle.",
            ],
            automate="agent",
            breaks="Client code referencing the old variable will break — that is the point. Move the "
                   "call server-side rather than putting the prefix back.",
            verify="grep -r 'SECRET\\|SERVICE_ROLE' .next/static dist build 2>/dev/null | wc -l  # want 0",
            recipe="SECRETS AND ENVIRONMENT",
        )

    # ---- 4. Supabase service_role in client-reachable code ----------------
    svc = L("supabase_service_key")
    if svc:
        client_side = [x for x in svc if re.search(r"(^|/)(src|app|pages|components|lib|client)/", str(x))
                       and not re.search(r"/(api|server|actions)/", str(x))]
        O.add(
            "critical" if client_side else "high",
            "Your Supabase service role key appears in application code",
            """The service role key bypasses every Row Level Security policy you have. It is the
            master key to your entire database — read, write and delete on every table, for every
            user. It is meant to live only on a server. If it reaches the browser, anyone can read
            and delete all of your data, and Row Level Security will not stop them because the
            service role is specifically designed to ignore it.""",
            domain="code",
            where=files_of(svc),
            proof=["Check whether the file above runs in the browser or on the server.",
                   "If it is imported by a client component, the key is in your bundle."],
            fix="Rotate the key immediately, then use it only in server-side code.",
            steps=[
                "**Rotate the service role key in your Supabase dashboard now** "
                "(Settings → API → service_role → reset). Everything else is secondary.",
                "In the browser, use only the `anon` key, and rely on Row Level Security.",
                "Use the service role key only in server code — API routes, server actions, edge "
                "functions — and store it as a variable WITHOUT a public prefix.",
                "Confirm Row Level Security is actually enabled on every table. With the anon key "
                "and RLS off, your data is public anyway.",
                "Rebuild and search the bundle for the key to confirm it is gone.",
            ],
            automate="agent",
            breaks="Client code using the service key will lose access — correct. Move it to a server route.",
            verify="Search your built bundle for 'service_role'. Expect zero hits.",
            recipe="SUPABASE AND FIREBASE",
        )

    # ---- 5. Firebase rules wide open ---------------------------------------
    fb = [x for x in L("firebase_rules") if not str(x).startswith("###")]
    if fb:
        O.add(
            "critical",
            "Your Firebase rules let anyone read and write your database",
            """`allow read, write: if true` means exactly that — anyone on the internet with your
            project ID can read every document and delete every document. They do not need your
            app, a login, or any credential. Firebase project IDs are in your client bundle, so
            they are not a secret. This is the default that ships with `firebase init`, and it is
            the single most common way a Firebase project gets wiped.""",
            domain="code",
            where=files_of(L("firebase_rules")),
            proof=["Open firestore.rules and look for `if true`."],
            fix="Write rules that check authentication and ownership.",
            steps=[
                "Use the SUPABASE AND FIREBASE recipe in `fix-recipes.md`.",
                "At minimum require a signed-in user: `allow read, write: if request.auth != null;`",
                "Better, require ownership: "
                "`allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;`",
                "Deploy the rules: `firebase deploy --only firestore:rules`",
                "Test with the Firebase rules simulator before and after.",
            ],
            automate="agent",
            breaks="Rules that are too strict break your app's reads. Test each collection after deploying.",
            verify="firebase deploy --only firestore:rules, then try an unauthenticated read.",
            recipe="SUPABASE AND FIREBASE",
        )

    # ---- 6. SQL built by string concatenation -----------------------------
    sql = L("sql_concat")
    if sql:
        O.add(
            "critical",
            "Database queries are built by gluing strings together",
            """When user input is concatenated into a SQL string, the user can change what the
            query does. Typing `' OR 1=1 --` into a login box becomes part of your query and can
            log an attacker in as the first user in your table. The same trick reads other tables,
            and on some setups writes files to the server. The fix is parameterised queries, which
            are also faster and easier to read.""",
            domain="code",
            where=files_of(sql),
            proof=["Open the file and look at how the query string is assembled.",
                   "Try entering  ' OR 1=1 --  into the relevant input on a test environment."],
            fix="Use parameterised queries everywhere. Never build SQL with + or template literals.",
            steps=[
                "Use the SQL INJECTION recipe in `fix-recipes.md`.",
                "Replace each concatenated query with a parameterised one — `?` or `$1` "
                "placeholders with values passed separately.",
                "If you are using an ORM (Prisma, Drizzle, SQLAlchemy, ActiveRecord), use its "
                "query builder rather than its raw-SQL escape hatch.",
                "Search the whole project for the same pattern — where there is one, there are "
                "usually more.",
                "Test that the query still returns what it should.",
            ],
            automate="agent",
            breaks="Nothing if done correctly. Test each query after changing it.",
            verify="grep -rn 'query(.*+\\|query(`.*${' --include='*.js' --include='*.ts' src | wc -l",
            recipe="SQL INJECTION",
        )

    # ---- 7. password handling ----------------------------------------------
    pwcmp = L("password_compare")
    hashing = L("password_hashing")
    if auth_routes and not hashing:
        O.add(
            "critical",
            "There is no password hashing library in this project",
            """You have login routes but nothing that hashes passwords — no bcrypt, argon2, scrypt
            or equivalent. That usually means passwords are stored as plain text or with something
            that is not a password hash. If your database is ever read by anyone, every user's
            password is theirs, and because people reuse passwords, so are their email and bank
            accounts. This is the finding that turns a small breach into a serious one.""",
            domain="code",
            where=files_of(auth_routes, 6),
            proof=["Look at a row in your users table. If you can read the password, it is not hashed."],
            fix="Hash passwords with bcrypt or argon2. Never store or compare them directly.",
            steps=[
                "Use the PASSWORD HANDLING recipe in `fix-recipes.md`.",
                "Install bcrypt (or argon2) and hash on signup with a cost factor of at least 12.",
                "On login, use the library's `compare` function — never `==` or `===`.",
                "For existing users you cannot un-hash anything: hash their password on next "
                "successful login, or force a password reset for everyone.",
                "Never log or email a password, and never send it back in a response.",
            ],
            automate="agent",
            breaks="Existing stored passwords need a migration path — see the recipe.",
            verify="Check a user row in the database. The password should be an unreadable hash.",
            recipe="PASSWORD HANDLING",
        )
    elif pwcmp and not hashing:
        O.add(
            "critical", "Passwords look like they are compared directly instead of hashed",
            """A direct `==` or `===` comparison on a password means the stored value is readable.
            Passwords must be hashed on the way in and verified with the hashing library's own
            compare function.""",
            domain="code", where=files_of(pwcmp),
            proof=["Open the file and look at how the password is checked."],
            fix="Hash on signup, use the library's compare on login.",
            steps=["Use the PASSWORD HANDLING recipe in `fix-recipes.md`."],
            automate="agent", breaks="Existing users need a migration path — see the recipe.",
            verify="Check a user row: the password should be an unreadable hash.",
            recipe="PASSWORD HANDLING",
        )

    # ---- 8. JWT verification weakened ---------------------------------------
    jwt = L("jwt_weak")
    if jwt:
        O.add(
            "critical",
            "Your app accepts login tokens without properly verifying them",
            """Decoding a token is not the same as verifying it. If the signature is not checked —
            or the algorithm is set to `none`, or expiry is ignored — then anyone can write their
            own token saying they are any user, including an admin, and your app will believe it.
            No password required.""",
            domain="code",
            where=files_of(jwt),
            proof=["Open the file and check whether it calls verify (with a secret) or just decode."],
            fix="Always verify the signature, pin the algorithm, and honour expiry.",
            steps=[
                "Use the JWT AND SESSIONS recipe in `fix-recipes.md`.",
                "Replace `decode` with `verify`, passing your secret.",
                "Pin the algorithm explicitly — `{ algorithms: ['HS256'] }` — never accept `none`.",
                "Do not set `ignoreExpiration`.",
                "Make sure your signing secret is long, random, and not committed to the repo.",
            ],
            automate="agent",
            breaks="Tokens issued under the old settings may stop working. Users log in again.",
            verify="Craft a token with a wrong signature and confirm your app rejects it.",
            recipe="JWT AND SESSIONS",
        )

    # ---- 9. CORS -------------------------------------------------------------
    cors = L("cors_config")
    if cors:  # collector emits "file|label" so no source text is ever carried
        wildcard = [x.split("|")[0] for x in cors if str(x).endswith(("|wildcard", "|bare-cors"))]
        creds = [x.split("|")[0] for x in cors if str(x).endswith("|credentials")]
        if wildcard:
            O.add(
                "high" if creds else "medium",
                "Your API accepts requests from any website" + (" and sends cookies with them" if creds else ""),
                """A wildcard CORS policy lets any website on the internet make requests to your API
                from a visitor's browser."""
                + (""" Combined with credentials enabled, that means a malicious page can make
                requests as your logged-in user and read the responses — their session, their data,
                their account. Browsers normally refuse this exact combination, which is a good sign
                it should not be configured."""
                   if creds else
                   """ On its own that is mostly a problem for APIs that should be private."""),
                domain="code",
                where=sorted(set(wildcard + creds))[:10],
                proof=["curl -H 'Origin: https://evil.example' -I https://your-api/endpoint",
                       "Look at the Access-Control-Allow-Origin header that comes back."],
                fix="Replace the wildcard with an explicit list of your own domains.",
                steps=[
                    "Use the CORS recipe in `fix-recipes.md`.",
                    "List your real origins explicitly — your production domain, and localhost "
                    "for development.",
                    "Only enable credentials if you actually use cookie-based auth across origins.",
                    "Never combine `origin: '*'` with `credentials: true` — it does not even work.",
                    "Test from your own frontend that requests still succeed.",
                ],
                automate="agent",
                breaks="If you miss an origin your frontend uses, its requests start failing. List them all.",
                verify="curl -H 'Origin: https://evil.example' -I your-api | grep -i allow-origin",
                recipe="CORS",
            )

    # ---- 10. routes vs auth checks (density signal) --------------------------
    routes, checks = n("route_count"), n("authcheck_count")
    if routes >= 5 and checks == 0:
        O.add(
            "high",
            "Found %d API routes and nothing that checks who is calling them" % routes,
            """shipcheck counted %d route handlers and zero references to any authentication check.
            That may be fine — a fully public API is a legitimate thing. But if any of those routes
            return user data, change data, or do anything an anonymous visitor should not be able
            to do, then right now anyone can call them directly with curl. They do not need to use
            your frontend, and your frontend hiding a button does not stop them.

            This one needs a human eye. Do not bolt authentication onto every route blindly —
            you will break your public endpoints.""" % routes,
            domain="code",
            where=["%d routes found, 0 auth checks" % routes],
            proof=["Pick a route that returns private data and call it directly with curl, "
                   "with no login. If you get data back, it is unprotected."],
            fix="List every route, decide which need authentication, then protect those.",
            steps=[
                "Make a list of every route in the app and mark each one: public, needs login, "
                "or needs a specific role.",
                "Use the AUTH MIDDLEWARE recipe in `fix-recipes.md` to protect the ones that need it.",
                "Default to protected: it is better to have a public endpoint fail once than a "
                "private one leak forever.",
                "For each protected route also check it only returns the CURRENT user's data — "
                "a route that accepts an id and returns that user's record is a hole even when "
                "login is required.",
                "Test each route with curl and no session.",
            ],
            automate="human",
            breaks="Adding auth to a route that should be public breaks your app. Decide per route.",
            verify="curl your private endpoints with no cookie or token and confirm 401.",
            recipe="AUTH MIDDLEWARE",
        )
    elif routes >= 12 and checks and routes / max(checks, 1) > 6:
        O.add(
            "medium",
            "Most of your routes do not appear to check authentication (%d routes, %d checks)" % (routes, checks),
            """There is some authentication in this project, but far more routes than auth checks.
            That ratio usually means a set of endpoints was added later and never protected.
            Worth walking the list.""",
            domain="code",
            where=["%d routes, %d auth checks" % (routes, checks)],
            proof=["List your routes and check each one for a guard."],
            fix="Audit each unprotected route and decide whether it should be public.",
            steps=["Use the AUTH MIDDLEWARE recipe in `fix-recipes.md`.",
                   "Consider applying auth at the router level and opting specific routes out, "
                   "rather than opting each one in — safer default."],
            automate="human",
            breaks="Same as above — decide per route.",
            verify="curl each private endpoint with no session and confirm 401.",
            recipe="AUTH MIDDLEWARE",
        )

    # ---- 11. dangerous execution --------------------------------------------
    dang = L("dangerous_exec")
    if dang:
        O.add(
            "high",
            "Code that runs commands or evaluates strings (%d place%s)" % (len(dang), "" if len(dang) == 1 else "s"),
            """`eval`, `exec`, shell commands and unsafe deserialization are fine when the input is
            yours and dangerous the moment any part of it comes from a user. If a user can
            influence the string, they can run their own code on your server. Each one of these
            needs a look to see where the input comes from.""",
            domain="code",
            where=files_of(dang),
            proof=["Open each location and trace where the input comes from. "
                   "If any part is user-supplied, it is exploitable."],
            fix="Remove it, or make sure nothing user-controlled can reach it.",
            steps=[
                "Use the DANGEROUS FUNCTIONS recipe in `fix-recipes.md`.",
                "For each: trace the input. Hardcoded is fine; user-influenced is not.",
                "Replace shell calls with a library call where one exists.",
                "If a shell call is unavoidable, pass arguments as an array — never build a "
                "command string — and validate each value against an allowlist.",
                "Replace `yaml.load` with `yaml.safe_load`, and never `pickle.loads` untrusted data.",
            ],
            automate="agent",
            breaks="Rewriting a shell call can change behaviour. Test the feature afterwards.",
            verify="Re-run the scan and confirm the remaining hits are all hardcoded input.",
            recipe="DANGEROUS FUNCTIONS",
        )

    # ---- 12. XSS sinks --------------------------------------------------------
    xss = L("xss_sinks")
    if xss:
        O.add(
            "medium",
            "HTML is being inserted without escaping (%d place%s)" % (len(xss), "" if len(xss) == 1 else "s"),
            """`dangerouslySetInnerHTML`, `innerHTML =` and `v-html` insert raw HTML into the page.
            If any of it came from a user, they can insert a script that runs for everyone who
            views it — stealing sessions, or acting as that user. Your framework escapes output by
            default; these are the places that opt out of that protection.""",
            domain="code",
            where=files_of(xss),
            proof=["Open each location and check whether the content can come from a user."],
            fix="Render as text, or sanitise the HTML first.",
            steps=[
                "Use the XSS recipe in `fix-recipes.md`.",
                "If it does not need to be HTML, render it as text — that is the whole fix.",
                "If it must be HTML (a rich text editor), sanitise it with DOMPurify or bleach "
                "before rendering, on the server.",
                "Add a Content-Security-Policy as a second layer — see the SECURITY HEADERS recipe.",
            ],
            automate="agent",
            breaks="Escaping content that was meant to be HTML will show tags as text. Check each case.",
            verify="Enter <script>alert(1)</script> into the relevant field and confirm it displays as text.",
            recipe="XSS",
        )

    # ---- 13. security headers in the app -------------------------------------
    if not L("security_headers_code") and fw:
        O.add(
            "low",
            "No security headers configured in your app",
            """Security headers tell the browser to be stricter — force HTTPS, block your site from
            being framed, stop it guessing file types, limit where scripts can load from. None of
            them fixes a specific bug, but they are close to free, they blunt whole categories of
            attack, and every security questionnaire and automated scanner checks for them.""",
            domain="code",
            where=["no helmet / CSP / HSTS configuration found"],
            proof=["curl -sI https://your-site | grep -iE 'strict-transport|content-security'"],
            fix="Add security headers at the framework level.",
            steps=[
                "Use the SECURITY HEADERS recipe in `fix-recipes.md` for %s." % stack,
                "Start with HSTS, X-Content-Type-Options and Referrer-Policy — these break nothing.",
                "Add Content-Security-Policy last, in report-only mode first, because a strict CSP "
                "will break inline scripts until you have tuned it.",
            ],
            automate="agent",
            breaks="A strict CSP can break inline scripts and third-party widgets. Report-only first.",
            verify="curl -sI https://your-site | grep -ci strict-transport-security",
            recipe="SECURITY HEADERS",
        )

    # ---- 14. CSRF -------------------------------------------------------------
    if L("cookie_calls") and not L("csrf_files") and fw:
        O.add(
            "medium",
            "Cookie-based sessions with no cross-site request protection",
            """Your app sets cookies and shipcheck found no CSRF protection and no SameSite
            handling. Because browsers attach cookies automatically, another website can make a
            request to your app in a logged-in user's browser — submitting a form, changing an
            email, deleting an account — and the request arrives fully authenticated. Modern
            browsers default cookies to SameSite=Lax which blocks the simplest version, but that
            is a default you are relying on rather than a control you set.""",
            domain="code",
            where=files_of(L("cookie_calls"), 8),
            proof=["Check your session cookie's flags in the browser dev tools, Application tab."],
            fix="Set SameSite, HttpOnly and Secure on session cookies, and add CSRF tokens for form posts.",
            steps=[
                "Use the CSRF AND COOKIES recipe in `fix-recipes.md`.",
                "Set `httpOnly: true` (JavaScript cannot read it), `secure: true` (HTTPS only), "
                "`sameSite: 'lax'` on every session cookie.",
                "For state-changing form posts, add CSRF tokens using your framework's built-in "
                "support.",
                "If your API is token-based (Authorization header) rather than cookie-based, CSRF "
                "does not apply — confirm which you are.",
            ],
            automate="agent",
            breaks="`secure: true` stops cookies working over plain HTTP — fine in production, "
                   "check your local dev setup.",
            verify="Inspect the session cookie in dev tools: HttpOnly, Secure and SameSite should be set.",
            recipe="CSRF AND COOKIES",
        )


# --------------------------------------------------------------------------
# PARSER HEALTH — a report must never read "clean" because a check silently broke
# --------------------------------------------------------------------------


def check_health(ev, O):
    rows = {}
    for line in ev.L("shipcheck", "health"):
        parts = str(line).split("|")
        if len(parts) == 3:
            name = parts[0]
            present = parts[1].split("=")[-1] == "1"
            try:
                lines = int(parts[2].split("=")[-1])
            except ValueError:
                lines = 0
            rows[name] = (present, lines)

    # Each entry: (health key, what it blinds us to, severity of not knowing)
    CRITICAL_SOURCES = [
        ("listeners", "what is listening on this server and what the internet can reach",
         "This is the most important part of the whole check."),
        ("sshd_config", "how SSH is configured — password login, root login, key settings", ""),
        ("docker", "your containers — privileged mode, mounted sockets, published ports", ""),
        ("packages", "which security updates are missing", ""),
    ]
    blind = []
    for key, what, extra in CRITICAL_SOURCES:
        if key not in rows:
            continue
        present, lines = rows[key]
        if present and lines == 0:
            blind.append((key, what, extra))

    if blind:
        O.add(
            "high",
            "shipcheck could not read %d thing%s it needs — this report is incomplete"
            % (len(blind), "" if len(blind) == 1 else "s"),
            """Some checks did not run. The tools were installed on this machine, but running them
            returned nothing, so shipcheck is blind in those areas. That is NOT the same as finding
            nothing wrong. Anything this report does not mention about those areas should be
            treated as unknown, not as a pass. Usually this is a permissions problem, or an output
            format shipcheck does not recognise. %s"""
            % " ".join(b[2] for b in blind).strip(),
            domain="server",
            where=["%s — could not read %s" % (b[0], b[1]) for b in blind],
            blind=True,
            proof=["sudo ./shipcheck.sh --out ./rerun   # try again with sudo",
                   "Then check the relevant command by hand, e.g. `sudo ss -tulpn`"],
            fix="Re-run with sudo. If it still returns nothing, report it as a bug.",
            steps=[
                "Re-run shipcheck with `sudo`.",
                "If the problem persists, run the underlying command yourself and see what it "
                "prints: `sudo ss -tulpn`, `sudo sshd -T`, `docker ps`, `apt list --upgradable`.",
                "If the command works by hand but shipcheck sees nothing, that is a shipcheck bug "
                "— please open an issue with the command's output format.",
            ],
            automate="human",
            breaks="Nothing.",
            verify="Re-run and confirm this finding is gone.",
        )

    # a host check that produced no listeners at all is worth its own alarm
    if "listeners" in rows:
        present, lines = rows["listeners"]
        if not present:
            O.add(
                "high",
                "shipcheck could not check what is exposed to the internet",
                """Neither `ss` nor `netstat` is installed on this machine, so shipcheck could not
                see which services are listening or on what addresses. **This report says nothing
                about your internet exposure** — which is normally the most valuable part of it.""",
                domain="server",
                where=["no ss or netstat available"],
                blind=True,
                proof=["which ss netstat"],
                fix="Install iproute2, then re-run.",
                steps=["sudo apt install iproute2   # Debian/Ubuntu",
                       "sudo dnf install iproute    # RHEL family",
                       "Then re-run shipcheck."],
                automate="human", breaks="Nothing.",
                verify="which ss",
            )


# --------------------------------------------------------------------------
# LIVE SITE
# --------------------------------------------------------------------------


def check_site(ev, O):
    site = ev.sec("shipcheck").get("site") or ""
    if not site:
        return

    def code(k):
        v = ev.sec("site").get(k) or ""
        m = re.search(r"(\d{3})", str(v))
        return m.group(1) if m else ""

    if code("git_config_status") == "200":
        O.add(
            "critical",
            "Your .git folder is being served to the internet",
            """Anyone can download your entire source code and full git history from your live
            site, including every secret ever committed. This is a single command for an attacker
            and it is scanned for automatically, constantly. Assume it has already been taken.""",
            domain="site",
            where=["%s/.git/config" % site.rstrip("/")],
            proof=["curl -I %s/.git/config   # returns 200" % site.rstrip("/")],
            fix="Stop the web server from serving the .git directory, and rotate every secret in the repo.",
            steps=[
                "Block it at the web server. nginx: `location ~ /\\.git { deny all; return 404; }`. "
                "Caddy: `@git path /.git/*` then `respond @git 404`. Apache: "
                "`RedirectMatch 404 /\\.git`.",
                "Better: do not deploy the .git directory at all — build artifacts only.",
                "Rotate every credential that has ever been in the repo. Treat it as leaked.",
                "Reload the web server and confirm you get a 404.",
            ],
            automate="human",
            breaks="Nothing.",
            verify="curl -s -o /dev/null -w '%%{http_code}' %s/.git/config   # want 404" % site.rstrip("/"),
        )

    if code("env_status") == "200":
        O.add(
            "critical",
            "Your .env file is downloadable from your website",
            """Your production credentials are being served as a plain file to anyone who asks for
            the URL. Every key in it should be considered public right now.""",
            domain="site",
            where=["%s/.env" % site.rstrip("/")],
            proof=["curl -I %s/.env   # returns 200" % site.rstrip("/")],
            fix="Rotate everything, then move the file out of the web root.",
            steps=[
                "Rotate EVERY key in that file immediately. This is the urgent part.",
                "Move .env outside the directory your web server serves from.",
                "Add a web server rule denying dotfiles: nginx `location ~ /\\. { deny all; }`.",
                "Confirm the URL returns 404.",
            ],
            automate="human",
            breaks="Nothing.",
            verify="curl -s -o /dev/null -w '%%{http_code}' %s/.env   # want 404" % site.rstrip("/"),
        )

    listing = str(ev.sec("site").get("directory_listing") or "0").strip()
    if listing.isdigit() and int(listing) > 0:
        O.add("medium", "Directory listing is turned on",
              """Your web server shows a browsable file index instead of a page. That hands
              anyone a complete map of what is on the server, including backups, old versions and
              files you forgot were there.""",
              domain="site", where=[site],
              proof=["curl %s/ | grep -i 'index of'" % site.rstrip("/")],
              fix="Turn off automatic directory indexes.",
              steps=["nginx: `autoindex off;` · Apache: `Options -Indexes` · Caddy: remove `file_server browse`."],
              automate="human", verify="curl -s %s/ | grep -ci 'index of'" % site.rstrip("/"))

    hdrs = "\n".join(ev.L("site", "headers"))
    if hdrs.strip():
        missing = []
        for name, why in [
            ("strict-transport-security", "browsers can be tricked into using plain HTTP"),
            ("content-security-policy", "no defence-in-depth against cross-site scripting"),
            ("x-content-type-options", "browsers may guess file types and run the wrong thing"),
            ("x-frame-options", "your site can be framed for clickjacking (or use CSP frame-ancestors)"),
        ]:
            if name not in hdrs.lower():
                missing.append("%s — %s" % (name, why))
        if missing:
            O.add("low", "Missing security headers (%d)" % len(missing),
                  """These headers tell the browser to be stricter. None of them fixes a real bug on
                  their own, but they are free, they take one config block, and every automated
                  scanner and customer security questionnaire checks for them.""",
                  domain="site", where=missing,
                  proof=["curl -sI %s" % site],
                  fix="Add the headers at your reverse proxy or framework.",
                  steps=["Add to nginx/Caddy or your framework's header middleware:",
                         "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                         "X-Content-Type-Options: nosniff",
                         "Content-Security-Policy: start with `default-src 'self'` and loosen as needed",
                         "Referrer-Policy: strict-origin-when-cross-origin"],
                  automate="agent",
                  breaks="A strict CSP can break inline scripts — add it in report-only mode first.",
                  verify="curl -sI %s | grep -ci strict-transport" % site)

        srv = re.search(r"^server:\s*(.+)$", hdrs, re.I | re.M)
        if srv and re.search(r"\d", srv.group(1)):
            O.add("low", "Your web server is announcing its exact version",
                  """Every response tells attackers which software and version you run, so they can
                  go straight to the exploits that work on it. Free to turn off.""",
                  domain="site", where=[srv.group(1).strip()],
                  proof=["curl -sI %s | grep -i ^server" % site],
                  fix="Hide the version banner.",
                  steps=["nginx: `server_tokens off;` · Apache: `ServerTokens Prod` and `ServerSignature Off`."],
                  automate="human", verify="curl -sI %s | grep -i ^server" % site)

    tls = "\n".join(ev.L("site", "tls"))
    m = re.search(r"notAfter=(.+)", tls)
    if m:
        try:
            from email.utils import parsedate_to_datetime
            exp = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                O.add("critical", "Your HTTPS certificate has expired",
                      """Every visitor gets a full-page browser warning telling them your site is
                      unsafe. Most will leave.""",
                      domain="site", where=["expired %d days ago" % -days],
                      proof=["echo | openssl s_client -connect yoursite:443 | openssl x509 -noout -dates"],
                      fix="Renew the certificate now.",
                      steps=["`sudo certbot renew --force-renewal` then reload the web server.",
                             "Then find out why auto-renewal did not run: `systemctl status certbot.timer`."],
                      automate="human", verify="curl -sI https://yoursite >/dev/null && echo ok")
            elif days < 21:
                O.add("high", "Your HTTPS certificate expires in %d days" % days,
                      """Renewal has not happened yet. If auto-renewal is broken, your site will start
                      showing browser security warnings to every visitor on that day.""",
                      domain="site", where=["expires in %d days" % days],
                      proof=["echo | openssl s_client -connect yoursite:443 | openssl x509 -noout -dates"],
                      fix="Renew now and fix auto-renewal.",
                      steps=["`sudo certbot renew` and reload the web server.",
                             "Check the renewal timer is enabled: `systemctl is-enabled certbot.timer`."],
                      automate="human", verify="systemctl is-enabled certbot.timer")
        except Exception:
            pass


# --------------------------------------------------------------------------
# SERVER
# --------------------------------------------------------------------------


def check_server(ev, O):
    if not ev.B("shipcheck", "checked_host"):
        return
    ls = listeners(ev)
    fw_text = "\n".join(ev.L("network", "fw_active"))
    ufw = "\n".join(ev.L("network", "ufw"))
    nft = "\n".join(ev.L("network", "nft"))
    ipt = "\n".join(ev.L("network", "iptables"))
    ipt6 = "\n".join(ev.L("network", "ip6tables"))
    fw_on = ("=active" in fw_text and "ufw=active" in fw_text) or "Status: active" in ufw \
        or "running" in "\n".join(ev.L("network", "firewalld")) or bool(nft.strip()) or bool(ipt.strip())
    deny = bool(re.search(r"policy drop", nft, re.I) or re.search(r"^:INPUT DROP", ipt, re.M)
                or "Default: deny (incoming)" in ufw)
    has_v6 = bool([x for x in ev.L("network", "ipv6_global") if "inet6" in x])
    pub4 = (ev.sec("network").get("public_ip4") or "").strip()

    if not fw_on:
        O.add("high", "There is no firewall running on this server",
              """Nothing filters incoming connections. Every service listening on this machine is
              reachable by whatever the network allows, and the only thing protecting each one is
              its own password. Installing something today does not mean it is protected tomorrow —
              the next thing you run will be exposed the moment it starts.""",
              domain="server", where=["no ufw, nftables, firewalld or iptables rules"],
              proof=["sudo ufw status", "sudo iptables -S"],
              fix="Turn on a default-deny firewall that allows only what you actually serve.",
              steps=["Decide which ports must be public — usually 22 (SSH), 80 and 443 only.",
                     "sudo ufw default deny incoming",
                     "sudo ufw default allow outgoing",
                     "sudo ufw allow 22/tcp   # do this BEFORE enabling, or you lose SSH",
                     "sudo ufw allow 80,443/tcp",
                     "sudo ufw enable",
                     "Open a SECOND terminal and confirm you can still SSH in before closing this one."],
              automate="human",
              breaks="Getting this wrong locks you out of your own server. Never run it blind.",
              verify="sudo ufw status verbose")

    if has_v6 and re.search(r"IPV6\s*=\s*no", ev.T("network", "ufw_ipv6") or "", re.I):
        O.add("high", "Your firewall is not filtering IPv6 at all",
              """This server has a public IPv6 address, and ufw is configured with IPv6 disabled.
              `ufw status` says active, and it is — for IPv4 only. Everything listening here is
              reachable over IPv6 with no filtering. This is the most common reason a "firewalled"
              server turns out to be wide open.""",
              domain="server", where=["/etc/default/ufw — IPV6=no"],
              proof=["grep IPV6 /etc/default/ufw", "ip -6 addr show scope global"],
              fix="Turn IPv6 on in ufw and reload.",
              steps=["sudo sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw",
                     "sudo ufw disable && sudo ufw enable   # required for it to take effect",
                     "Confirm from a second terminal that you can still SSH in."],
              automate="human",
              breaks="Reloading ufw briefly drops the ruleset. Keep a session open.",
              verify="grep -c '^IPV6=yes' /etc/default/ufw")
    elif has_v6 and ipt.strip() and not ipt6.strip() and "inet " not in nft:
        O.add("high", "Your firewall rules cover IPv4 only, but the server has a public IPv6 address",
              """You have iptables rules and no ip6tables rules. Half your attack surface is
              unfiltered. Anything bound to `::` — which on Linux is most things — is reachable
              from the internet over IPv6 regardless of what your IPv4 rules say.""",
              domain="server", where=["ip6tables has no rules"],
              proof=["sudo ip6tables -S", "ip -6 addr show scope global"],
              fix="Mirror your rules to IPv6, or switch to a single nftables `inet` table.",
              steps=["Easiest: use ufw, which handles both families.",
                     "Otherwise write the same rules into ip6tables and persist them."],
              automate="human", verify="sudo ip6tables -S | wc -l")

    # Docker punching through ufw
    pub_containers = [x for x in ev.L("containers", "inspect") if re.search(r"ports=.*0\.0\.0\.0", x)]
    if pub_containers and "ufw=active" in fw_text:
        O.add("high", "Docker is bypassing your firewall",
              """Docker writes its own network rules that run before ufw's, so a container port
              published with `-p 8080:8080` is open to the internet even though `ufw status` says
              that port is blocked. This surprises almost everyone, and it is how self-hosted
              admin panels end up public.""",
              domain="server",
              where=[x.split("|")[0].lstrip("/") for x in pub_containers[:8]],
              proof=["docker ps --format '{{.Names}}\\t{{.Ports}}'",
                     "sudo ufw status   # shows the port as blocked",
                     "From your phone on cellular: nc -vz %s <port>   # connects anyway" % (pub4 or "<your public IP>")],
              fix="Publish container ports to 127.0.0.1 only, and put a reverse proxy in front.",
              steps=["In docker-compose.yml change `- \"8080:8080\"` to `- \"127.0.0.1:8080:8080\"` "
                     "for anything that should not be public.",
                     "Run `docker compose up -d` to apply.",
                     "If it needs to be public, put nginx/Caddy in front on 443 and proxy to the "
                     "loopback port — then you get TLS and access control too.",
                     "Verify from outside your network that the port no longer answers."],
              automate="agent",
              breaks="Anything connecting to that port directly from another machine will stop working.",
              verify="docker ps --format '{{.Ports}}' | grep -c '0.0.0.0'")

    # listening services
    seen = set()
    for l in ls:
        if l["addr"].startswith("127.") or l["addr"] in ("::1",):
            continue
        if l["port"] in seen or l["port"] not in PORTS:
            continue
        seen.add(l["port"])
        label, sev = PORTS[l["port"]]
        if fw_on and deny and sev in ("critical", "high"):
            sev = {"critical": "high", "high": "medium"}[sev]
            note = " Your firewall is set to deny by default, so this may not be reachable from " \
                   "the internet — confirm with the external check before panicking."
        else:
            note = ""
        O.add(sev, "%s is listening on a public network address" % label,
              """%s is bound to %s rather than to localhost, so it accepts connections from the
              network rather than only from programs on this machine. Databases and caches are the
              things attackers scan for constantly, because so many are left open with no
              password.%s""" % (label, l["addr"] or "all interfaces", note),
              domain="server",
              where=["%s on %s:%s" % (l["proc"] or label, l["addr"], l["port"])],
              proof=["sudo ss -tulpn | grep ':%s'" % l["port"],
                     "From outside your network: nc -vz %s %s" % (pub4 or "<your public IP>", l["port"])],
              fix="Bind it to 127.0.0.1 so only this machine can reach it.",
              steps=["Find the bind setting in that service's config and set it to 127.0.0.1 "
                     "(Redis: `bind 127.0.0.1`, Postgres: `listen_addresses = 'localhost'`, "
                     "MySQL: `bind-address = 127.0.0.1`, MongoDB: `bindIp: 127.0.0.1`).",
                     "If it runs in Docker, change the published port to `127.0.0.1:%s:%s`." % (l["port"], l["port"]),
                     "Restart the service and confirm your app still connects.",
                     "Also block the port at the firewall as a second layer."],
              automate="human",
              breaks="Anything connecting to it from another machine will stop working.",
              verify="ss -tlnp | grep ':%s'" % l["port"])

    # Redis with no password
    redis = "\n".join(ev.L("data_services", "redis"))
    if redis.strip():
        parts = [p.strip() for p in redis.splitlines()]
        try:
            i = parts.index("requirepass")
            if i + 1 >= len(parts) or not parts[i + 1]:
                O.add("high", "Redis has no password set",
                      """Redis accepts commands from anyone who can reach it, with no credential at
                      all. If it is also reachable from the network, an attacker can read every
                      session and cached item — and on many setups can write a file to disk and get
                      a shell on the server.""",
                      domain="server", where=["redis — requirepass is empty"],
                      proof=["redis-cli CONFIG GET requirepass"],
                      fix="Set a password, and bind Redis to localhost.",
                      steps=["Generate a long random password.",
                             "Add `requirepass <password>` to /etc/redis/redis.conf.",
                             "Set `bind 127.0.0.1 -::1` in the same file.",
                             "Add the password to your app's connection string at the same time — "
                             "otherwise the app breaks the moment Redis restarts.",
                             "sudo systemctl restart redis-server"],
                      automate="human",
                      breaks="Your app loses its Redis connection until you update its config too.",
                      verify="redis-cli CONFIG GET requirepass")
        except ValueError:
            pass

    hba = [x for x in ev.L("data_services", "postgres_hba") if re.search(r"\btrust\b", x)]
    if hba:
        O.add("high", "PostgreSQL is set to let connections in with no password",
              """A `trust` line in pg_hba.conf means anything matching it connects to your database
              with no credential whatsoever.""",
              domain="server", where=[x.strip() for x in hba[:5]],
              proof=["grep -v '^#' /etc/postgresql/*/main/pg_hba.conf | grep trust"],
              fix="Change every `trust` to `scram-sha-256`.",
              steps=["Edit pg_hba.conf and replace `trust` with `scram-sha-256`.",
                     "Make sure your app's database user actually has a password set.",
                     "sudo systemctl reload postgresql"],
              automate="human",
              breaks="Anything relying on passwordless local connections stops working.",
              verify="grep -c trust /etc/postgresql/*/main/pg_hba.conf")

    # SSH
    cfg = sshd(ev)
    ssh_public = any(l["port"] == "22" and not l["addr"].startswith("127.") for l in ls)
    fails = (ev.sec("ssh").get("failed_logins_7d") or "").strip()
    fails_n = int(re.search(r"\d+", fails).group()) if re.search(r"\d+", fails or "") else 0

    if cfg.get("passwordauthentication") == "yes":
        vivid = ""
        if fails_n > 100:
            vivid = (" In the last 7 days there have been %s failed login attempts on this server. "
                     "That is people actively trying passwords right now." % f"{fails_n:,}")
        O.add("medium" if not ssh_public else "high",
              "SSH lets people log in with a password",
              """Anyone on the internet can try to guess your password, forever, with no limit.
              Bots do this to every server with port 22 open, continuously, from the moment it comes
              online.%s Switching to key-only login removes the entire category.""" % vivid,
              domain="server", where=["sshd — PasswordAuthentication yes"],
              proof=["sudo sshd -T | grep -i passwordauth"],
              fix="Set up an SSH key, confirm it works, then turn passwords off.",
              steps=["On YOUR computer: `ssh-keygen -t ed25519` if you do not already have a key.",
                     "Copy it up: `ssh-copy-id you@server`.",
                     "Test it in a NEW terminal: `ssh you@server` should log in without a password.",
                     "Only if that worked, on the server: create "
                     "/etc/ssh/sshd_config.d/60-hardening.conf containing "
                     "`PasswordAuthentication no` and `KbdInteractiveAuthentication no`.",
                     "sudo sshd -t   (must print nothing)",
                     "sudo systemctl reload ssh",
                     "KEEP YOUR CURRENT SESSION OPEN and log in from a second terminal to confirm."],
              automate="human",
              breaks="Gets you locked out permanently if your key does not work. Do the test first.",
              verify="sudo sshd -T | grep passwordauthentication")

    if cfg.get("permitrootlogin") == "yes":
        O.add("high", "You can log in as root over SSH",
              """`root` is the account every bot tries first, and it is the one account where a
              successful guess means total control. It also means nothing in your logs shows WHO
              did what — every action is just "root".""",
              domain="server", where=["sshd — PermitRootLogin yes"],
              proof=["sudo sshd -T | grep -i permitrootlogin"],
              fix="Log in as a normal user and use sudo.",
              steps=["Confirm you have a non-root account that can SSH in AND run sudo.",
                     "Create /etc/ssh/sshd_config.d/60-hardening.conf with "
                     "`PermitRootLogin prohibit-password`.",
                     "sudo sshd -t && sudo systemctl reload ssh",
                     "Verify from a second terminal before closing this one."],
              automate="human",
              breaks="If root is your only way in, this locks you out. Check first.",
              verify="sudo sshd -T | grep permitrootlogin")

    bad_keyperm = [x for x in ev.L("ssh", "host_key_perms")
                   if re.match(r"^\d{3}\s", x) and not re.match(r"^(600|640)\s", x)]
    if bad_keyperm:
        O.add("high", "Your server's SSH private keys can be read by other users",
              """These are the keys that prove this server is this server. Anyone who can read them
              can impersonate it and intercept connections from anyone who trusts it.""",
              domain="server", where=bad_keyperm,
              proof=["stat -c '%a %n' /etc/ssh/ssh_host_*_key"],
              fix="Set them back to owner-only.",
              steps=["chmod 600 /etc/ssh/ssh_host_*_key"],
              automate="safe", breaks="Nothing.",
              verify="stat -c %a /etc/ssh/ssh_host_ed25519_key",
              auto={"kind": "chmod", "mode": "600",
                    "paths": [x.split(None, 2)[-1] for x in bad_keyperm]})

    # accounts
    uid0 = [x for x in ev.L("accounts", "uid0") if x.strip()]
    if len(uid0) > 1:
        O.add("high", "More than one account has full root powers",
              """These accounts all have user ID 0, which means each one is root with a different
              name. Extra root accounts are a classic way for a backdoor to hide in plain sight,
              and they make your logs useless for working out who did what.""",
              domain="server", where=uid0,
              proof=["awk -F: '$3==0 {print $1}' /etc/passwd"],
              fix="Work out who owns each one and remove the extras.",
              steps=["Identify the owner and purpose of every account listed.",
                     "If you cannot explain one, treat this as a possible compromise, not a config issue.",
                     "Give real people normal accounts with sudo instead."],
              automate="human", breaks="Deleting an account in use locks that person out.",
              verify="awk -F: '$3==0' /etc/passwd | wc -l")

    nopw = [x for x in ev.L("accounts", "sudoers") if "NOPASSWD" in x and re.search(r"ALL\s*$", x)]
    if nopw:
        O.add("high", "An account can become root with no password at all",
              """A `NOPASSWD: ALL` sudo rule means anything that reaches that account is instantly
              root — a stolen SSH key, a compromised app running as that user, a hijacked CI job.
              There is no second check.""",
              domain="server", where=[x.strip()[:120] for x in nopw[:6]],
              proof=["sudo grep -rh NOPASSWD /etc/sudoers /etc/sudoers.d/"],
              fix="Require a password for sudo, or scope the rule to exact commands.",
              steps=["Decide whether this was for automation or convenience.",
                     "For convenience: remove the NOPASSWD and type your password.",
                     "For automation: restrict the rule to the exact command with a full path, "
                     "not ALL.",
                     "Always edit with `sudo visudo` — a syntax error there locks out sudo entirely."],
              automate="human", breaks="Automation relying on passwordless sudo stops working.",
              verify="sudo grep -c NOPASSWD /etc/sudoers /etc/sudoers.d/* 2>/dev/null")

    docker_grp = ev.sec("accounts").get("docker_group") or ""
    members = docker_grp.split(":")[-1].strip() if ":" in docker_grp else ""
    if members:
        O.add("medium", "Being in the docker group is the same as being root",
              """Anyone in the `docker` group can start a container that mounts your whole
              filesystem and edit anything on it. It is full root access that does not appear in
              sudo logs. That may be fine — just know that is what it means.""",
              domain="server", where=[m for m in members.split(",") if m],
              proof=["getent group docker"],
              fix="Treat docker group membership with the same care as root access.",
              steps=["Remove anyone who does not need it: `sudo gpasswd -d <user> docker`.",
                     "For a real fix, look at rootless Docker or Podman."],
              automate="human", breaks="Removing someone breaks their docker commands.",
              verify="getent group docker")

    # containers
    inspect = [x for x in ev.L("containers", "inspect") if x.strip()]
    priv = [x for x in inspect if "priv=true" in x]
    sock = [x for x in inspect if "docker.sock" in x]
    if priv or sock:
        O.add("critical", "A container has full control of the server",
              """%s%s Either way, anything that compromises the app inside that container owns the
              whole machine — not just the container. This is the single biggest self-hosting
              mistake."""
              % ("One or more containers run in privileged mode, which removes every isolation "
                 "boundary Docker provides. " if priv else "",
                 "One or more containers have the Docker socket mounted, which lets them start "
                 "new containers with your whole filesystem attached. " if sock else ""),
              domain="server",
              where=[x.split("|")[0].lstrip("/") for x in (priv + sock)[:8]],
              proof=["docker inspect <name> --format '{{.HostConfig.Privileged}}'",
                     "docker inspect <name> --format '{{range .Mounts}}{{.Source}} {{end}}'"],
              fix="Remove `privileged: true` and the docker.sock mount unless you genuinely need them.",
              steps=["Find why it was added. Usually it was to make one thing work once.",
                     "Remove `privileged: true` from docker-compose.yml and try again — most "
                     "containers do not need it.",
                     "If it needs one specific capability, add just that with `cap_add`.",
                     "If a management UI needs the socket, put a socket proxy in front of it with "
                     "a restricted allowlist, and do not expose that UI to the internet.",
                     "docker compose up -d and confirm the app still works."],
              automate="agent",
              breaks="The container may fail to start if it really needed that access.",
              verify="docker ps -q | xargs -r docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}'")

    ds = ev.sec("containers").get("socket") or ""
    if re.search(r"^srw-rw-rw-", ds):
        O.add("critical", "The Docker socket is writable by everyone on the server",
              """Every account on this machine can control Docker, which means every account is
              effectively root.""",
              domain="server", where=["/var/run/docker.sock"],
              proof=["ls -l /var/run/docker.sock"],
              fix="Restore the normal permissions.",
              steps=["sudo chmod 660 /var/run/docker.sock"],
              automate="safe", breaks="Nothing that should exist.",
              verify="stat -c %a /var/run/docker.sock",
              auto={"kind": "chmod", "mode": "660", "paths": ["/var/run/docker.sock"]})

    # patching
    upg = [x for x in ev.L("patching", "upgradable") if x.strip() and "Listing" not in x]
    sec_upg = [x for x in upg if re.search(r"security", x, re.I)]
    if sec_upg:
        O.add("high" if len(sec_upg) > 5 else "medium",
              "%d security updates are waiting to be installed" % len(sec_upg),
              """Each of these is a hole someone already found, published, and wrote a fix for.
              Attack tools are built from exactly this list, because it tells them what to try.
              This is the cheapest security work that exists.""",
              domain="server", where=sec_upg[:10],
              proof=["apt list --upgradable | grep -i security"],
              fix="Install them, then turn on automatic security updates so it does not happen again.",
              steps=["sudo apt update && sudo apt upgrade -y",
                     "Reboot if it tells you to.",
                     "Then turn on automatic security updates: "
                     "`sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`"],
              automate="human",
              breaks="Services restart during the upgrade. Do it when a short blip is fine.",
              verify="apt list --upgradable 2>/dev/null | grep -ci security")

    if ev.B("patching", "reboot_required"):
        O.add("medium", "The server needs a reboot to finish applying updates",
              """Updates are installed on disk, but the running kernel and libraries are still the
              old, vulnerable ones. The server is patched on paper and unpatched in memory.""",
              domain="server", where=["/var/run/reboot-required"],
              proof=["cat /var/run/reboot-required"],
              fix="Reboot when you can afford a minute of downtime.",
              steps=["sudo reboot", "Confirm your services came back up afterwards."],
              automate="human", breaks="A minute or two of downtime.",
              verify="[ -f /var/run/reboot-required ] && echo still-needed || echo done")

    kp = "\n".join(ev.L("patching", "key_packages"))
    nr = re.search(r"^needrestart\s+(\d+)\.(\d+)", kp, re.M)
    if nr and (int(nr.group(1)), int(nr.group(2))) < (3, 8):
        O.add("high", "The `needrestart` package on this server has a known root exploit",
              """needrestart runs automatically every time you install a package. Versions below
              3.8 can be tricked by any other user on the machine into giving them root — triggered
              by you running a routine `apt install`. It comes preinstalled on Ubuntu Server.""",
              domain="server", where=["needrestart %s.%s" % (nr.group(1), nr.group(2))],
              proof=["dpkg -l needrestart | tail -1"],
              fix="Update it.",
              steps=["sudo apt update && sudo apt install --only-upgrade needrestart"],
              automate="human", breaks="Nothing.",
              verify="dpkg -l needrestart | tail -1")

    auto = "\n".join(ev.L("patching", "auto_updates"))
    if "enabled" not in auto:
        O.add("medium", "Security updates are not installed automatically",
              """Right now, patching depends on you remembering. Over a year that means months
              where a published, fixable hole stays open on your server. Turning this on is a
              two-minute job that keeps working forever.""",
              domain="server", where=["unattended-upgrades not enabled"],
              proof=["systemctl is-enabled unattended-upgrades"],
              fix="Turn on automatic security updates.",
              steps=["sudo apt install unattended-upgrades",
                     "sudo dpkg-reconfigure -plow unattended-upgrades   # answer Yes",
                     "Leave automatic reboot OFF so it never restarts you unexpectedly."],
              automate="human", breaks="A service may restart when a package updates.",
              verify="systemctl is-enabled unattended-upgrades")

    osr = "\n".join(ev.L("system", "os_release"))
    for name, when in [("Ubuntu 20.04", "May 2025"), ("Ubuntu 18.04", "May 2023"),
                       ("Ubuntu 25.10", "July 2026"), ("Ubuntu 25.04", "January 2026"),
                       ("Debian GNU/Linux 10", "June 2024"), ("CentOS Linux 7", "June 2024")]:
        if name.replace("GNU/Linux ", "") in osr or name in osr:
            O.add("high", "This server runs %s, which stopped getting security updates in %s" % (name, when),
                  """New security holes found from here on will never be fixed on this version. This
                  is not a setting you can change — the operating system needs upgrading, or you need
                  a paid extended-support subscription.""",
                  domain="server", where=[name],
                  proof=["cat /etc/os-release"],
                  fix="Upgrade to a supported release, or subscribe to extended support.",
                  steps=["Back up first. This is the one change that can genuinely break everything.",
                         "Ubuntu: `sudo do-release-upgrade` (or rebuild on a new server and migrate — "
                         "usually cleaner).",
                         "Cheaper stopgap on Ubuntu: `sudo pro attach` — Ubuntu Pro is free for up to "
                         "5 machines for personal use and includes extended security updates."],
                  automate="human", breaks="An OS upgrade is a project. Snapshot first.",
                  verify="cat /etc/os-release | head -2")
            break

    # backups
    tools = (ev.sec("resilience").get("backup_tools") or "").strip()
    sched = [x for x in ev.L("resilience", "backup_schedule") if x.strip()]
    if not tools and not sched:
        O.add("high", "There are no backups running on this server",
              """No backup tool is installed and nothing is scheduled. If this server is
              ransomwared, deleted, or the disk fails, everything on it is gone. Provider snapshots
              taken with the same account that runs the server do not count for ransomware —
              whoever gets in can delete those too.""",
              domain="server", where=["no restic, borg, kopia or scheduled backup found"],
              proof=["systemctl list-timers | grep -i backup", "crontab -l"],
              fix="Set up automated backups to somewhere this server cannot delete from.",
              steps=["Pick a destination that is not this server — Backblaze B2, S3, or a NAS.",
                     "Install restic or borg and schedule a daily backup with a systemd timer.",
                     "Use append-only credentials so a compromised server cannot wipe the backups. "
                     "This is the part that matters against ransomware.",
                     "Actually restore one file, once. An untested backup is not a backup."],
              automate="human", breaks="Nothing. Costs a few dollars a month.",
              verify="systemctl list-timers | grep -ci backup")

    if not (ev.sec("resilience").get("persistent_logs") or "").strip():
        O.add("low", "Logs are wiped every time the server reboots",
              """The system journal is kept in memory only. If something goes wrong and the server
              restarts, the record of what happened is gone — including the reboot an attacker
              causes.""",
              domain="server", where=["/var/log/journal does not exist"],
              proof=["ls -d /var/log/journal"],
              fix="Make the journal persistent.",
              steps=["Create /var/log/journal and set Storage=persistent in journald.conf."],
              automate="safe", breaks="Uses some disk. Capped at 1GB by the fix.",
              verify="[ -d /var/log/journal ] && echo yes",
              auto={"kind": "journald_persistent"})

    # cheap kernel wins
    sc = {}
    for line in ev.L("resilience", "sysctl"):
        if "=" in line:
            k, _, v = line.partition("=")
            sc[k.strip()] = v.strip()
    want = [("kernel.kptr_restrict", "2"), ("kernel.dmesg_restrict", "1"),
            ("fs.protected_symlinks", "1"), ("fs.protected_hardlinks", "1"),
            ("fs.protected_fifos", "2"), ("fs.protected_regular", "2"),
            ("fs.suid_dumpable", "0"), ("net.ipv4.tcp_syncookies", "1"),
            ("net.ipv4.conf.all.accept_redirects", "0"),
            ("net.ipv4.conf.all.send_redirects", "0"),
            ("net.ipv4.conf.all.accept_source_route", "0"),
            ("net.ipv4.conf.all.log_martians", "1"),
            ("net.ipv6.conf.all.accept_redirects", "0"),
            ("net.ipv6.conf.all.accept_source_route", "0")]
    dev = [(k, sc[k], v) for k, v in want if k in sc and sc[k] != v]
    if dev:
        O.add("low", "%d kernel hardening settings are at their default values" % len(dev),
              """These do not fix a specific bug. They make the server harder to exploit if
              something else goes wrong — the security equivalent of wearing a seatbelt. They are
              free, reversible, and none of them will break anything on a normal server.""",
              domain="server", where=["%s is %s, should be %s" % (k, c, w) for k, c, w in dev],
              proof=["sysctl kernel.kptr_restrict fs.protected_symlinks"],
              fix="Write the recommended values to /etc/sysctl.d/60-shipcheck.conf.",
              steps=["The fix script does this for you."],
              automate="safe", breaks="Nothing on a normal server.",
              verify="sysctl -n kernel.kptr_restrict",
              auto={"kind": "sysctl", "values": [[k, w] for k, _, w in dev]})

    loose = [x for x in ev.L("resilience", "loose_secret_files")
             if re.match(r"^[0-7]?[0-7][0-7][1-7]\s|^[0-7]?[0-7][4-7][0-7]\s", x)]
    loose = [x for x in loose if not re.search(r"(fullchain|/certs?/|cert\.pem|ca-bundle)", x, re.I)]
    # Split by whether tightening the file can break a running service.
    # Only root-owned files under /root and /etc are provably safe to chmod blind.
    root_only = [x for x in loose if re.search(r"\s(/root/|/etc/)", x)]
    service_side = [x for x in loose if x not in root_only]

    if root_only:
        O.add("high", "Private keys and credentials in root's home can be read by other accounts (%d)"
              % len(root_only),
              """These are private keys or credential files under /root or /etc that accounts other
              than root can read. Only root should ever need them, so tightening them cannot break
              anything — and leaving them means any other account on this box, including a
              compromised service, reads them with no exploit required.""",
              domain="server", where=root_only[:15],
              proof=["stat -c '%a %U:%G %n' <each file>"],
              fix="Restrict them to root only.",
              steps=["chmod 600 on each file listed. The fix script does this."],
              automate="safe",
              breaks="Nothing — root reads these as root either way.",
              verify="stat -c %a <file>",
              auto={"kind": "chmod", "mode": "600",
                    "paths": [x.split(None, 2)[-1] for x in root_only[:15]]})

    if service_side:
        O.add("high", "Application credential files can be read by other accounts (%d)" % len(service_side),
              """These .env files and credential stores live in application directories and can be
              read by accounts other than their owner. Any other service on this box — or anything
              that compromises one — reads your database password and API keys without needing a
              single exploit.

              This is NOT in the fix script, deliberately. The right permission depends on which
              user your app actually runs as, and blindly setting 600 would take your app down if
              it runs as a different user than the file's owner.""",
              domain="server", where=service_side[:15],
              proof=["stat -c '%a %U:%G %n' <each file>",
                     "systemctl show -p User <your-service>   # which user needs to read it?"],
              fix="Set each file to be readable only by the account that actually needs it.",
              steps=[
                  "Find out which user runs the app that reads each file: "
                  "`systemctl show -p User <service>`, or `docker inspect <container> "
                  "--format '{{.Config.User}}'`, or check who owns the process in `ps aux`.",
                  "If that user owns the file: `chmod 600 <file>`.",
                  "If a different user needs it: `chown root:<appgroup> <file> && chmod 640 <file>` "
                  "— give it a group rather than leaving it world-readable.",
                  "Restart the app and confirm it still starts. If it fails to read its config, "
                  "you have the wrong user or group.",
              ],
              automate="agent",
              breaks="Getting the user wrong stops the app from reading its own config.",
              verify="stat -c '%a %U:%G' <file>")


# --------------------------------------------------------------------------


def coverage_notes(ev, O):
    sk = ev.L("shipcheck", "skipped")
    if ev.B("shipcheck", "checked_host") and not ev.B("shipcheck", "privileged"):
        O.add("low", "This check ran without admin rights, so parts of it were skipped",
              """shipcheck could not read the firewall rules, SSH config, user accounts or file
              permissions, because it was not run with sudo. Those are some of the most important
              checks. A clean result in those areas does not mean much right now.""",
              domain="server", where=["run again with: sudo ./shipcheck.sh"],
              proof=["id -u"], fix="Re-run with sudo.",
              steps=["sudo ./shipcheck.sh --out ./shipcheck-run"],
              automate="human", verify="")
    missing = [s for s in sk if "missing" in s or "no-ss" in s or "no-lockfile" in s]
    if missing:
        O.add("low", "Some checks could not run on this machine",
              """These checks needed a command that is not installed here. Listed so you know what
              was not looked at, rather than assuming it was fine.""",
              domain="server", where=missing, proof=[], fix="Optional.",
              steps=["Run ./install-tools.sh to add the optional deeper checks."],
              automate="human", verify="")


# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Turn shipcheck evidence into findings")
    ap.add_argument("run", nargs="?", default=None,
                    help="the shipcheck run directory (default: <repo>/outputs)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    if not args.run:
        args.run = default_run_dir()

    try:
        data, run_dir = load(args.run)
    except FileNotFoundError:
        sys.exit("No evidence.json found in %s — run shipcheck.sh first." % args.run)
    except json.JSONDecodeError as e:
        sys.exit("evidence.json is not valid JSON (%s). Re-run shipcheck.sh." % e)

    data["_run_dir"] = run_dir
    ev = Ev(data)
    O = Out((ev.sec("shipcheck").get("app_path") or "").strip())
    for fn in (check_code, check_appsec, check_site, check_server,
               check_health, coverage_notes):
        try:
            fn(ev, O)
        except Exception as e:
            print("warning: %s failed (%s) — continuing" % (fn.__name__, e), file=sys.stderr)

    findings = O.done()
    out = args.out or os.path.join(run_dir, "findings.json")
    doc = {
        "meta": {
            "tool": "shipcheck 0.1.0",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "checked_host": ev.B("shipcheck", "checked_app") or ev.B("shipcheck", "checked_host"),
            "privileged": ev.B("shipcheck", "privileged"),
            "app_path": ev.sec("shipcheck").get("app_path"),
            "site": ev.sec("shipcheck").get("site"),
            "public_ip4": (ev.sec("network").get("public_ip4") or "").strip(),
            "public_ip6": (ev.sec("network").get("public_ip6") or "").strip(),
            "skipped": ev.L("shipcheck", "skipped"),
        },
        "findings": findings,
    }
    with open(out, "w") as fh:
        json.dump(doc, fh, indent=2)

    c = {}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    print("shipcheck: %d finding%s (%s) -> %s"
          % (len(findings), "" if len(findings) == 1 else "s",
             ", ".join("%d %s" % (c[s], s) for s in ("critical", "high", "medium", "low") if s in c)
             or "nothing found",
             out), file=sys.stderr)


if __name__ == "__main__":
    main()
