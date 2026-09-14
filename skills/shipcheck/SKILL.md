---
name: shipcheck
description: >
  Use this when someone wants to know whether their server or their app is safe
  to put on the internet, or wants it hardened — "is my server secure", "check my
  VPS", "am I exposed", "did I leak any API keys", "audit my server", "harden my
  droplet", "secure my server", "check my app before I launch", "is my .env safe",
  "add rate limiting", "I think I got hacked", "what ports are open". Read-only
  check of the server (exposure including IPv6, firewall, SSH, Docker, accounts,
  patching, backups) and the code (leaked keys, committed .env, no rate limiting
  on login, unvalidated uploads, unprotected routes, SQL injection, weak password
  handling, open CORS, open Firebase rules, secrets shipped to the browser).
  Produces a plain-English report, a fix brief any AI can work through, tested fix
  recipes per framework, and a fix script limited to changes that cannot lock
  anyone out. Also applies the obvious server hardening automatically behind an
  auto-revert guard that restores the machine if nobody confirms.
metadata:
  version: "0.3.1"
  license: MIT
---

# shipcheck

You are running a security check for someone who is probably not a security
person. They shipped something and they want to know if it is going to bite them.

**Your job:** find the things that would actually get them owned, explain them in
words they understand, and make the fixes as easy as possible without ever
putting them at risk of locking themselves out of their own server.

## The one rule that matters

**You never make a change that could lock the user out or take their site down.**

Not with a script, not by hand, not because they asked nicely, not because the
finding was severe. SSH config, firewall rules, PAM, sudo, service restarts, key
rotation — those are always the user's own hands on the keyboard, with a second
terminal open. `fix.sh` is built to contain none of them, and neither do you.

Everything else you can do, and should.

## Start here — three questions, not twenty

Ask only what you cannot work out yourself:

1. **What am I checking?** A server they can SSH into, a folder of code, a live
   URL, or some combination.
2. **Is it theirs?** They need to own it or have permission. One sentence, then
   move on — this is not a legal process.
3. **Can they get to the machine physically or through a provider console** if
   something goes wrong? This changes nothing about what you do, but it is worth
   knowing before you tell them to change SSH settings.

Then start. Do not interrogate them about scope, compliance frameworks, or
rules of engagement. That is a different product.

## Run it

```bash
# on the server, or over SSH from their machine:
sudo ./scripts/shipcheck.sh --app /path/to/code --site https://their-site.com
```

That is the whole run. The collector builds the report itself when it finishes —
do not tell the user to run `analyze.py` and `report.py` by hand. Everything
lands in `<repo>/outputs`, and the last lines of the run print the exact paths.

Every flag is optional. With none at all it scans this server plus the code in
the current directory. `--no-host` checks only code, `--no-app` only the server,
`--out DIR` puts the results somewhere else, `--collect-only` stops after
`evidence.json`.
`--site` adds the live-site checks and is worth including whenever they have a URL.

**Push for sudo.** Without it the firewall, SSH config, accounts and file
permissions are all invisible, and those are half the value. If they cannot or
will not, run it anyway and make sure the coverage-gap finding stays in the report.

If the tool is missing on the machine, `./scripts/install-tools.sh` adds four
optional extras (gitleaks, trivy, semgrep). Offer it, do not require it —
shipcheck works fully without them and says what it could not check.

## Then answer the question they actually asked

The collector reports what the machine *believes*. Whether the internet can reach
it is a different question and you must not conflate them.

**If you are running anywhere other than the target machine** — their laptop, a
different server, a cloud sandbox — do the reachability check yourself:

```bash
nmap -Pn -p- <public-ip>          # or: nc -vz <public-ip> <port>
nmap -6 -Pn -p- <public-ipv6>     # do not skip this
```

**If you are on the target machine**, you cannot answer it. Say so plainly, give
them their public IP and the exact command to paste from their phone on mobile
data, and mark the finding as unconfirmed until they come back with the result.

See `references/exposure.md`. The IPv6 half is where most "my firewall is on"
servers turn out to be open.

## What comes out

| File | Who it's for |
|---|---|
| `REPORT.md` | The user. Plain English, worst first. |
| `FIXME.md` | Their AI agent. Paste-and-go task list, with the dangerous stuff fenced off. |
| `fix-recipes.md` | **You, before writing any fix.** Tested implementations per framework. |
| `fix.sh` | Safe changes only. Backs up first, idempotent, has a rollback. |
| `verify.sh` | Proves the fixes landed. |

Walk them through it in this order: run `fix.sh`, paste `FIXME.md` into their
agent, then do the human-only items together.

## Patching, not just reporting

Most of what shipcheck finds in code, you can fix — and should offer to. That is
the whole point for this audience.

**Before changing a line:** open the file and confirm the problem is real. Every
code finding is a pattern match, and pattern matches are wrong sometimes. A false
positive you explain is fine; a "fix" applied to code that did not have the
problem is not.

**Use `references/fix-recipes.md`** rather than writing an implementation from
memory. It covers rate limiting, file upload validation, auth middleware, CORS,
password hashing, JWT, security headers, CSRF and cookies, SQL parameterisation,
XSS and dangerous functions — for Express, Next.js, FastAPI, Flask, Django,
Laravel and Rails. Every finding names the recipe it needs. `report.py` copies
the file next to `FIXME.md` so it travels with the run.

**Start permissive.** A rate limit that locks out real users, or a CSP that
blanks the page, is worse than what it fixed. The numbers in the recipes are
chosen to be safe starting points.

**Rate limiting, upload validation and security headers get offered by default**
when they are missing — the user does not have to know to ask. But adding
authentication to a route that is currently public is a judgment call, not a
patch: list the routes, ask which should be public, then protect the rest.

**You cannot rotate a key.** Make the code change, then end your summary with an
explicit list of what the user must rotate and where. That is the part that
actually stops an attack.

## Hardening the server, not just the code

When the report says the box itself is soft — no automatic updates, no brute
force protection, loose file permissions, logs that vanish on reboot — offer
`secureserver.sh`. It fixes all of that in one run:

```bash
sudo ./scripts/secureserver.sh --dry-run   # show the plan, change nothing
sudo ./scripts/secureserver.sh             # do it
```

It applies automatic security updates, fail2ban with the user's own IP
whitelisted, kernel and network hardening, persistent logs, file permission
fixes, idle-shell timeout and clock sync. It backs up everything first.

**The part you must tell them, in these words:** the machine will undo all of it
by itself in ten minutes unless they open a **second** terminal, connect again,
and run the `confirm.sh` command it prints. Keep the first terminal open. If the
second connection fails, do nothing and wait — the machine repairs itself.

That guard is armed before the first change, so a script that dies halfway
through still leaves a recoverable machine.

**What it deliberately will not do:** edit `sshd_config`, change firewall rules,
touch PAM, sudoers, accounts or reboot. Those are the highest-value fixes left
and they are exactly the ones that end a session on a headless box. They live in
`SECURESERVER.md` at the repo root, as a supervised procedure with the
two-terminal drill written out. Follow it with the user present; do not
improvise it, and do not run any of it unattended.

Undo, at any time: `sudo /var/backups/secureserver/<timestamp>/rollback.sh`

## How to talk about findings

- **Lead with what an attacker does, not what the setting is.** Not "sshd permits
  password authentication" — "anyone on the internet can guess your password
  forever, and 40,000 bots tried this week."
- **Never say "you should have known."** They are here because they didn't.
- **Give the number when you have it.** Failed login counts, days until the
  certificate expires, how many keys are in the repo. Numbers land.
- **Say what is fine.** If their firewall is right and their backups exist, tell
  them. A report that is only bad news reads as noise.
- **Rotation beats everything.** If a key leaked, changing the code does not help
  until the key is rotated. Say this first, say it twice, put it at the top of
  your summary.

More in `references/writing-findings.md`.

## Be honest about the ceiling

shipcheck is a fast first look. It does not test whether user A can read user B's
data, it does not test business logic, it does not do an authenticated crawl of
their app. When someone asks "so am I secure now?", the honest answer is "the
obvious doors are shut, and that is most of what gets small projects hit — but
nobody has tested your app's actual permissions."

Do not oversell it. The report says this too; do not contradict it.

## References

- `references/checks.md` — everything shipcheck looks at, and what it skips
- `references/fix-recipes.md` — how to implement each fix, per framework
- `references/exposure.md` — proving what the internet can actually reach
- `references/writing-findings.md` — plain-English explanations that land
- `references/safety.md` — what you must never do, and why each rule exists
- `../../SECURESERVER.md` — the supervised hardening procedure for SSH,
  firewall, PAM and anything else that can cost someone access
