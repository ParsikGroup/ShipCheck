# shipcheck

**Security check for people who ship fast.**

Point your AI at your server and your code. Get back a plain-English report of
what an attacker could actually do — and a fix brief your agent can work straight
through.

```
"run shipcheck on my server"
```

That's the whole interface.

---

## What it does

Two things get you owned when you're moving fast:

1. **Something on your server is open to the internet that shouldn't be.**
2. **A key leaked into your code.**

shipcheck looks hard at both, in about ninety seconds, and it does not change
anything while it looks.

**Your server** — what's listening and whether the internet can actually reach it
(including IPv6, which is where most "my firewall is on" servers turn out to be
open), your firewall, whether Docker is quietly bypassing it, SSH, accounts and
sudo, containers, exposed databases, patching, and whether you have backups at all.

**Your code** — `.env` committed to git, keys in your git history from six months
ago, live API keys sitting in source files, `.env` missing from `.gitignore`,
debug mode left on, source maps shipped to production, `npm audit`.

**How your app is built** — the things that actually get small projects hit:

- **No rate limiting on login** — unlimited password guessing, unlimited reset emails
- **File uploads with no validation** — a script uploaded instead of a photo
- **Secrets behind `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_`** — compiled straight into
  the JavaScript every visitor downloads, while the app works perfectly so nothing
  looks wrong
- **Supabase `service_role` key in app code** — bypasses every Row Level Security policy
- **Firebase rules set to `if true`** — the `firebase init` default; anyone reads and
  deletes everything
- **SQL built by string concatenation**, passwords stored unhashed, JWTs decoded
  without verifying, wildcard CORS with credentials, `eval` and shell calls,
  unescaped HTML, missing security headers, cookie sessions with no CSRF handling

And it doesn't just report them — **it ships tested implementations**. `fix-recipes.md`
has the correct, conservative version of every fix for Express, Next.js, FastAPI,
Flask, Django, Laravel and Rails, so your agent applies a real one instead of
inventing something from memory.

**Your live site**, if you give it a URL — the classics: `/.git/` downloadable,
`/.env` downloadable, directory listing on, expired certificate, missing headers.

## Install

```bash
/plugin marketplace add ParsikGroup/ShipCheck
/plugin install shipcheck@parsiktechgroup
```

Then just ask. `"check my server"`, `"did I leak any API keys"`, `"am I safe to
launch"`.

Prefer to run it by hand? The scripts are standalone:

```bash
git clone https://github.com/ParsikGroup/ShipCheck
cd ShipCheck/skills/shipcheck/scripts
chmod +x *.sh

sudo ./shipcheck.sh --app ~/myproject --site https://mysite.com
```

One command. It collects, analyses and writes the whole report, then prints
where everything went — `ShipCheck/outputs/` by default. Every flag is optional:
with none it scans this server plus the code in the current directory.

## And then it fixes the server for you

Reporting a problem is half a product. `secureserver.sh` applies the obvious
hardening in one command:

```bash
sudo ./skills/shipcheck/scripts/secureserver.sh --dry-run   # show the plan
sudo ./skills/shipcheck/scripts/secureserver.sh             # do it
```

Automatic security updates. fail2ban on SSH, with your own IP whitelisted so it
cannot ban you. Kernel and network hardening. Logs that survive a reboot. File
permissions on `/etc/shadow`, `/root`, cron and SSH host keys. Idle shells
disconnected. Clock sync so your logs have honest timestamps.

**It cannot lock you out, and it does not ask you to take that on faith.**

Every change is backed up before it is made, and an auto-revert timer is armed
*before* the first one. If you do not open a second terminal and run `confirm.sh`
within ten minutes, the machine puts itself back exactly how it was. Walk away
mid-run, close your laptop, lose your connection — you get your server back.

It refuses to touch `sshd_config`, firewall rules, PAM, sudoers, user accounts,
or reboot. Those are the highest-value fixes left, and they are exactly the ones
that end a session on a box with no console. They live in
[`SECURESERVER.md`](SECURESERVER.md) as a supervised procedure — key-only SSH,
default-deny firewall, the two-terminal drill, and the Docker/ufw trap most
guides get wrong — for you and your AI to work through together.

Undo any run, any time:

```bash
sudo /var/backups/secureserver/<timestamp>/rollback.sh
```

## What you get

| File | What it's for |
|---|---|
| **REPORT.md** | Read this. Plain English, worst first, no jargon. |
| **FIXME.md** | Paste into Claude Code, Cursor, ChatGPT, or whatever you use. A task list for an agent, with the dangerous stuff explicitly fenced off. |
| **fix-recipes.md** | Travels with the brief. Tested implementations per framework, so the agent doesn't improvise. |
| **fix.sh** | `sudo ./fix.sh`. Only changes that cannot lock you out or break a service. Backs up first, safe to re-run, has a rollback. |
| **verify.sh** | Proves the fixes landed. |
| **secureserver.sh** | Hardens the box itself. Auto-reverts unless you confirm. |
| **SECURESERVER.md** | The supervised procedure for SSH and firewall changes. |

## Works with any AI

There is nothing model-specific here. `AGENTS.md` in this repo is written for any
agent — Claude, ChatGPT, Cursor, Copilot, Gemini, Windsurf, Aider — and tells it
how to run the check, how to read the output, and what it must never touch.

```
"Read AGENTS.md and use shipcheck on my server."
"Read SECURESERVER.md and harden this box."
```

The Claude Code plugin is just a convenience wrapper. Clone the repo and point
anything at it.

## The safety model

This is the part worth reading before you run anything.

Every finding is sorted into one of three levels, and **nothing is ever promoted
to a safer level because the finding looked serious**:

- **safe** — `fix.sh` does it. File permissions, kernel settings, persistent logs.
  Cannot lock you out, cannot take a service down. Backed up, reversible.
- **agent** — your AI can do it. Code changes, `.gitignore`, config, dependency
  upgrades, Docker port bindings.
- **human** — you do it, personally. SSH, firewall, sudo, PAM, rotating keys,
  installing packages, rebooting. Anything that can end your access to your own
  server, or costs money, or needs a decision only you can make.

`fix.sh` contains **zero** SSH, firewall, PAM or sudo changes. Not because they
don't matter — several are the highest-value fixes in the report — but because a
script that gets one wrong on a remote box with no console is unrecoverable.
Those stay written instructions, with the "open a second terminal first" step
spelled out.

**shipcheck never records the value of a secret.** It records that a Stripe live
key is in `src/config.js`, not what it is. The report and the fix brief are safe
to paste into a chat or attach to an issue.

## Requirements

Bash, and Python 3 for the report. That's it.

`./install-tools.sh` optionally adds gitleaks, trivy and semgrep for deeper code
scanning. It shows you what it would install before it installs anything, and
shipcheck works fully without them — it just tells you what it couldn't check.

## What this is not

shipcheck is a fast first look. It does **not** test:

- **whether user A can read user B's data** by changing an id in the URL — the most
  common serious bug in real apps. shipcheck counts your routes and your auth
  checks; it does not test them against each other.
- business logic: negative quantities, skipped payment steps, race conditions
- anything at runtime — the code checks are pattern matching on your source
- whether your backups actually restore
- your cloud IAM, Kubernetes, Windows, or mobile apps

The code findings are **candidates**. Pattern matching is right most of the time
and wrong some of the time, which is why both `FIXME.md` and `AGENTS.md` tell the
agent to open the file and confirm before changing anything.

A clean shipcheck means the obvious doors are shut, and that's most of what gets
small projects hit. It is not the same as your app being secure. The report says
so too.

## Contributing

Issues and PRs welcome. Three things that will get a PR rejected:

1. **Anything that puts an access-affecting change into `fix.sh`.** SSH, firewall,
   PAM, sudo, service restarts. The line is not negotiable.
2. **Anything that records a secret's value** into the evidence file, the report,
   or the fix brief.
3. **Anything that lets a run present as clean when a check silently failed.** If a
   parser breaks, the report must say so at the top.

4. **Anything that puts an access-affecting change into `secureserver.sh`,** or
   that applies a change before the auto-revert guard is armed.

`test/contract-test.sh` enforces all four against a real run, and
`test/run-secureserver.sh` proves the guard actually fires on a disposable
machine. Both run in CI.

New checks are very welcome, especially ones that catch real mistakes people
actually make. Keep them zero-dependency where you can.

## Licence

MIT. Free, forever, no strings. It's provided as-is with no warranty — you're
responsible for what you run on your own systems.

Built by [The Parsik Tech Group](https://github.com/ParsikGroup).
