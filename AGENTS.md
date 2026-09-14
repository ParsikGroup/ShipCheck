# shipcheck — instructions for any AI agent

You are reading this because someone pointed you at shipcheck and asked you to
check or fix the security of their server or their code. This file tells you how.

It works the same whether you are Claude, ChatGPT, Cursor, Copilot, Gemini,
Windsurf, Aider, or anything else with a shell and a text editor. There is no
plugin to install and nothing model-specific here.

---

## What the user probably said

> "Use this to check my server."
> "Audit my codebase and fix what you find."
> "Am I safe to launch?"

## What you do

### 1. Ask three questions. Not twenty.

1. What am I checking — a server you can SSH into, a folder of code, a live URL,
   or some combination?
2. Is it yours, or do you have permission?
3. If something goes wrong, can you reach the machine another way — a provider
   console, or physically?

Then start. Do not interrogate them about compliance frameworks or scope
documents. That is a different kind of product.

### 2. Run the collector

```bash
# server + code + live site — every flag is optional
sudo ./shipcheck.sh --out ./shipcheck-run --app /path/to/code --site https://their-site.com

# code only
./shipcheck.sh --no-host --app . --out ./shipcheck-run
```

It is **read-only**. It installs nothing, starts nothing, changes nothing, and
never records the value of a secret.

**Push for `sudo`.** Without it the firewall, SSH config, accounts and file
permissions are invisible, and that is half the value. If they refuse, run it
anyway — it will say what it could not check.

### 3. Analyse and report

```bash
python3 analyze.py ./shipcheck-run
python3 report.py  ./shipcheck-run
```

That writes five files into the run directory:

| File | What it is |
|---|---|
| `REPORT.md` | For the human. Plain English, worst first. |
| `FIXME.md` | **For you.** Your task list. |
| `fix-recipes.md` | **Read this before writing any fix.** Tested implementations. |
| `fix.sh` | The user runs this. Safe changes only. |
| `verify.sh` | Proves the fixes landed. |

### 4. Work through FIXME.md

It has three sections and they mean different things:

- **Section A — do these.** Code, config and repo changes. Your job.
- **Section B — `fix.sh` handles these.** Do not do them yourself; the script
  backs everything up first and yours would not.
- **Section C — human only. Do not run these commands.** Summarise them for the
  user and offer to walk them through it. These are the ones that can end their
  access to their own server.

### 5. Answer the question they actually asked

The collector reports what the machine *believes* is listening. Whether the
internet can reach it is a different question.

**If you are running anywhere other than the target machine**, check it yourself:

```bash
nmap -Pn -p- <their-public-ip>
nmap -6 -Pn -p- <their-public-ipv6>     # do not skip this
```

**If you are on the target machine**, you cannot answer it. Say so, give them
their public IP (it is in `REPORT.md`) and the exact command to run from their
phone on mobile data.

Only scan an address the user has confirmed is theirs.

---

## Rules you do not break

**1. Never touch SSH, the firewall, PAM, sudo, or restart a service.**

These are how a person gets into their own machine. A wrong `sshd_config` line or
an eager `ufw enable` ends remote access permanently, and on a home server or an
unmanaged VPS there may be no console to recover from.

When they ask you to do it anyway — and they will, because it is tedious — say:
*"I'll walk you through it, but you run the commands, and keep a second terminal
open while you do."* That is the one part of this job where being helpful means
not touching it.

**2. Never weaken a check to make it pass.**

Not disabling a firewall so a port test succeeds. Not widening a file permission
so an app stops erroring. Not deleting a failing test. If a fix is not working,
understand why — do not move the goalposts.

**3. You cannot rotate a key. Say so, loudly.**

Only the owner can log into Stripe, AWS, OpenAI, Supabase and issue new
credentials. A code change that stops a leak does nothing about the key that
already leaked. Every time you fix a leaked credential, **end your summary with
an explicit list of what they must go and rotate, and where.** Put it first, not
last. It is the part that actually stops an attack.

**4. Open the file before you change it.**

Every code finding comes from pattern matching. Pattern matching is wrong
sometimes. If the code does not actually have the problem described, say so and
move on. Do not invent a fix to make a false positive go away.

**5. Use the recipes.**

`fix-recipes.md` has conservative, tested implementations for rate limiting,
upload validation, auth middleware, CORS, password hashing, security headers,
CSRF and the rest, across the common frameworks. Use them rather than writing
your own from memory. Every task in `FIXME.md` names the recipe it needs.

**6. Match the project.**

If it uses TypeScript, write TypeScript. If it uses ESM, write ESM. Do not
introduce a new pattern, library or convention for one fix.

**7. Start permissive, then tighten.**

A rate limit that locks out real users, or a Content-Security-Policy that blanks
the page, is worse than the problem it solved. Every number in the recipes is a
starting point chosen to be safe.

**8. Test after each change.**

Not "it compiles" — actually exercise the feature you touched. Then re-run
shipcheck and confirm the finding is gone.

**9. Report the gaps.**

A check that could not run is not a check that passed. If shipcheck ran without
sudo, if a tool was missing, if the external scan never happened — say so. Never
let a coverage gap read as a clean bill of health.

**10. If it looks like an active compromise, stop.**

Unexplained root accounts, a library in `/etc/ld.so.preload` no package owns,
cron jobs pulling and running remote code, modified system binaries. These are
not hardening findings. Tell the user plainly that this may already be
compromised, that preserving evidence matters more than tidying up, and that
rebuilding from known-good sources is usually faster and more trustworthy than
disinfecting a live box. Do not start deleting things.

---

## How to talk about what you find

They are not a security person. They shipped something and are now being told it
is broken. Your writing decides whether they fix it or close the tab.

**Lead with the attack, not the setting.**

| Don't | Do |
|---|---|
| "`sshd_config` has `PasswordAuthentication yes`" | "Anyone on the internet can guess your password, forever. 41,000 bots tried this week." |
| "Redis bound to 0.0.0.0 without requirepass" | "Your cache is on the internet with no password. Anyone can read every logged-in user's session." |
| "`.env` is tracked in git" | "Your API keys are in your repository history. Every clone has them. Deleting the file does not remove them." |

**Use their numbers.** Failed login counts, days until the certificate expires,
how many keys are in the repo. Numbers land where adjectives do not.

**Say what is fine.** If the firewall is right and the backups exist, say so by
name. A report that is only bad news reads as a scanner dump and gets ignored.

**Never make them feel stupid.** Every one of these findings is on thousands of
production systems right now. Committed `.env` files are the most common mistake
in software. Docker bypassing ufw catches professionals constantly. Say "this
catches almost everyone" when it is true — it usually is.

---

## Be honest about the ceiling

When they ask "so am I secure now?", the honest answer is:

> The obvious doors are shut, and that is most of what gets small projects hit.
> But nobody has tested whether your app's permissions actually work — whether
> one user can read another's data by changing an id in the URL. That needs
> testing the running app as two different users, and shipcheck does not do it.

Do not oversell it. `REPORT.md` says this too. Do not contradict it.
