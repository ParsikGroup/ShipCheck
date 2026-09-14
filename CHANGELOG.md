# Changelog

## 0.3.1 — 2026-09-14

### The container check has never worked

Found on the first real Docker host shipcheck was ever pointed at.

The `docker inspect` Go template was written in double quotes inside a
single-quoted `sh -c` string, so the shell expanded `$p` and `$b` to empty
before Docker saw it:

```
{{range , := .NetworkSettings.Ports}}{{}}->{{}} {{end}}
```

That is not a valid template. `docker inspect` failed on every container, its
stderr went to `/dev/null`, the output file was empty — and **every machine with
running containers has been reporting the container check as blind since
0.1.0**, silently collecting nothing about privileged containers, containers
running as root, mounted `docker.sock`, host network mode, writable host mounts,
or published port bindings.

The one thing that stopped this being a silent false-clean is the coverage-gap
system added in 0.2.0: the report opened with "this check is incomplete" and
named docker every single time. It announced its own failure for months. That is
the entire argument for building it.

### Also fixed in the same area

- **Zero containers is no longer a coverage gap.** An idle Docker host reported
  as "incomplete" because health was keyed on whether `docker inspect` returned
  rows rather than whether the daemon was reachable.
- **Docker data is now collected through sudo when needed.** Previously the
  collector only ever tried the unprivileged path, so a box where the user is
  not in the `docker` group produced nothing even under `sudo`.
- **Coverage is claimed only for the path that actually ran.** An intermediate
  version of this fix tested the daemon with sudo while collecting without it,
  which would have reported full container coverage while capturing nothing.
  Reachability and collection now share one resolved command.

Net effect: shipcheck sees containers for the first time.

## 0.3.0 — 2026-09-14

shipcheck now fixes the server, not just the report on it.

### `secureserver.sh`

One command applies the hardening that every Linux server should have and most
do not: automatic security updates (never automatic reboots), fail2ban on SSH,
kernel and network hardening, logs that survive a reboot, file permissions on
`/etc/shadow`, `/root`, cron and SSH host keys, idle-shell timeout, clock sync,
and Ctrl+Alt+Del disabled at the console.

`--dry-run` prints the plan and stops. `--only` and `--skip` select steps.
`--tmout` sets the idle timeout. Debian and Ubuntu only; it refuses to guess on
anything else rather than half-apply a set of changes it has not been tested
against.

### The auto-revert guard

Every change is backed up before it is made, and a revert timer is armed
**before the first one**. If nobody runs `confirm.sh` from a second session
within the timeout, the machine restores itself — original file contents,
original permissions, original sysctl values, packages removed. Close your
laptop mid-run and you still have your server.

This is the reason the feature is shippable at all. `test/run-secureserver.sh`
proves it on a disposable machine: apply, deliberately do not confirm, wait, and
assert the machine is byte-identical to how it started.

Falls back to a detached timer when transient systemd units are unavailable.
Refuses to run at all without a terminal attached unless you pass
`--no-deadman` explicitly, because a guard nobody can confirm just wastes the
run.

### What it will not do, by design

No `sshd_config` edit. No firewall rule or policy change. No PAM, sudoers, user
account or password change. No reboot. Each of those can end a session on a
machine with no console, and a script cannot know whether there is a console.

Those fixes are the highest-value ones left, so they are not dropped — they move
to `SECURESERVER.md`, a model-agnostic brief that walks a human and their AI
through key-only SSH and a default-deny firewall with a revert timer on every
step. It covers the traps: sshd drop-in files are first-match-wins so a `99-`
file loses to Ubuntu's `50-cloud-init.conf`; `reload` not `restart`; socket
activation ignoring `Port` on 22.10+; and Docker publishing ports straight past
ufw through the `DOCKER-USER` chain.

### Contract tests

Three new checks, all with proven negative cases:

- `secureserver.sh` contains no SSH config, firewall, PAM, sudoers, account or
  reboot command.
- The guard is armed before the apply section begins.
- The generated `rollback.sh` and `confirm.sh` are valid bash.

### Fixed during the build

`dpkg -s <pkg>` returns success for a package that was **removed but not
purged** — its status is then `deinstall ok config-files` and the binaries are
gone. Used as an is-installed test, it made secureserver skip the install and
then try to configure and start software that was not on the machine. Anyone who
had ever run `apt-get remove fail2ban` would have got a run that reported
"installed" and did nothing. Now checked with an explicit
`dpkg-query -W -f='${Status}'` match.

### Deliberately excluded from the sysctl set

`ip_forward` (breaks Docker networking), `rp_filter` (breaks asymmetric routing
and some VPNs), `accept_ra` (breaks IPv6 on most VPS). Each is a real CIS
recommendation and each has broken real servers. They are named in the config
file so the next person knows the omission was a decision.

## 0.2.1 — 2026-09-14

Usability. Nothing about what gets checked changed; the tools just stopped
disagreeing with each other about where things live.

### One command instead of three

`shipcheck.sh` now runs `analyze.py` and `report.py` itself when it finishes, so
`sudo ./shipcheck.sh` produces the full report on its own. The three-step
sequence was the biggest source of "it didn't work": the second command had to
be told where the first one put its output, and getting that wrong produced an
argparse usage string rather than anything useful. `--collect-only` keeps the old
behaviour of stopping at `evidence.json`.

The run now ends by printing the absolute path of every file it wrote and what
each one is for.

### Output lands somewhere findable

Results go to `<repo>/outputs` by default — next to the code, already in
`.gitignore` — rather than a `shipcheck-run` directory relative to whatever
directory you happened to be in. `analyze.py` and `report.py` default to the
same place and take no argument. They still accept one, and still find runs left
by older versions in the old locations.

### sudo no longer locks you out of your own results

A run under `sudo` left the output owned by root at mode 700, so `cd` into it
failed with "Permission denied". The collector now hands ownership back to
`$SUDO_USER`. If you hit this with an older run, `analyze.py` and `report.py`
now say so explicitly and print the `chown` that fixes it, instead of raising
`PermissionError`.

### Fixed

- `$0`-relative paths were resolved after the app scan had already changed
  directory, so the chained report step looked for `analyze.py` at `/analyze.py`.

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
