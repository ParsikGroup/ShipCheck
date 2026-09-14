#!/usr/bin/env python3
"""
shipcheck report generator.

    python3 report.py ./shipcheck-run

Writes four files:

    REPORT.md   what's wrong, in plain English, worst first. Read this.
    FIXME.md    the same thing written for an AI coding agent. Paste it in.
    fix.sh      only the changes that cannot lock you out or break a service.
    verify.sh   re-checks what fix.sh claimed to fix.

The split between fix.sh and FIXME.md is the safety model. fix.sh contains
nothing that touches SSH, the firewall, PAM, or any running service's config.
Everything with real blast radius stays a written instruction.
"""

import argparse
import json
import os
import shlex
import sys
from datetime import datetime, timezone

SEV_ORDER = ["critical", "high", "medium", "low"]
BADGE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
DOMAIN = {"code": "your code", "server": "your server", "site": "your live site"}



def default_run_dir():
    """<repo>/outputs — same default shipcheck.sh uses, so no argument is needed."""
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", "..", ".."))
    cand = os.path.join(repo, "outputs")
    return cand if os.path.isdir(cand) else "./shipcheck-outputs"


def load(run):
    p = run if run.endswith(".json") else os.path.join(run, "findings.json")
    with open(p) as fh:
        return json.load(fh)


def by_sev(findings):
    return {s: [f for f in findings if f["severity"] == s] for s in SEV_ORDER}


def q(s):
    return shlex.quote(str(s))


# --------------------------------------------------------------------------
# REPORT.md — for the human
# --------------------------------------------------------------------------


def report_md(doc):
    F = doc["findings"]
    m = doc["meta"]
    g = by_sev(F)
    L = []
    A = L.append

    A("# shipcheck")
    A("")
    A("Ran %s." % datetime.now(timezone.utc).strftime("%d %B %Y at %H:%M UTC"))
    A("")

    # A coverage gap must be the first thing the reader sees. Otherwise a report
    # that says "nothing urgent" because a parser broke reads as a clean result.
    blind = [f for f in F if f.get("blind")]
    if blind:
        A("> ## Read this first: this check is incomplete")
        A(">")
        A("> shipcheck could not look at everything it normally does, so the summary below")
        A("> is **not** a clean bill of health — it is a partial one. What it could not see:")
        A(">")
        for b in blind:
            for w in b["where"][:6]:
                A("> - %s" % w)
        A(">")
        A("> Fix the coverage first (usually: re-run with `sudo`), then trust the rest.")
        A("> See %s below." % ", ".join(b["id"] for b in blind))
        A("")

    crit, high = len(g["critical"]), len(g["high"])
    if crit:
        A("## %d thing%s need%s fixing today" % (crit, "" if crit == 1 else "s", "s" if crit == 1 else ""))
        A("")
        A("These are not theoretical. Each one is something an attacker can use right now,")
        A("with no skill required, and most are actively scanned for by bots.")
    elif high:
        A("## Nothing critical, %d thing%s worth fixing this week" % (high, "" if high == 1 else "s"))
        A("")
        A("No open front doors. The items below are real, but they need either a mistake")
        A("elsewhere or a bit of effort to exploit.")
    elif F:
        A("## Nothing urgent")
        A("")
        A("No critical or high-severity issues. What's left is hardening — worth doing,")
        A("not worth losing sleep over.")
    elif blind:
        A("## Nothing found — but the check was incomplete")
        A("")
        A("shipcheck found no issues in the parts it could read. Given the coverage gap")
        A("above, that is not a result you should rely on. Fix the gap and run it again.")
    else:
        A("## Nothing found")
        A("")
        A("shipcheck found no issues in what it was able to check. See *What wasn't")
        A("checked* at the bottom — that list matters as much as this one.")
    A("")

    if F:
        A("| | Count |")
        A("|---|---|")
        for s in SEV_ORDER:
            if g[s]:
                A("| %s | %d |" % (BADGE[s], len(g[s])))
        A("")

    safe = [f for f in F if f["fix"]["automate"] == "safe"]
    agent = [f for f in F if f["fix"]["automate"] == "agent"]
    human = [f for f in F if f["fix"]["automate"] == "human"]
    if F:
        A("**How to work through this:**")
        A("")
        if safe:
            A("1. Run `sudo ./fix.sh` — handles %d item%s that cannot break anything."
              % (len(safe), "" if len(safe) == 1 else "s"))
        if agent:
            A("%d. Paste `FIXME.md` into Claude Code, Cursor, ChatGPT or whatever you use. It can "
              "do %d of these, and `fix-recipes.md` next to it tells it exactly how."
              % (2 if safe else 1, len(agent)))
        if human:
            A("%d. Do the remaining %d yourself. They're the ones that can lock you out of your "
              "own server or need a key rotated, and no script should do them for you."
              % ((3 if safe else 2) if agent else (2 if safe else 1), len(human)))
        A("")

    ip4 = m.get("public_ip4") or ""
    A("---")
    A("")
    A("## Are you actually exposed?")
    A("")
    A("Everything above about open ports is what this machine *believes*. The only way to")
    A("know what the internet can reach is to look from outside your network. From your")
    A("phone on mobile data, or any machine that is not on this network:")
    A("")
    A("```bash")
    A("nmap -Pn -p- %s          # IPv4" % (ip4 or "<your public IP>"))
    if m.get("public_ip6"):
        A("nmap -6 -Pn -p- %s   # IPv6 — the half everyone forgets" % m["public_ip6"])
    else:
        A("nmap -6 -Pn -p- <your public IPv6>   # if you have one. Don't skip this.")
    A("```")
    A("")
    A("No nmap? `nc -vz <ip> <port>` works for checking one port at a time.")
    A("")
    A("**Why IPv6 matters:** your router's NAT protects IPv4 by accident. IPv6 has no NAT.")
    A("If your ISP gives you IPv6, every device on your network can have an address the")
    A("whole internet can route to, and your IPv4 firewall rules do not apply to it.")
    A("")

    for s in SEV_ORDER:
        if not g[s]:
            continue
        A("---")
        A("")
        A("# %s" % BADGE[s])
        A("")
        for f in g[s]:
            A("## %s — %s" % (f["id"], f["title"]))
            A("")
            A("*%s*" % DOMAIN.get(f["domain"], f["domain"]))
            A("")
            A(f["plain"])
            A("")
            if f["where"]:
                A("**Where:**")
                A("")
                for w in f["where"][:15]:
                    A("- `%s`" % w)
                if len(f["where"]) > 15:
                    A("- …and %d more" % (len(f["where"]) - 15))
                A("")
            if f["proof"]:
                A("**See it yourself:**")
                A("")
                A("```bash")
                for p in f["proof"]:
                    A(p)
                A("```")
                A("")
            A("**Fix:** %s" % f["fix"]["summary"])
            A("")
            if f["fix"]["steps"]:
                for i, st in enumerate(f["fix"]["steps"], 1):
                    A("%d. %s" % (i, st))
                A("")
            if f["fix"]["breaks"]:
                A("> **Watch out:** %s" % f["fix"]["breaks"])
                A("")
            tier = f["fix"]["automate"]
            label = {"safe": "`fix.sh` does this for you.",
                     "agent": "An AI agent can do this — it's in `FIXME.md`.",
                     "human": "**Do this one yourself.** It can lock you out or needs a decision."}
            A("%s" % label[tier])
            A("")

    A("---")
    A("")
    A("## What wasn't checked")
    A("")
    A("shipcheck is a fast first look, not a security assessment. It did not check:")
    A("")
    A("- **Whether your permissions actually work.** Can user A read user B's data by changing")
    A("  an id in the URL? That is the most common serious bug in real apps and it can only be")
    A("  found by testing your app as two different users. shipcheck does not do that.")
    A("- **Business logic.** Ordering -1 items, skipping the payment step, replaying a request,")
    A("  racing two checkouts.")
    A("- **Running the app.** The code checks are pattern matching on your source. They find the")
    A("  common mistakes; they do not prove anything about what happens at runtime.")
    A("- Whether your backups actually restore.")
    A("- Your cloud account's IAM, Kubernetes, Windows, macOS, or mobile apps.")
    A("")
    if m.get("skipped"):
        A("On this run it also skipped: %s" % ", ".join("`%s`" % s for s in m["skipped"][:10]))
        A("")
    if not m.get("privileged"):
        A("**This run had no admin rights**, so the firewall, SSH config, user accounts and file")
        A("permissions were not read. Re-run with `sudo` for those.")
        A("")
    A("A clean shipcheck means the obvious doors are shut. It does not mean the app is secure.")
    A("")
    A("---")
    A("")
    A("<sub>shipcheck is free and open source, from The Parsik Tech Group. It is provided as-is,")
    A("with no warranty. You are responsible for what you run on your own systems.</sub>")
    return "\n".join(L)


# --------------------------------------------------------------------------
# FIXME.md — for the agent
# --------------------------------------------------------------------------


def fixme_md(doc):
    F = doc["findings"]
    m = doc["meta"]
    agent = [f for f in F if f["fix"]["automate"] == "agent"]
    safe = [f for f in F if f["fix"]["automate"] == "safe"]
    human = [f for f in F if f["fix"]["automate"] == "human"]
    L = []
    A = L.append

    A("# Security fixes — task list for an AI coding agent")
    A("")
    A("Generated by shipcheck on %s." % datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    if m.get("app_path"):
        A("Project: `%s`" % m["app_path"])
    A("")
    A("## Read this first")
    A("")
    A("You are being asked to fix security problems in a real, running project. Work")
    A("through **Section A** only. Sections B and C are context — do not act on them.")
    A("")
    A("**Rules:**")
    A("")
    A("1. **Do the tasks in Section A, in order.** They are sorted worst-first.")
    A("2. **Never weaken a check to make it pass.** Do not disable a firewall, delete a")
    A("   test, loosen a permission, or add an exception to make something go green.")
    A("3. **Never commit a secret.** If a task involves credentials, the fix is to remove")
    A("   them from the code and read them from the environment — never to move them to a")
    A("   different file that is also committed.")
    A("4. **You cannot rotate keys.** Only a human can log into Stripe/AWS/OpenAI and issue")
    A("   new ones. Where a task says to rotate, make the code change and then tell the user")
    A("   clearly that they must rotate, and which keys.")
    A("5. **Do not touch SSH, the firewall, PAM, sudo, or any service restart.** Those are")
    A("   in Section C for a reason — getting them wrong locks the user out of their own")
    A("   server permanently. If the user asks you to do one anyway, walk them through it")
    A("   in a second terminal rather than running it yourself.")
    A("6. **Run the verify command after each fix** and report the result.")
    A("7. **Report what you could not do.** A task you skipped is fine. A task you claimed")
    A("   to finish and did not is not.")
    A("")
    A("Nothing in this file contains an actual secret value. Where a credential was found,")
    A("only its location and type were recorded.")
    A("")
    A("## Use the recipes")
    A("")
    A("`fix-recipes.md` sits next to this file. It contains tested, conservative")
    A("implementations for every fix below — rate limiting, upload validation, auth")
    A("middleware, CORS, password hashing, security headers and the rest, for the common")
    A("frameworks. **Use those rather than writing your own.** Each task names the recipe")
    A("it needs. If you cannot find the file, ask the user for it before improvising.")
    A("")
    A("## These findings come from pattern matching")
    A("")
    A("shipcheck greps for patterns. It is right most of the time and wrong some of the")
    A("time. **Open each file and confirm the problem is real before changing anything.**")
    A("If the code does not have the issue described, say so and move on — do not invent")
    A("a fix to make a false positive go away.")
    A("")

    A("---")
    A("")
    A("## Section A — do these")
    A("")
    if not agent:
        A("Nothing here for you. Everything found is either handled by `fix.sh` or needs a")
        A("human. Tell the user that and point them at Section C.")
        A("")
    for i, f in enumerate(agent, 1):
        A("### A%d. %s" % (i, f["title"]))
        A("")
        A("- **Severity:** %s" % BADGE[f["severity"]])
        A("- **Finding ID:** %s" % f["id"])
        A("- **Area:** %s" % DOMAIN.get(f["domain"], f["domain"]))
        A("")
        A("**Why this matters:** %s" % f["plain"])
        A("")
        if f["where"]:
            A("**Affected:**")
            A("")
            for w in f["where"][:20]:
                A("- `%s`" % w)
            A("")
        if f.get("recipe"):
            A("**Recipe:** see the `%s` section of `fix-recipes.md`." % f["recipe"])
            A("")
        A("**What to do:**")
        A("")
        for j, st in enumerate(f["fix"]["steps"], 1):
            A("%d. %s" % (j, st))
        A("")
        if f["fix"]["breaks"]:
            A("**Risk:** %s" % f["fix"]["breaks"])
            A("")
        if f["fix"]["verify"]:
            A("**Verify when done:**")
            A("")
            A("```bash")
            A(f["fix"]["verify"])
            A("```")
            A("")
        A("---")
        A("")

    A("## Section B — already handled by `fix.sh` (context only)")
    A("")
    if safe:
        A("The user runs `sudo ./fix.sh` for these. **Do not do them yourself** — the script")
        A("backs everything up first and yours would not.")
        A("")
        for f in safe:
            A("- **%s** — %s (`%s`)" % (f["id"], f["title"], BADGE[f["severity"]]))
        A("")
    else:
        A("None.")
        A("")

    A("## Section C — human only. DO NOT ATTEMPT THESE.")
    A("")
    if human:
        A("These can lock the user out of their own server, cost money, or need a decision")
        A("only they can make. **You must not run these commands.** Your job with this")
        A("section is to summarise it for the user and offer to walk them through it")
        A("interactively, with a second terminal open.")
        A("")
        for f in human:
            A("### %s — %s (%s)" % (f["id"], f["title"], BADGE[f["severity"]]))
            A("")
            A("%s" % f["plain"])
            A("")
            A("What the user needs to do:")
            A("")
            for j, st in enumerate(f["fix"]["steps"], 1):
                A("%d. %s" % (j, st))
            A("")
            if f["fix"]["breaks"]:
                A("> Risk if done carelessly: %s" % f["fix"]["breaks"])
                A("")
    else:
        A("None.")
        A("")

    A("---")
    A("")
    A("## When you're finished")
    A("")
    A("Report back with:")
    A("")
    A("1. Which Section A tasks you completed, and the output of each verify command.")
    A("2. Which you skipped, and why.")
    A("3. **A clear list of any credentials the user must rotate themselves.** Put this")
    A("   at the top of your summary — it is the part that actually stops an attack, and")
    A("   the part a code change cannot do.")
    A("4. A reminder to run `sudo ./fix.sh` and then `sudo ./verify.sh` if they have not.")
    A("5. Anything in Section A you believe was a false positive, and why. That is useful")
    A("   feedback, not a failure.")
    A("")
    A("Then tell them to re-run shipcheck. A fix that does not clear the finding is not done.")
    return "\n".join(L)


# --------------------------------------------------------------------------
# fix.sh — SAFE tier only
# --------------------------------------------------------------------------


FIX_HEAD = r'''#!/usr/bin/env bash
# shipcheck fix script — the safe subset only.
#
#   sudo ./fix.sh --dry-run    show what would change, change nothing
#   sudo ./fix.sh              apply
#   sudo ./rollback.sh         undo (created next to the backup)
#
# What is NOT in here, on purpose: anything touching SSH, the firewall, PAM,
# sudo, package installs, or a service's own config. Those can lock you out of
# your own server, so they stay as written instructions in REPORT.md.
#
# Everything below is backed up before it is changed, and is safe to re-run.
set -u
umask 022

DRYRUN=0
[ "${1:-}" = "--dry-run" ] || [ "${1:-}" = "-n" ] && DRYRUN=1

[ "$(id -u)" -eq 0 ] || { echo "Run this with sudo: sudo ./fix.sh"; exit 1; }

BACKUP="/root/.shipcheck-backup/$(date -u +%Y%m%dT%H%M%SZ)"
if [ "$DRYRUN" -eq 0 ]; then
  mkdir -p "$BACKUP" && chmod 700 "$BACKUP"
fi
CHANGED=0

backup_file() {
  [ "$DRYRUN" -eq 1 ] && return 0
  if [ ! -e "$1" ]; then echo "$1" >> "$BACKUP/.created"; return 0; fi
  grep -qxF "$1" "$BACKUP/.modified" 2>/dev/null && return 0
  install -D -m "$(stat -c %a "$1")" "$1" "$BACKUP${1}" 2>/dev/null
  printf '%s\t%s\n' "$1" "$(stat -c %a "$1")" >> "$BACKUP/.modes"
  echo "$1" >> "$BACKUP/.modified"
}

set_mode() {  # set_mode <path> <mode>
  [ -e "$1" ] || { echo "  skip    $1 (not there)"; return 0; }
  cur="$(stat -c %a "$1")"
  [ "$cur" = "$2" ] && { echo "  ok      $1 is already $2"; return 0; }
  backup_file "$1"
  if [ "$DRYRUN" -eq 1 ]; then echo "  would   chmod $2 $1  (currently $cur)"
  else chmod "$2" "$1" && echo "  FIXED   $1  $cur -> $2"; CHANGED=$((CHANGED+1)); fi
}

set_sysctl() {  # set_sysctl <key> <value>
  cur="$(sysctl -n "$1" 2>/dev/null)"
  [ -z "$cur" ] && { echo "  skip    $1 (not on this kernel)"; return 0; }
  [ "$cur" = "$2" ] && { echo "  ok      $1 is already $2"; return 0; }
  if [ "$DRYRUN" -eq 1 ]; then echo "  would   set $1 = $2  (currently $cur)"; return 0; fi
  backup_file /etc/sysctl.d/60-shipcheck.conf
  touch /etc/sysctl.d/60-shipcheck.conf
  if grep -qE "^\s*$1\s*=" /etc/sysctl.d/60-shipcheck.conf; then
    sed -i "s|^\s*$1\s*=.*|$1 = $2|" /etc/sysctl.d/60-shipcheck.conf
  else
    printf '%s = %s\n' "$1" "$2" >> /etc/sysctl.d/60-shipcheck.conf
  fi
  echo "  FIXED   $1  $cur -> $2"; CHANGED=$((CHANGED+1)); SYSCTL_DIRTY=1
}
SYSCTL_DIRTY=0

make_logs_persistent() {
  if [ -d /var/log/journal ]; then echo "  ok      logs already survive reboots"; return 0; fi
  if [ "$DRYRUN" -eq 1 ]; then echo "  would   make the system journal persistent (capped at 1GB)"; return 0; fi
  backup_file /etc/systemd/journald.conf.d/60-shipcheck.conf
  mkdir -p /etc/systemd/journald.conf.d /var/log/journal
  printf '[Journal]\nStorage=persistent\nSystemMaxUse=1G\nCompress=yes\n' \
    > /etc/systemd/journald.conf.d/60-shipcheck.conf
  systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1
  systemctl restart systemd-journald >/dev/null 2>&1
  echo "  FIXED   logs now survive reboots (capped at 1GB)"; CHANGED=$((CHANGED+1))
}

echo
echo "shipcheck fix — the safe changes only"
[ "$DRYRUN" -eq 1 ] && echo "DRY RUN: nothing will actually change" || echo "backup: $BACKUP"
echo
'''

FIX_TAIL = r'''
if [ "$SYSCTL_DIRTY" -eq 1 ] && [ "$DRYRUN" -eq 0 ]; then
  sysctl --system >/dev/null 2>&1 || true
fi

echo
if [ "$DRYRUN" -eq 1 ]; then
  echo "Dry run finished. Run without --dry-run to apply."
elif [ "$CHANGED" -eq 0 ]; then
  echo "Nothing to change — it was all already correct."
  rmdir "$BACKUP" 2>/dev/null
else
  echo "$CHANGED change(s) applied."
  echo "Backup: $BACKUP    Undo with: sudo ./rollback.sh"
  echo "Check it worked:   sudo ./verify.sh"
fi
echo
echo "This script deliberately did NOT touch SSH, your firewall, sudo or PAM."
echo "Those fixes are in REPORT.md and you should do them by hand."
exit 0
'''

ROLLBACK = r'''#!/usr/bin/env bash
# Undo whatever fix.sh changed. Restores files and their original permissions.
set -u
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo ./rollback.sh"; exit 1; }
B="${1:-$(ls -1dt /root/.shipcheck-backup/*/ 2>/dev/null | head -1)}"; B="${B%/}"
[ -n "$B" ] && [ -d "$B" ] || { echo "No shipcheck backup found."; exit 1; }
echo "Undoing changes from $B"
n=0
[ -f "$B/.modified" ] && while IFS= read -r f; do
  [ -n "$f" ] || continue
  if [ -e "$B$f" ]; then install -D "$B$f" "$f" && echo "restored $f" && n=$((n+1)); fi
done < "$B/.modified"
[ -f "$B/.modes" ] && while IFS=$'\t' read -r f mode; do
  [ -n "$f" ] && [ -e "$f" ] && chmod "$mode" "$f" 2>/dev/null && echo "mode $mode  $f"
done < "$B/.modes"
[ -f "$B/.created" ] && while IFS= read -r f; do
  [ -n "$f" ] && [ -e "$f" ] && rm -f "$f" && echo "removed  $f" && n=$((n+1))
done < "$B/.created"
sysctl --system >/dev/null 2>&1
echo "Done — $n item(s) restored."
'''


def fix_sh(doc):
    safe = [f for f in doc["findings"] if f["fix"]["automate"] == "safe" and f.get("auto")]
    out = [FIX_HEAD]
    if not safe:
        out.append('echo "Nothing here needs the script — every fix in REPORT.md needs you or your agent."')
    for f in safe:
        a = f["auto"]
        out.append('echo "%s  %s"' % (f["id"], f["title"].replace('"', "'")[:70]))
        if a["kind"] == "chmod":
            for p in a["paths"]:
                out.append("set_mode %s %s" % (q(p), q(a["mode"])))
        elif a["kind"] == "sysctl":
            for k, v in a["values"]:
                out.append("set_sysctl %s %s" % (q(k), q(v)))
        elif a["kind"] == "journald_persistent":
            out.append("make_logs_persistent")
        out.append("")
    out.append(FIX_TAIL)
    return "\n".join(out)


def verify_sh(doc):
    safe = [f for f in doc["findings"] if f["fix"]["automate"] == "safe" and f.get("auto")]
    L = ["#!/usr/bin/env bash",
         "# Re-checks exactly what fix.sh claimed to fix. Nothing else.",
         "set -u", "PASS=0; FAIL=0",
         'ck() { got="$(eval "$2" 2>/dev/null)";',
         '      if [ "$got" = "$3" ]; then printf "  ok    %s\\n" "$1"; PASS=$((PASS+1));',
         '      else printf "  FAIL  %s (got \'%s\', wanted \'%s\')\\n" "$1" "${got:-nothing}" "$3"; FAIL=$((FAIL+1)); fi; }',
         'echo; echo "shipcheck verify"; echo']
    if not safe:
        L.append('echo "  fix.sh had nothing to do, so there is nothing to verify."')
    for f in safe:
        a = f["auto"]
        if a["kind"] == "chmod":
            for p in a["paths"]:
                L.append("[ -e %s ] && ck %s %s %s" %
                         (q(p), q("%s mode on %s" % (a["mode"], p)),
                          q("stat -c %%a %s" % q(p)), q(a["mode"])))
        elif a["kind"] == "sysctl":
            for k, v in a["values"]:
                L.append("ck %s %s %s" % (q("%s = %s" % (k, v)), q("sysctl -n %s" % q(k)), q(v)))
        elif a["kind"] == "journald_persistent":
            L.append("ck %s %s %s" % (q("logs survive reboot"),
                                      q("[ -d /var/log/journal ] && echo yes"), q("yes")))
    L += ['echo',
          'printf "%s passed, %s failed\\n" "$PASS" "$FAIL"',
          '[ "$FAIL" -eq 0 ] || echo "A FAIL means fix.sh has not run, or something reverted it."',
          '[ "$FAIL" -eq 0 ]']
    return "\n".join(L)


# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Write the shipcheck reports and fix scripts")
    ap.add_argument("run", nargs="?", default=None,
                    help="the shipcheck run directory (default: <repo>/outputs)")
    args = ap.parse_args()
    if not args.run:
        args.run = default_run_dir()

    try:
        doc = load(args.run)
    except FileNotFoundError:
        sys.exit("No findings.json in %s — run analyze.py first." % args.run)

    out = args.run if os.path.isdir(args.run) else os.path.dirname(args.run)
    files = {
        "REPORT.md": (report_md(doc), 0o644),
        "FIXME.md": (fixme_md(doc), 0o644),
        "fix.sh": (fix_sh(doc), 0o750),
        "rollback.sh": (ROLLBACK, 0o750),
        "verify.sh": (verify_sh(doc), 0o750),
    }
    for name, (content, mode) in files.items():
        p = os.path.join(out, name)
        with open(p, "w") as fh:
            fh.write(content.rstrip("\n") + "\n")
        os.chmod(p, mode)

    # Copy the recipes in beside FIXME.md. An agent handed the fix brief with no
    # recipes file will invent implementations, which is exactly what we are
    # trying to avoid.
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "..", "references", "fix-recipes.md"),
        os.path.join(here, "fix-recipes.md"),
    ):
        if os.path.exists(candidate):
            with open(candidate) as src, open(os.path.join(out, "fix-recipes.md"), "w") as dst:
                dst.write(src.read())
            break
    else:
        print("NOTE: fix-recipes.md not found next to the scripts — FIXME.md references it.\n"
              "      Copy it into %s manually, or the agent will improvise its fixes." % out,
              file=sys.stderr)

    F = doc["findings"]
    n_safe = len([f for f in F if f["fix"]["automate"] == "safe"])
    n_agent = len([f for f in F if f["fix"]["automate"] == "agent"])
    n_human = len([f for f in F if f["fix"]["automate"] == "human"])
    print("\nWrote to %s:" % out, file=sys.stderr)
    print("  REPORT.md    read this first", file=sys.stderr)
    print("  FIXME.md     paste into your AI agent  (%d task%s)" % (n_agent, "" if n_agent == 1 else "s"),
          file=sys.stderr)
    print("  fix.sh       sudo ./fix.sh             (%d safe fix%s)" % (n_safe, "" if n_safe == 1 else "es"),
          file=sys.stderr)
    print("  verify.sh    sudo ./verify.sh", file=sys.stderr)
    print("  rollback.sh  sudo ./rollback.sh", file=sys.stderr)
    if os.path.exists(os.path.join(out, "fix-recipes.md")):
        print("  fix-recipes.md  how to implement each fix (the agent reads this)", file=sys.stderr)
    if n_human:
        print("\n  %d item%s need%s you personally — see REPORT.md."
              % (n_human, "" if n_human == 1 else "s", "s" if n_human == 1 else ""), file=sys.stderr)


if __name__ == "__main__":
    main()
