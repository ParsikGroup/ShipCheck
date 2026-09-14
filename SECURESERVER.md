# secureserver — the brief

You are hardening someone's Linux server. They are not a security engineer and
this is probably the only machine they have. **Losing their SSH access is a
worse outcome than leaving the box unhardened**, because an unhardened box is a
risk and a locked box is a dead one.

Work in two passes. The first is automated and cannot cost them access. The
second is where the real wins are, and it is done with a human present.

---

## Rules you must not break

1. **Never edit `sshd_config`, firewall rules, PAM or sudoers without the human
   watching, in a live session, with a second terminal open.** Not "after
   telling them". While they watch.
2. **Never `systemctl restart ssh`. Use `reload`.** Restart drops every existing
   connection, including the one holding their only working session open.
3. **Never enable a firewall before the SSH rule is in place and verified.** The
   order is: allow SSH, verify, then enable. Never the other way around.
4. **Always arm a revert timer before an access-affecting change**, and cancel it
   only after a *new* connection has been proven to work. The pattern is in
   every section below. Use it every time.
5. **Never change the SSH port or add 2FA unless they ask.** Both break their
   tooling, their deploy scripts and their muscle memory for no defensive gain
   against anything that matters.
6. **Never generate, replace or delete an SSH key.** If a key is missing, stop
   and have them create it on their own machine.
7. **Never reboot.** Tell them a reboot is needed and let them choose when.
8. **If you cannot verify a change worked, revert it.** An unverified hardening
   change is not a win, it is a liability with unknown blast radius.
9. **Do not report something as done that you did not verify.** Run the
   verification command and read its output.
10. **If they go quiet mid-procedure, revert and stop.** Do not continue an
    access-affecting sequence without the human.

---

## Pass 1 — the automated part

```bash
sudo ./skills/shipcheck/scripts/secureserver.sh
```

This applies everything that provably cannot cost them access: automatic
security updates, fail2ban with their own IP whitelisted, kernel hardening,
persistent logs, file permissions, idle-shell timeout, clock sync.

It backs up everything first and arms an auto-revert timer. **Tell the human
what they have to do**, because the script's own instructions are easy to miss:

> The machine will undo all of this by itself in ten minutes unless you open a
> **second** terminal, connect again, and run the `confirm.sh` command it
> printed. Keep the first terminal open while you do it.

Run `--dry-run` first if they are nervous. It prints the plan and stops.

If the machine is not Debian or Ubuntu, the script refuses. Do not work around
that — do Pass 2 by hand and skip Pass 1 entirely.

---

## Pass 2 — the changes that need a human

Each of these follows the same shape. Learn it once:

```
1. Prove the safe state works BEFORE you change anything.
2. Arm a timer that undoes the change on its own.
3. Make the change.
4. Open a NEW connection and prove it still works.
5. Cancel the timer.
```

If step 4 fails, **do nothing**. Wait for the timer. The machine repairs itself.

### 2.1 — SSH: keys only, no root login

This is the single highest-value change on the list. It is also the one that
locks people out, so the order matters.

**First, prove key auth already works.** From *their* machine, not the server:

```bash
ssh -o PasswordAuthentication=no -o PreferredAuthentications=publickey you@server 'echo KEY_AUTH_OK'
```

If that does not print `KEY_AUTH_OK`, **stop.** They have no working key and
disabling passwords will lock them out. Have them run `ssh-copy-id you@server`
from their own machine first, then test again. Do not create a key for them.

**Check how this server reads its config.** Ubuntu 22.04 and later use drop-in
files, and there is a trap:

```bash
grep -n '^Include' /etc/ssh/sshd_config
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null
grep -rn 'PasswordAuthentication\|PermitRootLogin' /etc/ssh/sshd_config.d/ 2>/dev/null
```

**sshd uses the FIRST value it sees for most keywords, not the last.** Ubuntu
ships `/etc/ssh/sshd_config.d/50-cloud-init.conf` containing
`PasswordAuthentication yes`. A file named `99-*.conf` sorts *after* it and is
therefore **ignored**. If that cloud-init file exists and sets either keyword,
you must edit that file, or name yours something that sorts before it. Check,
do not assume.

**Then:**

```bash
# 1. back up
sudo cp -a /etc/ssh/sshd_config /root/sshd_config.bak.$(date +%s)

# 2. write the drop-in (adjust the name if cloud-init got there first)
sudo tee /etc/ssh/sshd_config.d/49-secureserver.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
EOF

# 3. validate the syntax — this catches typos before they cost you the box
sudo sshd -t || echo "CONFIG IS BROKEN — DO NOT RELOAD"

# 4. arm the revert
sudo systemd-run --on-active=600 --unit=ssh-revert \
  /bin/sh -c 'rm -f /etc/ssh/sshd_config.d/49-secureserver.conf; systemctl reload ssh'

# 5. reload — NOT restart
sudo systemctl reload ssh
```

**Now the human opens a brand new terminal and connects.** Not a new tab in the
same session — a genuinely new SSH connection. If it works:

```bash
sudo systemctl stop ssh-revert.timer
```

If it does not work, they wait ten minutes and it fixes itself.

**Socket activation.** On Ubuntu 22.10 and later SSH is started by
`ssh.socket`, and `Port` and `ListenAddress` in `sshd_config` are silently
ignored. Check with `systemctl is-enabled ssh.socket`. This does not affect the
directives above, but it is why "I changed the port and nothing happened"
happens.

### 2.2 — Firewall: default deny inbound

**First, find out what is actually listening and what must stay reachable.**

```bash
sudo ss -tulpn | grep LISTEN
```

Go through that list with the human. For each port: is this meant to be
reachable from the internet? Write the answer down before touching anything.

```bash
# 1. SSH FIRST. Always. Before anything else.
sudo ufw allow 22/tcp comment 'ssh'

# 2. whatever else they actually need
sudo ufw allow 80/tcp comment 'http'
sudo ufw allow 443/tcp comment 'https'

# 3. defaults
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 4. arm the revert BEFORE enabling
sudo systemd-run --on-active=600 --unit=ufw-revert /usr/sbin/ufw --force disable

# 5. enable
sudo ufw --force enable
```

New terminal, new connection. If it works:

```bash
sudo systemctl stop ufw-revert.timer
sudo ufw status verbose
```

**IPv6.** Confirm `IPV6=yes` in `/etc/default/ufw`. A firewall that only filters
IPv4 on a machine with a public IPv6 address is not a firewall. A great many
"my server was locked down" stories end here.

**Docker ignores ufw. This is not a bug you can configure away.** A container
started with `-p 5432:5432` writes its own iptables rules in the `DOCKER-USER`
chain, which is evaluated *before* ufw's. The database is on the internet and
`ufw status` shows it as blocked. Do not try to fix this with ufw rules. Fix it
where the port is published:

```yaml
ports:
  - "127.0.0.1:5432:5432"   # correct — localhost only
  # - "5432:5432"           # wrong — the whole internet
```

Then `docker compose up -d` to re-create the container, and verify from
somewhere else that the port is closed.

### 2.3 — Only if they ask

Do not do these by default. Each one costs them something real.

- **PAM password quality** (`libpam-pwquality`). A bad edit to `/etc/pam.d/`
  can make `sudo` and login fail for everyone. Two terminals, revert timer,
  and keep a root shell open the entire time.
- **SSH on a non-standard port.** Stops log noise, stops nothing else. Breaks
  their deploy scripts and every teammate's config.
- **2FA on SSH.** Real defence, real lockout risk, and it must be tested from a
  second session before the first one is closed.
- **AppArmor enforcement.** Can break working applications in ways that are
  hard to diagnose. Only with a rollback plan.
- **Disabling legacy filesystem modules.** Fine on most servers, breaks
  anything that mounts a USB drive or an unusual image.

---

## Verification

Do not report success without running these and reading the output.

```bash
# updates are actually configured
systemctl is-enabled unattended-upgrades; apt-config dump | grep Periodic::Unattended

# fail2ban is running and watching ssh
sudo fail2ban-client status sshd

# kernel settings took
sysctl kernel.randomize_va_space fs.suid_dumpable net.ipv4.tcp_syncookies

# logs persist
journalctl --disk-usage; ls -d /var/log/journal

# ssh is key-only  (expect: "Permission denied (publickey)")
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no you@server

# firewall is on, including v6
sudo ufw status verbose

# what is still exposed
sudo ss -tulpn | grep LISTEN
```

Then re-run the audit and compare:

```bash
sudo ./skills/shipcheck/scripts/shipcheck.sh
```

---

## What to tell them at the end

Plain language, no jargon, three parts:

1. **What changed**, in terms of what an attacker can no longer do. Not
   "enabled `kernel.kptr_restrict`" — "a program running as a normal user on
   this box can no longer read kernel memory addresses, which is a step in most
   privilege-escalation chains."
2. **What is still open and why.** If they need port 5432 reachable, say so and
   say what protects it instead.
3. **The one thing they have to do themselves.** Usually: reboot for a kernel
   update, or rotate a key that leaked. Give them the exact command.

And tell them where the undo is:

```bash
sudo /var/backups/secureserver/<timestamp>/rollback.sh
```
