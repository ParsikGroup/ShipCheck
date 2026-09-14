# Proving what the internet can actually reach

This is the most valuable thing shipcheck does and the easiest to get wrong.

## The three layers

A service is reachable from the internet only when **all** of these are true:

1. It is **bound** to a routable address (`0.0.0.0`, `::`, or a public IP) rather
   than to `127.0.0.1`.
2. The **host firewall** allows it (ufw, nftables, firewalld).
3. The **network in front** allows it — a cloud provider security group, or on a
   home connection, a port forward on the router.

From on the machine you can see layers 1 and 2. You cannot see layer 3. So a
report written from inside the box can say "this is listening on all interfaces"
and must not say "this is exposed to the internet."

## Do the check yourself when you can

If you are running anywhere other than the target — the user's laptop, a
different server, a cloud sandbox with network access — just do it:

```bash
nmap -Pn -sT -p- --min-rate 1000 <public-ipv4>
nmap -6 -Pn -sT -p- --min-rate 1000 <public-ipv6>
```

No nmap available:

```bash
for p in 22 80 443 3306 5432 6379 8080 9000 27017; do
  timeout 3 bash -c "echo >/dev/tcp/<ip>/$p" 2>/dev/null && echo "$p OPEN"
done
```

Only scan the address the user has confirmed is theirs. Scanning a neighbour
because you guessed at a range is not acceptable, and on a shared host the IP may
not be what you think.

## When you are on the box, hand it over cleanly

Do not just say "you should scan from outside." Give them the exact thing to
paste, with their real IP filled in, and tell them where to run it:

> Your public IP is **203.0.113.10**. Open a terminal on your phone (Termux) or
> any computer that is *not* on your home network — mobile data works — and run:
>
> ```
> nmap -Pn -p- 203.0.113.10
> ```
>
> Paste me what comes back and I'll tell you which of those should not be there.

`shipcheck.sh` already looked up the public IPv4 and IPv6 and put them in the
report, so you can fill them in.

## IPv6 is where servers are actually open

This is the finding, over and over:

- On IPv4, a home router does NAT. Nothing gets in unless a port is forwarded.
  People treat that as a firewall. It works by accident.
- **IPv6 has no NAT.** Every device gets a globally routable address. The only
  thing between it and the internet is the router's IPv6 firewall, which is a
  separate setting many people have never opened.
- Most Linux services bind to `::` by default, which is dual-stack — so it is
  listening on IPv6 whether anyone meant it to or not.
- `iptables` rules do not apply to IPv6. `ip6tables` is a separate ruleset. And
  `ufw` with `IPV6=no` in `/etc/default/ufw` reports "active" while filtering
  nothing on v6.

Always run the `-6` scan. Always check `ip -6 addr show scope global` and
`/etc/default/ufw`.

## Home servers: check the router, not just the box

Two things `shipcheck.sh` cannot see:

- **Port forwards.** They live on the router. Ask the user to open its admin page
  and read the list. A forward set up two years ago for something long deleted is
  extremely common.
- **UPnP.** If it is on, applications have been opening ports on the router by
  themselves without telling anyone. Ask them to check, and to turn it off unless
  something specific needs it.

## Behind a tunnel, most of this evaporates

If everything reaches the app through a Cloudflare Tunnel, Tailscale, or a
similar overlay, and no ports are forwarded at all, then the exposure findings
largely do not apply — the box is not directly reachable. Say so, drop the
severity, and shift the focus to the app and to what happens if the tunnel
credentials leak.

Worth confirming rather than assuming: run the external scan anyway. People often
have a tunnel *and* a forgotten port forward.
