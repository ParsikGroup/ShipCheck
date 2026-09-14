# Writing findings people actually act on

The person reading this shipped something and is now being told it is broken.
Your writing decides whether they fix it or close the tab.

## Lead with the attack, not the setting

| Don't write | Write |
|---|---|
| `sshd_config` has `PasswordAuthentication yes` | Anyone on the internet can guess your password, forever, with no limit. 41,000 bots tried this week. |
| Redis bound to `0.0.0.0` without `requirepass` | Your cache is on the internet with no password. Anyone can read every logged-in user's session — and on most setups, get a shell on the server. |
| `.env` tracked in git | Your API keys are in your repository history. Every clone has them. Deleting the file does not remove them. |
| Missing `Strict-Transport-Security` header | Free hardening. Doesn't fix a bug, takes one config line, and every security questionnaire asks for it. |

## Use their numbers

Numbers make it real:

- "41,238 failed SSH logins in the last 7 days"
- "your certificate expires in 6 days"
- "4 files contain live API keys"
- "23 security updates are waiting"

`shipcheck.sh` collects these. Use them.

## Rank by what actually happens

Order by "how bad is the worst realistic outcome, and how easy is it":

1. **Someone can get in right now with no skill.** Exposed unauthenticated
   database, `.git` served to the web, downloadable `.env`, leaked live keys.
2. **Someone gets in if they try a bit.** Password SSH on a public IP, known
   unpatched CVE, admin panel on the internet.
3. **Makes a bad day worse.** No backups, no logs, everything runs as root.
4. **Hardening.** Headers, sysctls, file permissions.

A missing security header listed above an exposed database is how you lose the
reader.

## Say what is fine

If the firewall is correct, the backups exist, the keys are clean — say so,
briefly, by name. It calibrates everything else. A report that is nothing but
problems reads as a scanner dump, and scanner dumps get ignored.

## Rotation first, always

When credentials have leaked, the code fix is secondary. Nothing is resolved
until the key is dead. Put the rotation list at the very top of your summary, as
a list, with the provider named:

> **Rotate these today, before anything else:**
> - Stripe live key — dashboard.stripe.com → Developers → API keys
> - OpenAI key — platform.openai.com → API keys
> - Database password — then update your app's connection string

## Never make them feel stupid

Every one of these findings is on thousands of production systems right now.
Committed `.env` files are the single most common mistake in software. Docker
bypassing ufw catches professionals constantly. Say "this catches almost
everyone" when it is true, because it usually is.

No lectures. No "you should have." They are here, which means they are already
doing more than most.

## Close with what is still untested

End every report by naming what was not checked — app permissions, business
logic, whether backups restore. Not as a disclaimer, as useful information. It
tells them what a real assessment would add, and it stops "shipcheck passed" from
becoming "we're secure."
