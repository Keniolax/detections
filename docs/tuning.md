# Tuning and false positives

A detection is only useful if it is quiet when nothing is wrong. `make noise`
runs ordinary activity near the rules and checks none of them fire:

- two failed SSH logins as one user (a mistyped password), under every threshold;
- reading a watched file instead of changing it (FIM must not react to a read);
- writing to an unwatched path.

Result: no rule fired on benign activity. The output is in
[`evidence/noise.json`](evidence/noise.json).

## Per-rule notes

The file-integrity rules are high-signal because the paths they watch rarely
change on a running server. Their real false positive is a legitimate change by
an administrator or a package, so each should be read as "who changed this, and
was it expected", not "block it".

| Rule | Technique | What tunes it | The honest false positive |
|---|---|---|---|
| 100210 authorized_keys | T1098.004 | path is exact | an admin adding a real key |
| 100211 shell profile | T1546.004 | path list | a package shipping a profile script |
| 100212 clear history | T1070.003 | history files only | a user clearing their own history (rare on a service account) |
| 100213 cron job | T1053.003 | cron directories | a package installing a cron job |
| 100214 systemd service | T1543.002 | `.service` under unit dirs | a package installing a service |
| 100221 ld.so.preload | T1574.006 | one exact file | a monitoring agent that installs a preload library (allowlist it) |
| 100220 new account | T1136.001 | child of the auth event | routine account provisioning (correlate with a ticket) |
| 100222 password spraying | T1110.003 | `different_srcuser`, 6 users in 120s | several real users failing from one jump host at once (rare) |

## The thresholds that matter

The two correlation rules are where tuning is a real choice:

- **Brute force** is already caught by Wazuh's built-in rule 5712 (8 failures
  from one source in 120s). This repo does not re-ship it; see the design notes
  in the README. Writing a second rule for it adds a duplicate alert, not a
  detection.
- **Password spraying** (100222) is the gap the built-in leaves. Spraying tries
  a few guesses against many accounts, so each account stays under the
  brute-force threshold and 5712 never fires. 100222 counts *different*
  usernames from one source instead. Six in 120 seconds is low enough to catch
  a slow spray and high enough to clear a couple of users fat-fingering a
  password at the same time. Raise it if a shared host is noisy; lower it to
  catch a slower spray at the cost of more review.
