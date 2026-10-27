# Proof each rule fires

Each rule was tested by running the real technique on the lab victim.

| Rule | Technique | Detection | Result | Level | Rule(s) |
|---|---|---|---|---|---|
| 100210 | T1098.004 | SSH authorized_keys modified | ✅ fired | 10 | 100210 |
| 100211 | T1546.004 | Shell profile modified | ✅ fired | 10 | 100211 |
| 100212 | T1070.003 | Bash history cleared | ✅ fired | 8 | 100212 |
| 100213 | T1053.003 | Cron job created | ✅ fired | 10 | 100213 |
| 100214 | T1543.002 | Systemd service created | ✅ fired | 10 | 100214 |
| 100220 | T1136.001 | Local account created | ✅ fired | 8 | 100220 |
| 100221 | T1574.006 | Dynamic linker preload file created | ✅ fired | 12 | 100221 |
| 100222 | T1110.003 | SSH password spraying (many users) | ✅ fired | 12 | 100222 |
