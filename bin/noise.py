#!/usr/bin/env python3
"""Generate benign activity and check the rules stay quiet.

A rule that fires on normal activity is noise. This runs ordinary things that
sit near the rules -- a couple of mistyped SSH logins, reading a watched file
rather than changing it, writing to an unwatched path -- and checks that none
of the correlation or unwatched-path rules fire. It reports any that do.
Point LAB_DIR at the home-soc-lab checkout.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAB = pathlib.Path(os.environ.get("LAB_DIR", ROOT / "../home-soc-lab")).resolve()
EV = ROOT / "docs/evidence"
RULE_IDS = [str(i) for i in range(100210, 100223)]
_TS = re.compile(r"([+-]\d{2})(\d{2})$")


def compose(*args, capture=False):
    return subprocess.run(["docker", "compose", *args], cwd=LAB, check=False,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None, text=True)


def victim(cmd):
    compose("exec", "-T", "victim", "sh", "-c", cmd, capture=True)


def parse_ts(s):
    return dt.datetime.fromisoformat(_TS.sub(r"\1:\2", s)).timestamp()


def fired_since(since):
    out = compose("exec", "-T", "wazuh.manager", "cat",
                  "/var/ossec/logs/alerts/alerts.json", capture=True)
    hits = {}
    for line in (out.stdout or "").splitlines():
        for rid in RULE_IDS:
            if f'"id":"{rid}"' in line:
                try:
                    d = json.loads(line)
                    if parse_ts(d["timestamp"]) >= since - 2:
                        hits.setdefault(rid, 0)
                        hits[rid] += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass
    return hits


def main() -> int:
    print("noise: generating benign activity")
    t0 = time.time()
    # 1. Two failed logins as one user -- a mistyped password, under any threshold.
    compose("--profile", "test", "run", "--rm", "--no-deps",
            "probe", "victim", f"realuser-{int(t0)}", "2", capture=True)
    # 2. Read a watched file without changing it. FIM must not react to a read.
    victim("cat /root/.bashrc >/dev/null 2>&1 || true")
    victim("cat /etc/profile.d/bash_completion.sh >/dev/null 2>&1 || true")
    # 3. Write to an unwatched path. No rule should match.
    victim("echo scratch > /tmp/benign.txt; rm -f /tmp/benign.txt")
    time.sleep(16)

    hits = fired_since(t0)
    EV.mkdir(parents=True, exist_ok=True)
    (EV / "noise.json").write_text(json.dumps({"false_positives": hits}, indent=2))
    if hits:
        print("noise: FALSE POSITIVES:")
        for rid, n in hits.items():
            print(f"       rule {rid} fired {n} time(s) on benign activity")
        return 1
    print("noise: no rule fired on benign activity (0 false positives)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
