#!/usr/bin/env python3
"""Prove each rule fires on the real technique.

Loads the rules into the lab manager, runs each technique from tests/proof.yaml
on the victim, and checks the rule fired in the run window. Writes the evidence
to docs/evidence/. Point LAB_DIR at the home-soc-lab checkout.
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

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAB = pathlib.Path(os.environ.get("LAB_DIR", ROOT / "../home-soc-lab")).resolve()
EV = ROOT / "docs/evidence"
SETTLE = 14
_TS = re.compile(r"([+-]\d{2})(\d{2})$")


def compose(*args, capture=False):
    return subprocess.run(["docker", "compose", *args], cwd=LAB, check=False,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None, text=True)


def victim(cmd: str):
    compose("exec", "-T", "victim", "sh", "-c", cmd, capture=True)


def parse_ts(s: str) -> float:
    return dt.datetime.fromisoformat(_TS.sub(r"\1:\2", s)).timestamp()


def probe(user: str, count: int):
    compose("--profile", "test", "run", "--rm", "--no-deps",
            "probe", "victim", user, str(count), capture=True)


def spray(users: int):
    names = " ".join(f"spray{i}" for i in range(1, users + 1))
    loop = (f'for u in {names}; do ssh -o BatchMode=yes -o StrictHostKeyChecking=no '
            f'-o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR '
            f'"$u@victim" true 2>/dev/null; done; true')
    compose("--profile", "test", "run", "--rm", "--no-deps",
            "--entrypoint", "sh", "probe", "-c", loop, capture=True)


def alerts_since(rule_id: str, since: float) -> list[dict]:
    out = compose("exec", "-T", "wazuh.manager", "cat",
                  "/var/ossec/logs/alerts/alerts.json", capture=True)
    hits = []
    for line in (out.stdout or "").splitlines():
        if f'"id":"{rule_id}"' not in line:
            continue
        try:
            d = json.loads(line)
            if parse_ts(d["timestamp"]) >= since - 3:
                hits.append(d)
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
    return hits


def run_one(p: dict) -> dict:
    t0 = time.time()
    if p["kind"] == "victim":
        if p.get("setup"):
            victim(p["setup"])
            time.sleep(2)
            t0 = time.time()
        victim(p["command"])
    elif p["kind"] == "brute":
        probe(f"brute-{int(t0)}", p["count"])
    elif p["kind"] == "spray":
        spray(p["users"])
    time.sleep(SETTLE)
    hits = alerts_since(str(p["rule_id"]), t0)
    if p.get("cleanup"):
        victim(p["cleanup"])
    sample = None
    if hits:
        h = hits[-1]
        sample = {"rule_id": h["rule"]["id"], "level": h["rule"]["level"],
                  "description": h["rule"]["description"],
                  "mitre": h["rule"].get("mitre", {}).get("id"),
                  "path": h.get("syscheck", {}).get("path"),
                  "full_log": (h.get("full_log") or "").strip()[:160]}
    return {"rule_id": p["rule_id"], "technique": p["technique"], "label": p["label"],
            "fired": bool(hits), "count": len(hits), "sample": sample}


def main() -> int:
    subprocess.run(["bash", str(ROOT / "bin/apply.sh")], check=True,
                   env={**os.environ, "LAB_DIR": str(LAB)})
    spec = yaml.safe_load((ROOT / "tests/proof.yaml").read_text())
    results = [run_one(p) for p in spec["proofs"]]
    for r in results:
        print(f"prove: {'PASS' if r['fired'] else 'FAIL'}  rule {r['rule_id']}  "
              f"{r['technique']:<10} {r['label']}")

    EV.mkdir(parents=True, exist_ok=True)
    (EV / "proof.json").write_text(json.dumps({"results": results}, indent=2))
    lines = ["# Proof each rule fires", "",
             "Each rule was tested by running the real technique on the lab victim.",
             "", "| Rule | Technique | Detection | Result | Level | Rule(s) |",
             "|---|---|---|---|---|---|"]
    for r in results:
        s = r["sample"]
        lines.append(f"| {r['rule_id']} | {r['technique']} | {r['label']} | "
                     f"{'✅ fired' if r['fired'] else '❌ did not fire'} | "
                     f"{s['level'] if s else '—'} | {s['rule_id'] if s else '—'} |")
    (EV / "proof.md").write_text("\n".join(lines) + "\n")

    passed = sum(r["fired"] for r in results)
    print(f"prove: {passed}/{len(results)} rules fired on their technique")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
