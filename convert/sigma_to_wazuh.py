#!/usr/bin/env python3
"""Convert the Sigma rules in sigma/ to a Wazuh local ruleset.

No maintained pySigma backend targets Wazuh's FIM and correlation rules, so
this is a focused converter for the two rule classes this repo uses:

  - file_event  -> a child of the syscheck group that matches the file path.
  - auth        -> a child of an auth rule (if_sid) or a frequency correlation
                   rule (if_matched_sid), taking the Wazuh-specific parameters
                   from the Sigma rule's `wazuh:` block.

It is deliberately strict: a Sigma rule whose shape it does not recognise stops
the run, so the Wazuh output can never silently drift from the Sigma intent.
Run it with --check to fail if wazuh/local_rules.xml is out of date.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import xml.sax.saxutils as sx

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIGMA = ROOT / "sigma"
OUT = ROOT / "wazuh/local_rules.xml"


def esc(pattern: str) -> str:
    return re.escape(pattern)


def mitre_ids(tags: list[str]) -> list[str]:
    ids = []
    for t in tags:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", t)
        if m:
            ids.append(m.group(1).upper())
    return ids


def field_regex(doc: dict) -> list[str]:
    """Return one or more pcre2 patterns for the `file` field (AND-ed)."""
    det = doc["detection"]
    cond = det["condition"].strip()

    def patterns(selname: str) -> tuple[str, list[str]]:
        sel = det[selname]
        (key, vals), = sel.items()
        vals = vals if isinstance(vals, list) else [vals]
        mod = key.split("|")[1] if "|" in key else "equals"
        return mod, vals

    def alt(mod: str, vals: list[str]) -> str:
        parts = [esc(v) + ("$" if mod == "endswith" else "") for v in vals]
        return "(?:" + "|".join(parts) + ")"

    if cond == "selection":
        mod, vals = patterns("selection")
        return [alt(mod, vals)]
    if cond == "selection or selection_dir":
        m1, v1 = patterns("selection")
        m2, v2 = patterns("selection_dir")
        merged = [esc(v) + "$" for v in v1] + [esc(v) for v in v2]
        return ["(?:" + "|".join(merged) + ")"]
    if cond == "selection and selection_ext":
        m1, v1 = patterns("selection")
        m2, v2 = patterns("selection_ext")
        return [alt(m1, v1), alt(m2, v2)]
    raise ValueError(f"{doc['title']}: unsupported condition {cond!r}")


def rule_xml(doc: dict) -> str:
    wz = doc["wazuh"]
    rid, level = wz["id"], wz["level"]
    desc = sx.escape(doc["title"])
    parent = wz["parent"]
    lines = []
    attrs = f'id="{rid}" level="{level}"'
    if "frequency" in parent:
        attrs += f' frequency="{parent["frequency"]}" timeframe="{parent["timeframe"]}"'
    lines.append(f'  <rule {attrs}>')

    cat = doc["logsource"].get("category")
    if cat == "file_event":
        lines.append("    <if_group>syscheck</if_group>")
        for rx in field_regex(doc):
            lines.append(f'    <field name="file" type="pcre2">{sx.escape(rx)}</field>')
    elif "if_sid" in parent:
        lines.append(f'    <if_sid>{parent["if_sid"]}</if_sid>')
    elif "if_matched_sid" in parent:
        lines.append(f'    <if_matched_sid>{parent["if_matched_sid"]}</if_matched_sid>')
        for mod in parent.get("modifiers", []):
            lines.append(f"    <{mod} />")
    else:
        raise ValueError(f"{doc['title']}: no usable parent")

    lines.append(f"    <description>{desc}</description>")
    for mid in mitre_ids(doc.get("tags", [])):
        lines.append(f"    <mitre><id>{mid}</id></mitre>")
    lines.append("  </rule>")
    return "\n".join(lines)


def build() -> str:
    docs = []
    for f in sorted(SIGMA.glob("*.yml")):
        docs.append(yaml.safe_load(f.read_text()))
    docs.sort(key=lambda d: d["wazuh"]["id"])
    body = "\n".join(rule_xml(d) for d in docs)
    return (
        "<!-- Generated from sigma/ by convert/sigma_to_wazuh.py. Do not edit by hand. -->\n"
        '<group name="lab,detections,">\n' + body + "\n</group>\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed XML is out of date")
    args = ap.parse_args()
    xml = build()
    if args.check:
        current = OUT.read_text() if OUT.exists() else ""
        if current != xml:
            print("sigma_to_wazuh: wazuh/local_rules.xml is out of date; "
                  "run `python convert/sigma_to_wazuh.py`", file=sys.stderr)
            return 1
        print("sigma_to_wazuh: wazuh/local_rules.xml is up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(xml)
    print(f"sigma_to_wazuh: wrote {OUT} from {len(list(SIGMA.glob('*.yml')))} Sigma rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
