"""CI checks for the detection rules. No lab needed.

They pin the rule set's shape: every Sigma rule is well-formed, maps to one
Wazuh rule with the same ATT&CK id, and the committed Wazuh ruleset is what the
converter produces from the Sigma sources.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "convert"))
import sigma_to_wazuh as conv  # noqa: E402

SIGMA = ROOT / "sigma"
RULES = (ROOT / "wazuh/local_rules.xml").read_text()


def sigma_docs():
    return [yaml.safe_load(f.read_text()) for f in sorted(SIGMA.glob("*.yml"))]


def test_at_least_eight_rules():
    assert len(list(SIGMA.glob("*.yml"))) >= 8


def test_each_sigma_rule_is_well_formed():
    seen_ids = set()
    for d in sigma_docs():
        for key in ("title", "id", "description", "logsource", "detection", "level", "tags"):
            assert key in d, f"{d.get('title')}: missing {key}"
        assert d["id"] not in seen_ids, "duplicate sigma id"
        seen_ids.add(d["id"])
        assert any(t.startswith("attack.t") for t in d["tags"]), \
            f"{d['title']}: no ATT&CK technique tag"
        assert "wazuh" in d and "id" in d["wazuh"]


def test_wazuh_rule_ids_unique():
    ids = re.findall(r'<rule id="(\d+)"', RULES)
    assert len(ids) == len(set(ids)), "duplicate Wazuh rule id"
    assert len(ids) == len(sigma_docs())


def test_every_technique_has_a_wazuh_rule():
    for d in sigma_docs():
        for mid in conv.mitre_ids(d["tags"]):
            assert f"<id>{mid}</id>" in RULES, f"{mid} missing from Wazuh ruleset"


def test_committed_ruleset_matches_converter():
    assert conv.build() == RULES, "wazuh/local_rules.xml is stale; run make convert"


def test_tactics_span_several():
    tactics = set()
    for d in sigma_docs():
        for t in d["tags"]:
            if t.startswith("attack.") and not re.match(r"attack\.t\d", t):
                tactics.add(t)
    assert len(tactics) >= 3, "rules should span several tactics"
