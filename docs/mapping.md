# Sigma to Wazuh

The Sigma rules in `sigma/` are the detections. `convert/sigma_to_wazuh.py`
turns them into `wazuh/local_rules.xml`. There is no maintained pySigma backend
for Wazuh's file-integrity and correlation rules, so the converter is written
for the two rule classes this repo uses, and it is strict: a rule shape it does
not recognise stops the run, so the Wazuh output can never drift from the Sigma
intent. CI runs it with `--check` to keep the committed XML in sync.

## File events

A Sigma `file_event` rule matches on `TargetFilename`. Wazuh's file-integrity
monitor reports the path in the `file` field of a `syscheck` event, so the
converter emits a child of the `syscheck` group with a regex on `file`.

| Sigma | Wazuh |
|---|---|
| `logsource.category: file_event` | `<if_group>syscheck</if_group>` |
| `TargetFilename\|endswith: /x` | `<field name="file" type="pcre2">/x$</field>` |
| `TargetFilename\|contains: /x/` | `<field name="file" type="pcre2">/x/</field>` |
| two selections joined by `and` | two `<field name="file">` entries (both must match) |
| `tags: attack.t1098.004` | `<mitre><id>T1098.004</id></mitre>` |

The telemetry is Wazuh's generic FIM alerts (rule 550 modified, 554 added).
These rules are children of those: they add the path match, a name, a severity
and the ATT&CK mapping, turning a generic "file changed" into a named technique.

## Correlation (auth)

Brute force and spraying count events over time. Sigma states this with a
`count() ... >= N` condition; Wazuh states it with a frequency rule that counts
a parent rule's matches. Sigma's aggregation does not map one-to-one to Wazuh's
frequency syntax, so these rules carry the Wazuh parameters in the Sigma file's
`wazuh:` block, and the converter reads them.

| Sigma `wazuh:` | Wazuh |
|---|---|
| `if_matched_sid: '5710'` | `<if_matched_sid>5710</if_matched_sid>` |
| `frequency: 8`, `timeframe: 120` | `frequency="8" timeframe="120"` on the rule |
| `modifiers: [same_source_ip]` | `<same_source_ip />` |
| `modifiers: [different_srcuser]` | `<different_srcuser />` |

`different_srcuser` is what separates spraying from brute force: it fires only
when the failed logins are for *different* usernames from one source.
