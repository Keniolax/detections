# detections

Eight detection rules for Linux attacker techniques, written in
[Sigma](https://sigmahq.io/) and converted to Wazuh. Each one was tested by
running the real technique against the [home-soc-lab](https://github.com/Keniolax/home-soc-lab)
SIEM and watching the rule fire.

Week 4 of this bootcamp mapped what that lab could and could not detect and
found it blind to most of the ATT&CK matrix. These rules close the part of that
gap the lab can actually see.

## What it detects

| Rule | ATT&CK | Technique | Telemetry |
|---|---|---|---|
| 100210 | T1098.004 | SSH authorized_keys modified | file integrity |
| 100211 | T1546.004 | Shell profile modified | file integrity |
| 100212 | T1070.003 | Shell command history cleared | file integrity |
| 100213 | T1053.003 | Cron job created | file integrity |
| 100214 | T1543.002 | Systemd service created | file integrity |
| 100221 | T1574.006 | Dynamic linker preload file created | file integrity |
| 100220 | T1136.001 | Local account created | auth log |
| 100222 | T1110.003 | SSH password spraying | auth log |

Six tactics: Persistence, Defense Evasion, and Credential Access.

## How it works

The Sigma rules in `sigma/` are the detections. `convert/sigma_to_wazuh.py`
turns them into `wazuh/local_rules.xml`; the two stay in sync and CI checks it.
The file-integrity rules are children of Wazuh's generic "file changed" alerts:
they add the path, a name, a severity and the ATT&CK mapping. The spraying rule
counts failed logins for different usernames from one source. See
[docs/mapping.md](docs/mapping.md).

## Run it

Needs a running `home-soc-lab` (`make up` there). Point `LAB_DIR` at it.

```bash
make check                     # validate the rules, no lab needed
LAB_DIR=../home-soc-lab make apply    # load the rules into the manager
LAB_DIR=../home-soc-lab make prove    # run each technique and watch its rule fire
LAB_DIR=../home-soc-lab make noise    # benign activity, check for false positives
```

`make prove` runs all eight techniques and reports which rule fired for each.
The evidence it writes is in [docs/evidence/](docs/evidence/): the
[proof table](docs/evidence/proof.md) and the raw alerts.

## What you'll see

```
prove: PASS  rule 100210  T1098.004  SSH authorized_keys modified
...
prove: 8/8 rules fired on their technique
noise: no rule fired on benign activity (0 false positives)
```

## Design decisions

**Decision: the telemetry is file integrity and the auth log, not process execution.**
*Alternatives considered:* `auditd` with `execve` rules, which would catch the
discovery and execution techniques too.
*Why:* the lab runs in a container, and the cloud host blocks the kernel audit
netlink even for a privileged container, so `auditd` cannot run. Real-time file
integrity monitoring uses inotify and needs no privilege, so it works. The rules
target what the sensor can see.
*Cost accepted:* command-only techniques (discovery, shell execution) stay
blind here. Detecting those needs a host sensor — `auditd`, Falco, or Sysmon for
Linux — that a sandboxed lab cannot run. That limit is stated, not hidden.

**Decision: no brute-force rule.**
*Alternatives considered:* writing one, to match the eight-rule target.
*Why:* Wazuh already ships rule 5712 for SSH brute force, and its correlation
consumes the same failed-login events, so a second rule adds a duplicate alert,
not a detection. Knowing what a SIEM already provides is part of the job. The
gap the built-in leaves is password *spraying* — many usernames, few tries
each, under the per-user threshold — so that is the rule worth writing (100222).

**Decision: Sigma is the source, Wazuh is generated.**
*Alternatives considered:* writing Wazuh XML directly.
*Why:* Sigma is portable across SIEMs and is the detection-as-code artifact a
reviewer can read. No maintained pySigma backend targets Wazuh's FIM and
correlation rules, so `convert/sigma_to_wazuh.py` is a focused converter for the
two rule classes here, and it is strict: a rule shape it does not recognise
stops the build.
*Cost accepted:* the converter covers these rule classes, not all of Sigma.

## How you would evade these

- The file rules watch specific paths. Persistence in a path they do not watch
  (a user systemd unit, a different RC file) is missed. The answer is to widen
  the watch list, which trades coverage for noise.
- The file rules need the file to exist when the agent takes its baseline, so a
  watched file must be pre-created (this lab creates an empty `ld.so.preload`).
- The spraying rule counts six usernames in two minutes. A slow spray, a few
  guesses an hour, stays under it. Lowering the threshold catches the slow spray
  and costs more review.

## Limits

- Eight techniques, not the whole matrix. Command execution and network
  techniques are not covered here — the lab has no sensor for them.
- Tested against this one lab, on Linux. The Sigma rules are portable; the
  Wazuh rules are for Wazuh 4.x.

## License

MIT. See [LICENSE](LICENSE).
