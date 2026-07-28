<!--
Thanks for contributing. Delete the sections that don't apply.
CI runs the same checks you can run locally:
    pip install ./tools && huntmd validate hunts/your-hunt.md
    python tools/tests/check.py
-->

## What this is

<!-- One line: a new hunt, a spec change, a tooling fix. -->

## For a new hunt

- **Threat / behaviour:** <!-- what an adversary is doing -->
- **Data sources needed:** <!-- SIEM, EDR, identity provider… -->
- **Known false positives:** <!-- what legitimately looks like this -->
- **How the logic was verified:** <!-- tested against real data? derived from an advisory? -->

Checklist:

- [ ] One hypothesis (multi-hypothesis work is split into separate files)
- [ ] At least one `attack.tXXXX` label
- [ ] `references:` cite an advisory, ATT&CK page, or writeup a reviewer can check
- [ ] Queries are parameterized (`params=(…)` + `{{…}}`), not hard-coded
- [ ] Any `if~:` routes its `indeterminate:` branch
- [ ] Any `agent` step has `tools` and `max_iterations`
- [ ] Any destructive `action` is behind `approval: required` or a decision
- [ ] **`tlp:` is `clear` or `green`** — this repository is public. Anything more
      restricted belongs in a private library, not here.
- [ ] No customer names, internal hostnames, tenant identifiers, or licensed
      detection content

## For a spec change

- **What breaks without it:** <!-- the hunt you can't express today -->
- [ ] `SPEC.md` updated
- [ ] Runtime impact recorded in `PROFILES.md` (capability matrix row)
- [ ] Reference tooling updated, or the gap noted deliberately
- [ ] Existing hunts still lint and round-trip (`python tools/tests/check.py`)

## For tooling

- [ ] `python tools/tests/check.py` passes
- [ ] Stayed dependency-free (stdlib + PyYAML) so `huntmd` still vendors cleanly
