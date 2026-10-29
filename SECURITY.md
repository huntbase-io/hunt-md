# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/huntbase-io/hunt-md/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab). Do not open a
public issue or pull request for a suspected vulnerability.

Include the spec version or `huntmd` version, the command you ran, a minimal
input file that shows the problem, and what you expected to happen. We will
acknowledge your report within 5 working days, keep you updated while we look
into it, and credit you in the advisory unless you prefer otherwise.

Security fixes are made against the latest spec version and the `huntmd` on
`main`.

## Scope

This repository holds the hunt.md specification, the hunt library and the
reference tooling (`huntmd`, in `tools/`). In scope are, for example:

- `huntmd` doing something unsafe with a crafted hunt.md, definition, CACAO
  or MISP file: running code, reading or writing files outside the paths you
  passed, or hanging or exhausting memory (for example, regular expression
  backtracking);
- the linter passing a hunt that breaks a safety rule it claims to enforce,
  such as an ungated destructive `action`, an unbounded `agent` step, or a hunt
  above TLP:GREEN passing `--max-tlp green`;
- a gap in the specification that would lead a conforming runtime to take an
  unsafe action, such as running a destructive step without approval;
- a hunt in `hunts/` whose steps would change or exfiltrate data, or that
  contains credentials, personal data or other sensitive material.

Issues in runtimes that read hunt.md (for example Huntbase, MISP or a CACAO
executor) should be reported to those projects. A runtime that ignores a rule
the spec requires is a bug in that runtime.

## Using hunts safely

A hunt is a playbook that a runtime may execute. Read a hunt's queries and
actions before you run it, keep the default guardrails (SPEC §8.1), run
queries with read-only credentials where you can, and keep `approval:
required` on any action that changes state.
