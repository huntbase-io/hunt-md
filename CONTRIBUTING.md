# Contributing a hunt

Thanks for adding to the hunt.md library. Hunts are reviewed like code — in a PR,
against the format spec and a lint pass.

## Add a hunt

1. Copy `templates/hunt-template.md` into `hunts/`.
2. **Name the file** after the hunt, kebab-cased: `hunts/<short-slug>.md`
   (e.g. `hunts/kerberoasting.md`, `hunts/scattered-spider-identity-takeover.md`).
3. Fill in the frontmatter and steps per [`SPEC.md`](./SPEC.md). At minimum:
   - a `hypothesis` (what the hunt tests),
   - one or more `labels: attack.tXXXX` techniques,
   - `targets` and `parameters` your steps reference,
   - at least one `query` or `collection` step and, where useful, an `agent`
     step and a decision.
4. Lint it locally — CI runs exactly this:

   ```bash
   pip install ./tools
   huntmd validate hunts/my-hunt.md --profile format --max-tlp green
   huntmd validate hunts/my-hunt.md --profile quality   # hunts in this repo must pass it
   python tools/tests/check.py
   ```

5. Open a PR. Describe the threat, the data sources needed, and any known false
   positives.

## Authoring rules (what the linter checks)

- **Reachability** — every step is reachable from a start; no dangling `→`.
- **Variables def-before-use** — a `$var`/`{{param}}` is defined (as an `out=`,
  a parameter, or an agent output) before it's read.
- **Queries have a `target`** — every query/collection names a `targets:` entry.
- **Fuzzy conditions have `indeterminate:`** — an `if~:` MUST route indeterminate
  (recommended: to a human `task`).
- **Agent steps are bounded** — every `agent` step has a `tools` allowlist and
  `max_iterations`.
- **Guardrails stay at their defaults** unless you have a reason — relaxing
  `telemetry`, `evidence`, `missing_data` or `claims` warns, and a reviewer will
  ask why (SPEC §8.1).
- **Confidence is ordinal** — `(confidence: high)`, not `>= 0.8`. A model's
  numeric confidence isn't calibrated between runs.
- **"We couldn't look" never closes a hunt** — route `unavailable:` to a human or
  a collection step, never to `end` — and name what the dead end costs:
  `unavailable: → escalate (blind_spot: <id>)` with a `blind_spots:` entry
  (SPEC §3.5).
- **Say what the hunt can see** — when the hunt comes from an intrusion report,
  `scenario:` + `coverage:` say per stage whether it is covered, not visible,
  or out of scope (SPEC §3.4).
- **Say what a query reads and what silence proves** — `reads:`, `verified:`,
  `expected:` and `silence:` on query steps (SPEC §5.5–§5.6); a hunt must not
  close on an empty result its own author marked as proving nothing.
- **Destructive actions are gated** — any `action` that changes state
  (disable/isolate/block/…) sits behind `approval: required` or a preceding
  decision.
- **Languages are declared** — the query language tag is present; unknown
  languages are allowed but warned (portability lint).
- **Portability** — prefer abstract `targets` (`category:`); add per-runtime
  `bindings` (e.g. `huntbase: { product: … }`) rather than hard-coding a product
  as the only option.
- **Targets resolve to a telemetry plane** — a plane category (`endpoint`,
  `iam`, …) derives it; a store (`siem`, `datalake`) states
  `telemetry: [identity, …]` (SPEC §6). A query target with no plane warns.
- **Say why the hunt exists** — the `hunt:` block (SPEC §3.3): `trigger`,
  `handoff`, and a prose `justification`. Off-vocabulary values warn; a
  missing justification is a `--profile quality` warning.
- **Shareable via MISP** (optional, `--profile misp`) — with the two rules above
  met and an ATT&CK label, peers filtering their MISP instance can find the
  hunt; nothing MISP-specific is needed. See PROFILES.md §3.

## What belongs in this repository

This repository is **public and MIT-licensed**. Everything in it is world-readable
forever, including anything you push and then delete — so the boundary is
enforced mechanically, not by reviewer memory.

**Keep out of this repo:**

- Hunts above **TLP:GREEN**. CI runs `huntmd validate --max-tlp green` and fails
  the build otherwise. A hunt with no `tlp:` at all also fails — an unlabelled
  hunt is unreviewed, not safe.
- Customer names, tenant identifiers, internal hostnames, IP ranges, or
  account names — including in example output and comments.
- Detection content you don't have the rights to publish (vendor rule packs,
  licensed feeds, content from a paid subscription).
- Anything derived from an engagement under NDA, even if generalised, unless the
  client has agreed in writing.

If a hunt is genuinely useful but can't be public, the right home is a **private
hunt library** — a separate private repository that consumes this one as a
pinned dependency. The same format, the same tooling, a different sharing
boundary. Nothing about hunt.md requires your hunts to be public.

**Redact before you open an issue**, too. Issues and PR discussions are as public
as the code.

## Certificate of origin

By opening a PR you confirm you have the right to contribute the content under
this repository's [`LICENSE`](./LICENSE), and that it isn't subject to a
confidentiality obligation. Sign your commits off if your employer requires it:

```bash
git commit -s -m "Add hunt for ..."
```

## Scope & quality

- One hypothesis per hunt. Split multi-hypothesis investigations into separate
  files (link them with `run:` if one composes another).
- Keep queries parameterized (`params=(…)` + `{{…}}`), not hard-coded — it's
  injection-safe and lets importers collect inputs at launch.
- Cite `references` (advisory, ATT&CK, blog) so reviewers can verify the logic.

## Runtime support

Not every construct runs on every runtime — see the capability matrix in
[`PROFILES.md`](./PROFILES.md). A hunt that uses a construct a given runtime
can't execute still renders, round-trips, and exports; the linter tells you what
a target runtime supports.

## License of contributions
By contributing you agree your contribution is licensed under the repository
[`LICENSE`](./LICENSE).
