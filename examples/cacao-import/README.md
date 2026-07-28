# CACAO → hunt.md reference conversions

Real CACAO playbooks, converted to `hunt.md` by the reference importer:

```bash
huntmd convert path/to/playbook.json          # CACAO detected by shape → hunt.md
```

They exist to show what the importer actually produces on third-party input, and
to serve as fixtures when changing [`tools/huntmd/cacao.py`](../../tools/huntmd/cacao.py).

> **These are drafts, not hunts.** They deliberately live outside [`hunts/`](../../hunts):
> an imported playbook has no hypothesis, no ATT&CK coverage and no abstract data
> sources, because CACAO doesn't carry them. The importer marks each gap with a
> `TODO` so `huntmd validate` points straight at what a human still has to supply.
> Nothing here meets the bar in [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## What's here

| File(s) | Source | Demonstrates |
|---|---|---|
| `soarca-*.md` (8) | [COSSAS/SOARCA](https://github.com/COSSAS/SOARCA) `test/playbook/` | One command type each — `ssh`, `http-api`, `openc2`, `powershell`, `manual`, plus assignment/variable handling |
| `pf-phishing.md`, `pf-malware.md`, `pf-sample.md` | [ugurrates/playbookforge](https://github.com/ugurrates/playbookforge) `playbooks/` | `if-condition` branching, `$$variable$$` interpolation, ATT&CK cited as plain references |
| `caldera-*.md` (3) | [davidojeabulu/caldera-cacao-importer](https://github.com/davidojeabulu/caldera-cacao-importer) `test_playbooks/` | CACAO **1.x** `single` steps and `attack-cmd` commands — the legacy shape the importer also accepts |

Each file records where it came from in its frontmatter:

```yaml
x_source:
  repo: https://github.com/COSSAS/SOARCA
  path: test/playbook/ssh-playbook.json
  license: Apache-2.0
x_cacao_source:      # identity of the original playbook, pinned for traceability
  id: playbook--...
  spec_version: cacao-2.0
```

Step-level `cacao_id` values pin each original CACAO step id in a Tier-2 block
(SPEC §10), so a converted step can always be traced back to its source.

## Licensing

Only conversions of **Apache-2.0** sources are redistributed here, each
attributed above and in its own frontmatter. Derivative works, licensed under
their originals' terms.

The importer was developed against a wider corpus — **49 playbooks from six
projects**, including control-flow examples (`parallel`, `while-condition`) from
repositories that carry **no licence at all**. Those are deliberately *not*
vendored: no licence means no right to redistribute. Reproduce the full corpus
locally with:

```bash
./fetch-corpus.sh /tmp/cacao-corpus       # downloads; nothing is committed
```

## Regenerating

```bash
cd tools
python -m huntmd convert /tmp/cacao-corpus/soarca-ssh-playbook.json -o ../examples/cacao-import/soarca-ssh-playbook.md
```

The `x_source` block is added when generating this directory; the importer
itself doesn't invent it.
