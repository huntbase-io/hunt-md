# Running a private hunt library

The public repository holds the format, the tooling, and hunts that are safe to
share with the world. Hunts that aren't — customer-specific, TLP:AMBER or above,
built on licensed content — belong in a **private library** that consumes this
repository rather than forking it.

Same format, same tooling, different sharing boundary.

```
huntbase-io/hunt-md            public, MIT    the format + tooling + public hunts
        ▲
        │ pinned submodule (one-way)
        │
huntbase-io/hunt-md-internal   private        proprietary hunts
```

## Why not a fork

**Never make the private repository a fork of the public one.** GitHub fork
networks share object storage: commits pushed to any repository in a network stay
retrievable through that network, including from repositories later made private
or deleted. This was demonstrated publicly in 2024 and is working-as-designed
behaviour, not a bug. A private fork of a public repo is not a security boundary.

Two unrelated repositories share no object store. That's the property you want.

**Also avoid** generating the public repo as a filtered export of the private
one. Every publish becomes a chance to leak, the allowlist is one bad edit from
wrong, and fixing a mistake means rewriting public history.

## Setup

```bash
gh repo create huntbase-io/hunt-md-internal --private --clone
cd hunt-md-internal

git submodule add https://github.com/huntbase-io/hunt-md.git vendor/hunt-md
git -C vendor/hunt-md checkout v0.4          # pin a tag, not a moving branch
git commit -m "Vendor hunt.md v0.4"

pip install ./vendor/hunt-md/tools           # provides `huntmd`
mkdir -p hunts
```

Clone it later with `git clone --recurse-submodules`, and upgrade deliberately:

```bash
git -C vendor/hunt-md fetch --tags && git -C vendor/hunt-md checkout v0.5
python vendor/hunt-md/tools/tests/check.py   # confirm nothing regressed
git commit -am "Upgrade hunt.md to v0.5"
```

Pinning to a tag means a public-repo change can never silently alter how your
private hunts validate or convert.

## Direction of flow

Public is upstream. Private consumes it. Nothing is automated in the other
direction.

When a private hunt becomes publishable — the customer specifics are gone, the
TLP drops to green — move it **one file at a time**, by hand, through a normal PR
to the public repo. Never merge a private branch into a public one: it carries
history you didn't intend to publish.

## Guardrails

1. **Don't add the public repo as a remote in the private clone.** Most accidental
   disclosures are a `git push` to a remote that shouldn't have existed. The
   submodule is a subdirectory with its own remote, which is exactly the
   separation you want.

2. **Invert the TLP gate in the private repo's CI** — it's the same flag:

   ```bash
   # public CI:  nothing above green may be published
   huntmd validate hunts/x.md --max-tlp green

   # private CI: everything must be labelled, any level is allowed
   huntmd validate hunts/x.md --max-tlp red
   ```

   Both fail on a hunt with no `tlp:` at all, which is the case worth catching.

3. **Enable secret scanning with push protection** on both repositories, and
   branch protection with required review on the public `main`.

4. **Run the public repo's checks against your private hunts.** They are the same
   correctness rules — bounded agent steps, gated actions, `indeterminate:`
   routing — and they matter more when the hunt touches a real customer:

   ```bash
   python vendor/hunt-md/tools/tests/check.py
   for f in hunts/*.md; do huntmd validate "$f" --profile format --max-tlp red; done
   ```

## Contributing back

If a fix or format gap surfaces while writing private hunts, it belongs upstream —
open an issue or PR on the public repository. Keeping improvements to the *format*
private benefits nobody, including you: a divergent private copy of the spec is a
maintenance cost you pay forever.
