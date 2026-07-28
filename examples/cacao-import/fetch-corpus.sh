#!/usr/bin/env bash
# Reproduce the CACAO corpus the hunt.md importer was developed against:
# ~49 playbooks from six independent projects, covering CACAO 1.x and 2.0,
# every workflow step type, and eight distinct command types.
#
# Nothing downloaded here is committed to this repository — several sources
# carry no licence, so they can be read and tested against locally but not
# redistributed. See README.md.
#
#   ./fetch-corpus.sh [target-dir]     (default: ./corpus)   requires: gh, python3

# No `pipefail`: `head` closing a pipe early is expected here, and a source that
# has moved or gone private must not abort the whole fetch.
set -uo pipefail
set +o pipefail
OUT="${1:-./corpus}"
mkdir -p "$OUT"

command -v gh >/dev/null || { echo "error: the GitHub CLI (gh) is required" >&2; exit 1; }

# repo : branch : path-filter : filename-prefix : max-files
SOURCES=(
  "COSSAS/SOARCA:development:playbook:soarca:8"
  "ugurrates/playbookforge:main:playbooks/:pf:4"
  "davidojeabulu/caldera-cacao-importer:master:test_playbooks:caldera:3"
  "unibuc-cs/CyberPlaybookLLM:master:CACAO_examples:unibuc-ex:12"
  "unibuc-cs/CyberPlaybookLLM:master:Dataset/Main/Playbooks:unibuc:14"
  "Fraunhofer-FIT-DSAI/SASP:main:example.playbooks:sasp:9"
  "palantir-h2020/ti-re:master:cacaoPlaybook:tire:3"
)

for spec in "${SOURCES[@]}"; do
  IFS=: read -r repo branch filter prefix limit <<<"$spec"
  echo "==> $repo ($filter)"
  paths=$(gh api "repos/$repo/git/trees/$branch?recursive=1" \
      --jq ".tree[] | select(.type==\"blob\") | select(.path|endswith(\".json\")) | select(.path|test(\"$filter\")) | .path" 2>/dev/null \
    | grep -viE "schema|package|tsconfig|eslint" | head -"$limit")
  [ -n "$paths" ] || { echo "    (nothing found — source may have moved)"; continue; }

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    name="$prefix-$(basename "$path" | sed 's/[^A-Za-z0-9._-]/_/g')"
    encoded=${path// /%20}   # some repos have spaces in playbook paths
    if gh api "repos/$repo/contents/$encoded?ref=$branch" --jq .content 2>/dev/null \
         | base64 -d > "$OUT/$name" 2>/dev/null && [ -s "$OUT/$name" ]; then
      echo "    $name"
    else
      rm -f "$OUT/$name"
    fi
  done <<<"$paths"
done

echo
echo "Fetched $(find "$OUT" -name '*.json' | wc -l | tr -d ' ') playbooks into $OUT"
echo "Convert them all with:"
echo "  for f in $OUT/*.json; do python -m huntmd convert \"\$f\" -o \"\${f%.json}.md\"; done"
