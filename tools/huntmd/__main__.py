"""CLI for the hunt.md converter + validator.

    uv run python -m huntmd convert  <file.md>            # -> definition YAML (stdout)
    uv run python -m huntmd convert  <file.md> --to cacao # -> CACAO v2 playbook JSON
    uv run python -m huntmd convert  <file.yaml|.json>    # -> hunt.md (stdout)
    uv run python -m huntmd convert  <file> --to md|yaml|json|cacao -o <out>
    uv run python -m huntmd validate <file.md> [--profile huntbase|format|cacao]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from huntmd.cacao import cacao_to_markdown, markdown_to_cacao
from huntmd.core import (
    ConversionError,
    definition_to_markdown,
    markdown_to_definition,
    validate_markdown,
)


def _looks_like_markdown(path: Path, text: str) -> bool:
    if path.suffix.lower() in (".md", ".markdown"):
        return True
    if path.suffix.lower() in (".yaml", ".yml", ".json"):
        return False
    return text.lstrip().startswith("---") or "\n## " in text


def _looks_like_cacao(defn: object) -> bool:
    """A CACAO playbook has a `workflow` map (possibly under a single-key wrapper)."""
    if not isinstance(defn, dict):
        return False
    if isinstance(defn.get("workflow"), dict):
        return True
    if "nodes" in defn:  # Huntbase definition
        return False
    return any(isinstance(v, dict) and isinstance(v.get("workflow"), dict) for v in defn.values())


def _cmd_convert(args: argparse.Namespace) -> int:
    path = Path(args.file)
    text = path.read_text(encoding="utf-8")
    is_md = _looks_like_markdown(path, text)
    try:
        if is_md:
            target = args.to or "yaml"
            if target == "cacao":
                result = json.dumps(markdown_to_cacao(text), indent=2) + "\n"
            elif target == "json":
                result = json.dumps(markdown_to_definition(text), indent=2)
            elif target == "yaml":
                result = yaml.safe_dump(markdown_to_definition(text), sort_keys=False, default_flow_style=False)
            else:
                raise ConversionError("Converting hunt.md → md is a no-op; use --to yaml|json|cacao.")
        elif args.to == "cacao":
            raise ConversionError("--to cacao takes a hunt.md source (the input is already a playbook).")
        else:
            definition = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
            # Both inbound formats are JSON/YAML objects; tell them apart by shape.
            result = cacao_to_markdown(definition) if _looks_like_cacao(definition) else definition_to_markdown(definition)
    except ConversionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(result, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(result)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text(encoding="utf-8")
    issues = validate_markdown(text, profile=args.profile)
    errors = [i for i in issues if i.level == "error"]
    for issue in issues:
        print(str(issue), file=sys.stderr)
    if not issues:
        print("ok: no issues", file=sys.stderr)
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hunt-md", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="hunt.md ⇄ Huntbase definition")
    c.add_argument("file")
    c.add_argument(
        "--to",
        choices=["md", "yaml", "json", "cacao"],
        help="output format (md input defaults to yaml; 'cacao' emits a CACAO v2 playbook)",
    )
    c.add_argument("-o", "--output", help="write to file instead of stdout")
    c.set_defaults(func=_cmd_convert)

    v = sub.add_parser("validate", help="lint a hunt.md")
    v.add_argument("file")
    v.add_argument(
        "--profile",
        choices=["huntbase", "format", "cacao"],
        default="huntbase",
        help="lint against a runtime/interchange profile (default: huntbase)",
    )
    v.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
