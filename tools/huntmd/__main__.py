"""CLI for the hunt.md converter + validator.

    uv run python -m huntmd convert  <file.md>            # -> definition YAML (stdout)
    uv run python -m huntmd convert  <file.yaml|.json>    # -> hunt.md (stdout)
    uv run python -m huntmd convert  <file> --to md|yaml|json -o <out>
    uv run python -m huntmd validate <file.md> [--profile huntbase|format]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

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


def _cmd_convert(args: argparse.Namespace) -> int:
    path = Path(args.file)
    text = path.read_text(encoding="utf-8")
    is_md = _looks_like_markdown(path, text)
    try:
        if is_md:
            definition = markdown_to_definition(text)
            target = args.to or "yaml"
            if target == "json":
                result = json.dumps(definition, indent=2)
            elif target == "yaml":
                result = yaml.safe_dump(definition, sort_keys=False, default_flow_style=False)
            else:
                raise ConversionError("Converting hunt.md → md is a no-op; use --to yaml|json.")
        else:
            definition = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
            result = definition_to_markdown(definition)
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
    c.add_argument("--to", choices=["md", "yaml", "json"], help="output format (md input defaults to yaml)")
    c.add_argument("-o", "--output", help="write to file instead of stdout")
    c.set_defaults(func=_cmd_convert)

    v = sub.add_parser("validate", help="lint a hunt.md")
    v.add_argument("file")
    v.add_argument("--profile", choices=["huntbase", "format"], default="huntbase")
    v.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
