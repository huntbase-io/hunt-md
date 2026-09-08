"""CLI for the hunt.md converter + validator.

    uv run python -m huntmd convert  <file.md>            # -> definition YAML (stdout)
    uv run python -m huntmd convert  <file.md> --to cacao # -> CACAO v2 playbook JSON
    uv run python -m huntmd convert  <file.md> --to misp [--result run.yaml]  # -> MISP event JSON (HUNT-EX)
    uv run python -m huntmd convert  <file.yaml|.json>    # -> hunt.md (stdout)
    uv run python -m huntmd convert  <file> --to md|yaml|json|cacao -o <out>
    uv run python -m huntmd validate <file.md> [--profile huntbase|format|cacao|misp]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from huntmd.cacao import cacao_to_markdown, markdown_to_cacao
from huntmd.misp import hypothesis_count, is_misp_event, markdown_to_misp, misp_to_markdown, misp_to_markdowns
from huntmd.results import is_result_document, validate_result
from huntmd.core import (
    ConversionError,
    definition_to_markdown,
    dump_yaml,
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
            elif target == "misp":
                run = None
                if args.result:
                    rp = Path(args.result)
                    rtext = rp.read_text(encoding="utf-8")
                    try:
                        run = json.loads(rtext) if rp.suffix.lower() == ".json" else yaml.safe_load(rtext)
                    except (json.JSONDecodeError, yaml.YAMLError) as exc:
                        raise ConversionError(f"--result {rp}: not parseable as YAML/JSON ({exc.__class__.__name__})") from exc
                    if not is_result_document(run):
                        raise ConversionError(f"--result {rp} is not a run result (expected 'hunt_result' root)")
                result = json.dumps(markdown_to_misp(text, result=run), indent=2, ensure_ascii=False) + "\n"
            elif target == "json":
                result = json.dumps(markdown_to_definition(text), indent=2)
            elif target == "yaml":
                result = dump_yaml(markdown_to_definition(text), sort_keys=False, default_flow_style=False)
            else:
                raise ConversionError("Converting hunt.md → md is a no-op; use --to yaml|json|cacao.")
        elif args.to in ("cacao", "misp"):
            raise ConversionError(f"--to {args.to} takes a hunt.md source (the input is already a playbook/event).")
        else:
            definition = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
            # All inbound formats are JSON/YAML objects; tell them apart by shape.
            if is_misp_event(definition):
                if args.split:
                    return _write_split(definition, args.output)
                n = hypothesis_count(definition)
                if n > 1:
                    print(
                        f"note: this event carries {n} hypotheses; hunt.md is one hypothesis per file. "
                        f"Converting the first and declaring the rest under `related:` — "
                        f"re-run with --split -o <dir> to write all {n}.",
                        file=sys.stderr,
                    )
                result = misp_to_markdown(definition)
            elif _looks_like_cacao(definition):
                result = cacao_to_markdown(definition)
            else:
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


def _write_split(event: object, out: str | None) -> int:
    """Write one hunt.md per hypothesis (SPEC §3.8) into a directory."""
    files = misp_to_markdowns(event)
    target = Path(out) if out else Path.cwd()
    if target.suffix.lower() in (".md", ".markdown"):
        print(f"error: --split writes several files; -o must be a directory (got {target})", file=sys.stderr)
        return 2
    target.mkdir(parents=True, exist_ok=True)
    for name, text in files:
        (target / name).write_text(text, encoding="utf-8")
        print(f"wrote {target / name}", file=sys.stderr)
    if len(files) == 1:
        print("note: the event carried one hypothesis (or the exact source), so one file was written.", file=sys.stderr)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.file)
    text = path.read_text(encoding="utf-8")

    # A run result is YAML/JSON with a `hunt_result` root — lint it as a result
    # (SPEC §12) rather than trying to parse it as a hunt.
    if not _looks_like_markdown(path, text):
        try:
            doc = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            print(f"error: could not parse {path}: {exc}", file=sys.stderr)
            return 2
        if is_result_document(doc):
            issues = validate_result(doc)
            for issue in issues:
                print(str(issue), file=sys.stderr)
            if not issues:
                print("ok: no issues", file=sys.stderr)
            return 1 if any(i.level == "error" for i in issues) else 0
        print("error: not a hunt.md or a run result (expected 'hunt_result')", file=sys.stderr)
        return 2

    # Sibling .md files are the "library" a related:/series: slug can name (SPEC §3.8).
    bundle = {p.stem for p in path.parent.glob("*.md") if p.name != path.name} or None
    issues = validate_markdown(text, profile=args.profile, max_tlp=args.max_tlp, bundle=bundle)
    errors = [i for i in issues if i.level == "error"]
    for issue in issues:
        print(str(issue), file=sys.stderr)
    if not issues:
        print("ok: no issues", file=sys.stderr)
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hunt-md", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="hunt.md ⇄ Huntbase definition / CACAO / MISP")
    c.add_argument("file")
    c.add_argument(
        "--to",
        choices=["md", "yaml", "json", "cacao", "misp"],
        help="output format (md input defaults to yaml; 'cacao' emits a CACAO v2 playbook, "
        "'misp' a MISP event with HUNT-EX tags + threat-hunt-* objects)",
    )
    c.add_argument(
        "--result",
        metavar="RUN",
        help="with --to misp: a run result (SPEC §12) to export as a threat-hunt-finding + hunt-ex:outcome",
    )
    c.add_argument("-o", "--output", help="write to file instead of stdout (a directory with --split)")
    c.add_argument(
        "--date",
        metavar="YYYY-MM-DD",
        help="with --to misp: pin the event date (default: the hunt's own `created:`, else today). "
        "Pin it so re-exporting an unchanged hunt is byte-identical.",
    )
    c.add_argument(
        "--split",
        action="store_true",
        help="MISP input only: write one hunt.md per threat-hunt-hypothesis into -o "
        "(hunt.md is one hypothesis per file; the parts are wired with series:/related:). "
        "A document carrying several events writes all of them.",
    )
    c.set_defaults(func=_cmd_convert)

    v = sub.add_parser("validate", help="lint a hunt.md or a run result")
    v.add_argument("file")
    v.add_argument(
        "--profile",
        choices=["huntbase", "format", "cacao", "misp", "quality"],
        default="huntbase",
        help="lint against a runtime/interchange profile (default: huntbase); "
        "'quality' adds the opt-in rules that make a hunt more than a rule",
    )
    v.add_argument(
        "--max-tlp",
        metavar="LEVEL",
        help="fail if the hunt's tlp: exceeds LEVEL (clear|green|amber|amber+strict|red). "
        "A public repository lints with --max-tlp green.",
    )
    v.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
