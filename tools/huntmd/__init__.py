"""hunt.md ⇄ Huntbase playbook-definition converter + validator.

Reference tooling for the hunt.md format. Self-contained (stdlib + PyYAML only),
so it runs as a plain CLI or can be vendored into a runtime's import/export path.

    python -m huntmd convert  hunt.md               # -> Huntbase definition YAML
    python -m huntmd convert  hunt.md --to cacao    # -> CACAO v2 playbook JSON
    python -m huntmd convert  hunt.md --to misp     # -> MISP event (HUNT-EX + threat-hunt-* objects)
    python -m huntmd convert  definition.yaml       # -> hunt.md
    python -m huntmd validate hunt.md

See ../SPEC.md for the format and ../PROFILES.md for the profiles this targets:
the Huntbase runtime (executes) and CACAO v2 (interchange export). Constructs a
runtime can't execute are reported by `validate`.
"""

from huntmd.cacao import markdown_to_cacao, playbook_to_cacao
from huntmd.misp import is_misp_event, markdown_to_misp, misp_to_markdown, misp_to_playbook, playbook_to_misp
from huntmd.core import (
    ConversionError,
    effective_guardrails,
    definition_to_markdown,
    markdown_to_definition,
    parse_markdown,
    validate_markdown,
)

from huntmd.results import is_result_document, validate_result

__all__ = [
    "ConversionError",
    "effective_guardrails",
    "is_result_document",
    "validate_result",
    "definition_to_markdown",
    "is_misp_event",
    "markdown_to_cacao",
    "markdown_to_misp",
    "misp_to_markdown",
    "misp_to_playbook",
    "playbook_to_misp",
    "markdown_to_definition",
    "parse_markdown",
    "playbook_to_cacao",
    "validate_markdown",
]
