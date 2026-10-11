"""Generate the files derived from the rule registry.

    python -m guardian.manifest events    > terraform/events.json
    python -m guardian.manifest markdown  > docs/detections.md

Terraform reads events.json to build EventBridge rules, so the API calls that
are routed to the Lambda can never drift from the rules that inspect them.
"""

from __future__ import annotations

import json
import sys

from .models import API_CALL, CONSOLE_SIGNIN
from .rules import ALL_RULES
from .rules.identity import ANY_SOURCE


def event_manifest() -> dict:
    api: dict[str, set[str]] = {}
    signin: set[str] = set()
    for rule in ALL_RULES:
        if rule.source == ANY_SOURCE:
            continue
        if rule.detail_type == CONSOLE_SIGNIN:
            signin.update(rule.events)
        elif rule.detail_type == API_CALL:
            api.setdefault(rule.source, set()).update(rule.events)
    return {
        "api": {source: sorted(names) for source, names in sorted(api.items())},
        "signin": sorted(signin),
    }


def detections_markdown() -> str:
    lines = [
        "# Detections",
        "",
        "Generated from the rule registry with `python -m guardian.manifest markdown`. Do not edit by hand.",
        "",
        f"{len(ALL_RULES)} rules.",
        "",
        "| ID | Detection | Severity | ATT&CK | Trigger | Automatic response |",
        "|---|---|---|---|---|---|",
    ]
    for rule in ALL_RULES:
        trigger = ", ".join(rule.events) or "any API call by the root user"
        service = "" if rule.source == ANY_SOURCE else rule.source.split(".")[0] + ": "
        lines.append(
            f"| {rule.id} | {rule.title} | {rule.severity} | {', '.join(rule.mitre)} "
            f"| {service}{trigger} | {rule.remediation or 'Alert only'} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if argv[1:] == ["events"]:
        print(json.dumps(event_manifest(), indent=2))
    elif argv[1:] == ["markdown"]:
        print(detections_markdown(), end="")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
