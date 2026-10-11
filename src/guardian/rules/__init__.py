"""Registry of every detection rule."""

from __future__ import annotations

from ..models import Rule
from . import exposure, iam, identity, logging, network, s3

ALL_RULES: list[Rule] = [
    *logging.RULES,
    *s3.RULES,
    *network.RULES,
    *exposure.RULES,
    *iam.RULES,
    *identity.RULES,
]

# Rules that inspect every event from a routed source rather than named API calls.
ROOT_ACTIVITY_RULES = [r for r in ALL_RULES if r.source == identity.ANY_SOURCE]


def rules_for(source: str, event_name: str) -> list[Rule]:
    return [r for r in ALL_RULES if r.source == source and event_name in r.events]
