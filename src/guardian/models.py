"""Core types shared by every detection rule."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"

# detail-type values EventBridge uses for CloudTrail-sourced events
API_CALL = "AWS API Call via CloudTrail"
CONSOLE_SIGNIN = "AWS Console Sign In via CloudTrail"


@dataclass(frozen=True)
class Detection:
    """What a rule found in a single CloudTrail event."""

    resource: str
    reason: str
    context: dict[str, Any] = field(default_factory=dict)


class Clients:
    """Lazy boto3 client factory, so tests can pass in fakes."""

    def __init__(self, factory: Optional[Callable[[str, Optional[str]], Any]] = None):
        self._factory = factory
        self._cache: dict[tuple[str, Optional[str]], Any] = {}

    def get(self, service: str, region: Optional[str] = None) -> Any:
        key = (service, region)
        if key not in self._cache:
            if self._factory is not None:
                self._cache[key] = self._factory(service, region)
            else:
                import boto3  # imported lazily: only needed inside Lambda

                self._cache[key] = boto3.client(service, region_name=region)
        return self._cache[key]


Evaluator = Callable[[dict], Optional[Detection]]
Remediator = Callable[[dict, Detection, Clients], str]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    source: str  # CloudTrail eventSource, e.g. "iam.amazonaws.com"
    events: tuple[str, ...]  # CloudTrail eventName values this rule inspects
    mitre: tuple[str, ...]  # MITRE ATT&CK technique ids
    evaluate: Evaluator
    remediate: Optional[Remediator] = None
    remediation: str = ""  # human description of what remediate() does
    detail_type: str = API_CALL
    # Most rules only care about changes that actually happened. Set this for
    # rules where a denied attempt is itself the signal.
    include_failed: bool = False
