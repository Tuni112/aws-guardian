"""Lambda entry point: evaluate a CloudTrail event, remediate, and alert."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from .models import Clients, Detection, Rule
from .rules import ROOT_ACTIVITY_RULES, rules_for
from .util import actor, identity

log = logging.getLogger("guardian")
log.setLevel(logging.INFO)

OFF, DRY_RUN, ENFORCE = "off", "dry_run", "enforce"
ROOT_ROUTE = "root"


@dataclass
class Settings:
    mode: str = DRY_RUN
    remediate_rules: frozenset[str] = frozenset({"all"})
    topic_arn: str = ""
    own_role_arn: str = ""
    trusted_principals: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "Settings":
        def csv(name: str) -> list[str]:
            return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]

        mode = os.environ.get("REMEDIATION_MODE", DRY_RUN).lower()
        return cls(
            mode=mode if mode in (OFF, DRY_RUN, ENFORCE) else DRY_RUN,
            remediate_rules=frozenset(csv("REMEDIATE_RULES") or ["all"]),
            topic_arn=os.environ.get("ALERT_TOPIC_ARN", ""),
            own_role_arn=os.environ.get("GUARDIAN_ROLE_ARN", ""),
            trusted_principals=tuple(csv("TRUSTED_PRINCIPALS")),
        )

    def should_remediate(self, rule: Rule) -> bool:
        return self.mode == ENFORCE and bool({"all", rule.id} & self.remediate_rules)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    resource: str
    reason: str
    actor: str
    source_ip: str
    account: str
    region: str
    event_name: str
    event_id: str
    event_time: str
    detected_at: str
    remediation: str  # what was done, what would be done, or why nothing was
    remediated: bool
    seconds_to_respond: Optional[float]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _seconds_since(event_time: str, now: datetime) -> Optional[float]:
    try:
        then = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return round((now - then).total_seconds(), 1)


def _session_issuer(event: dict) -> str:
    return ((identity(event).get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn", "")


def _is_ignored(event: dict, settings: Settings) -> bool:
    """Skip Guardian's own remediation calls (no feedback loop) and trusted automation."""
    callers = {identity(event).get("arn", ""), _session_issuer(event)} - {""}
    ignored = {settings.own_role_arn, *settings.trusted_principals} - {""}
    return bool(callers & ignored)


def _matching_rules(envelope: dict) -> list[Rule]:
    event = envelope.get("detail") or {}
    if envelope.get("guardian_route") == ROOT_ROUTE:
        return ROOT_ACTIVITY_RULES
    rules = rules_for(event.get("eventSource", ""), event.get("eventName", ""))
    return [r for r in rules if r.detail_type == envelope.get("detail-type")]


def _respond(rule: Rule, event: dict, detection: Detection, settings: Settings, clients: Clients):
    """Returns (description, remediated)."""
    if rule.remediate is None:
        return "alert only: no automatic remediation for this rule", False
    if settings.mode == OFF:
        return "remediation is turned off", False
    if not settings.should_remediate(rule):
        return f"dry run, would: {rule.remediation}", False
    try:
        outcome = rule.remediate(event, detection, clients)
    except Exception as exc:  # a failed fix must never suppress the alert
        log.exception("remediation failed for %s", rule.id)
        return f"FAILED: {type(exc).__name__}: {exc}", False
    return outcome, not outcome.startswith("none:")


def evaluate(envelope: dict, settings: Settings, clients: Clients) -> list[Finding]:
    event = envelope.get("detail") or {}
    if not event or _is_ignored(event, settings):
        return []
    failed = bool(event.get("errorCode"))
    findings = []
    for rule in _matching_rules(envelope):
        if failed and not rule.include_failed:
            continue
        detection = rule.evaluate(event)
        if detection is None:
            continue
        outcome, remediated = _respond(rule, event, detection, settings, clients)
        now = _now()
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                mitre=list(rule.mitre),
                resource=detection.resource,
                reason=detection.reason,
                actor=actor(event),
                source_ip=event.get("sourceIPAddress", ""),
                account=event.get("recipientAccountId", ""),
                region=event.get("awsRegion", ""),
                event_name=event.get("eventName", ""),
                event_id=event.get("eventID", ""),
                event_time=event.get("eventTime", ""),
                detected_at=now.isoformat(timespec="seconds"),
                remediation=outcome,
                remediated=remediated,
                seconds_to_respond=_seconds_since(event.get("eventTime", ""), now),
            )
        )
    return findings


def format_alert(finding: Finding) -> tuple[str, str]:
    subject = f"[{finding.severity}] {finding.rule_id} {finding.title}"[:100]
    body = "\n".join(
        [
            f"{finding.rule_id}  {finding.title}",
            f"Severity:  {finding.severity}",
            f"What:      {finding.reason}",
            f"Resource:  {finding.resource}",
            f"Who:       {finding.actor} from {finding.source_ip or 'unknown ip'}",
            f"Where:     account {finding.account}, {finding.region}",
            f"When:      {finding.event_time} ({finding.event_name}, event {finding.event_id})",
            f"Response:  {finding.remediation}",
            f"Latency:   {finding.seconds_to_respond}s from API call to response",
            f"ATT&CK:    {', '.join(finding.mitre)}",
        ]
    )
    return subject, body


def publish(findings: list[Finding], settings: Settings, clients: Clients) -> None:
    for finding in findings:
        log.info(json.dumps({"guardian_finding": asdict(finding)}))
        if not settings.topic_arn:
            continue
        subject, body = format_alert(finding)
        clients.get("sns").publish(TopicArn=settings.topic_arn, Subject=subject, Message=body)


def lambda_handler(envelope: dict, context=None) -> dict:
    settings = Settings.from_env()
    clients = Clients()
    findings = evaluate(envelope, settings, clients)
    publish(findings, settings, clients)
    return {"findings": [f.rule_id for f in findings]}
