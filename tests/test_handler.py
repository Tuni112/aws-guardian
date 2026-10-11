import json
from pathlib import Path

from conftest import ACCOUNT, ROOT, envelope, make_event

from guardian import handler
from guardian.handler import DRY_RUN, ENFORCE, OFF, Settings, evaluate, format_alert, publish
from guardian.manifest import detections_markdown, event_manifest

REPO = Path(__file__).resolve().parents[1]
ROLE = f"arn:aws:iam::{ACCOUNT}:role/aws-guardian"
OPEN_SSH = {
    "groupId": "sg-0abc",
    "ipPermissions": {
        "items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]
    },
}


def open_ssh(**kwargs):
    return envelope(make_event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", OPEN_SSH, **kwargs))


def test_dry_run_alerts_but_changes_nothing(clients, calls):
    (finding,) = evaluate(open_ssh(), Settings(mode=DRY_RUN), clients)
    assert calls == []
    assert not finding.remediated
    assert finding.remediation.startswith("dry run, would:")


def test_off_mode_still_alerts(clients, calls):
    (finding,) = evaluate(open_ssh(), Settings(mode=OFF), clients)
    assert calls == [] and finding.remediation == "remediation is turned off"


def test_enforce_can_be_limited_to_named_rules(clients, calls):
    settings = Settings(mode=ENFORCE, remediate_rules=frozenset({"S3-001"}))
    (finding,) = evaluate(open_ssh(), settings, clients)
    assert calls == [] and not finding.remediated


def test_failed_remediation_still_produces_the_alert(failing_clients):
    (finding,) = evaluate(open_ssh(), Settings(mode=ENFORCE), failing_clients)
    assert not finding.remediated
    assert finding.remediation.startswith("FAILED: RuntimeError")


def test_guardians_own_actions_are_ignored(clients):
    own = {
        "type": "AssumedRole",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/aws-guardian/aws-guardian",
        "sessionContext": {"sessionIssuer": {"arn": ROLE}},
    }
    settings = Settings(mode=ENFORCE, own_role_arn=ROLE)
    assert evaluate(open_ssh(identity=own), settings, clients) == []


def test_trusted_principals_are_ignored(clients):
    settings = Settings(mode=ENFORCE, trusted_principals=(f"arn:aws:iam::{ACCOUNT}:user/alice",))
    assert evaluate(open_ssh(), settings, clients) == []


def test_root_route_only_runs_the_root_rule(clients):
    """Root opening SSH arrives twice: once per EventBridge rule. Each delivery
    must report a different finding so the alert is not duplicated."""
    normal = evaluate(open_ssh(identity=ROOT), Settings(), clients)
    routed = evaluate({**open_ssh(identity=ROOT), "guardian_route": "root"}, Settings(), clients)
    assert [f.rule_id for f in normal] == ["NET-001"]
    assert [f.rule_id for f in routed] == ["ID-004"]


def test_finding_records_actor_and_latency(clients):
    (finding,) = evaluate(open_ssh(), Settings(), clients)
    assert finding.actor.endswith("user/alice")
    assert finding.source_ip == "203.0.113.10"
    assert finding.account == ACCOUNT
    assert finding.seconds_to_respond is not None and finding.seconds_to_respond > 0


def test_alert_is_published_to_sns(clients, calls):
    settings = Settings(topic_arn="arn:aws:sns:us-east-1:111122223333:alerts")
    findings = evaluate(open_ssh(), settings, clients)
    publish(findings, settings, clients)
    (service, method, kwargs), = calls
    assert (service, method) == ("sns", "publish")
    assert kwargs["Subject"].startswith("[CRITICAL] NET-001")
    assert "sg-0abc" in kwargs["Message"]
    assert len(kwargs["Subject"]) <= 100


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("REMEDIATION_MODE", "ENFORCE")
    monkeypatch.setenv("REMEDIATE_RULES", "NET-001, S3-001")
    monkeypatch.setenv("TRUSTED_PRINCIPALS", "arn:a,arn:b")
    settings = Settings.from_env()
    assert settings.mode == ENFORCE
    assert settings.remediate_rules == {"NET-001", "S3-001"}
    assert settings.trusted_principals == ("arn:a", "arn:b")
    monkeypatch.setenv("REMEDIATION_MODE", "nonsense")
    assert Settings.from_env().mode == DRY_RUN


def test_lambda_handler_end_to_end(monkeypatch, clients):
    monkeypatch.setattr(handler, "Clients", lambda: clients)
    monkeypatch.delenv("ALERT_TOPIC_ARN", raising=False)
    assert handler.lambda_handler(open_ssh()) == {"findings": ["NET-001"]}
    assert handler.lambda_handler({}) == {"findings": []}


def test_alert_format_is_readable(clients):
    (finding,) = evaluate(open_ssh(), Settings(), clients)
    subject, body = format_alert(finding)
    assert "NET-001" in subject and "T1562.007" in body


def test_generated_files_match_the_registry():
    """Terraform routes events from events.json; it must never drift from the rules."""
    assert json.loads((REPO / "terraform/events.json").read_text()) == event_manifest()
    assert (REPO / "docs/detections.md").read_text() == detections_markdown()
