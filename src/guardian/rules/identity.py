"""Risky sign-ins and any use of the root user."""

from __future__ import annotations

from ..models import CONSOLE_SIGNIN, CRITICAL, HIGH, MEDIUM, Detection, Rule
from ..util import identity, is_root, response

SIGNIN = "signin.amazonaws.com"
ANY_SOURCE = "*"


def _signed_in(event: dict) -> bool:
    return response(event).get("ConsoleLogin") == "Success"


def _mfa_used(event: dict) -> bool:
    return (event.get("additionalEventData") or {}).get("MFAUsed") == "Yes"


def root_console_login(event: dict):
    if is_root(event) and _signed_in(event):
        mfa = "with" if _mfa_used(event) else "WITHOUT"
        return Detection("root", f"Root user signed in to the console {mfa} MFA from {event.get('sourceIPAddress')}")
    return None


def console_login_without_mfa(event: dict):
    ident = identity(event)
    # Federated and SSO sessions report MFAUsed=No even when the IdP enforced MFA,
    # so only IAM users are a reliable signal here.
    if ident.get("type") == "IAMUser" and _signed_in(event) and not _mfa_used(event):
        name = ident.get("userName", "unknown")
        return Detection(f"user/{name}", f"IAM user {name} signed in to the console without MFA")
    return None


def console_login_failed(event: dict):
    if response(event).get("ConsoleLogin") == "Failure" and is_root(event):
        return Detection("root", f"Failed root console sign-in from {event.get('sourceIPAddress')}")
    return None


def root_api_activity(event: dict):
    ident = identity(event)
    if not is_root(event) or ident.get("invokedBy") or event.get("eventType") == "AwsServiceEvent":
        return None
    return Detection(
        "root",
        f"Root user called {event.get('eventSource', '').split('.')[0]}:{event.get('eventName')}",
    )


RULES = [
    Rule(
        id="ID-001",
        title="Root user console sign-in",
        severity=CRITICAL,
        source=SIGNIN,
        events=("ConsoleLogin",),
        mitre=("T1078.004",),
        evaluate=root_console_login,
        detail_type=CONSOLE_SIGNIN,
    ),
    Rule(
        id="ID-002",
        title="Console sign-in without MFA",
        severity=MEDIUM,
        source=SIGNIN,
        events=("ConsoleLogin",),
        mitre=("T1078.004",),
        evaluate=console_login_without_mfa,
        detail_type=CONSOLE_SIGNIN,
    ),
    Rule(
        id="ID-003",
        title="Failed root console sign-in",
        severity=HIGH,
        source=SIGNIN,
        events=("ConsoleLogin",),
        mitre=("T1110",),
        evaluate=console_login_failed,
        detail_type=CONSOLE_SIGNIN,
        include_failed=True,
    ),
    Rule(
        id="ID-004",
        title="Root user API activity",
        severity=HIGH,
        source=ANY_SOURCE,
        events=(),
        mitre=("T1078.004",),
        evaluate=root_api_activity,
    ),
]
