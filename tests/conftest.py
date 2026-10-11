import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardian.models import API_CALL, Clients  # noqa: E402

ACCOUNT = "111122223333"


def make_event(source, name, request=None, *, user="alice", identity=None, **extra):
    """A CloudTrail record shaped like the `detail` of an EventBridge event."""
    event = {
        "eventVersion": "1.09",
        "eventSource": source,
        "eventName": name,
        "eventTime": "2026-10-10T12:00:00Z",
        "eventID": "11111111-2222-3333-4444-555555555555",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "recipientAccountId": ACCOUNT,
        "userIdentity": identity
        or {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}"},
        "requestParameters": request or {},
        "responseElements": None,
    }
    event.update(extra)
    return event


def envelope(event, detail_type=API_CALL, **extra):
    return {"detail-type": detail_type, "detail": event, **extra}


ROOT = {"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root", "principalId": ACCOUNT}


class FakeClient:
    """Records every call so tests can assert on the remediation that was issued."""

    def __init__(self, service, calls, fail=False):
        self._service, self._calls, self._fail = service, calls, fail

    def __getattr__(self, method):
        def call(**kwargs):
            if self._fail:
                raise RuntimeError("access denied")
            self._calls.append((self._service, method, kwargs))
            return {}

        return call


@pytest.fixture
def calls():
    return []


@pytest.fixture
def clients(calls):
    return Clients(lambda service, region: FakeClient(service, calls))


@pytest.fixture
def failing_clients(calls):
    return Clients(lambda service, region: FakeClient(service, calls, fail=True))
