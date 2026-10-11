"""Defense evasion: attempts to blind logging and threat detection."""

from __future__ import annotations

from ..models import CRITICAL, HIGH, Clients, Detection, Rule
from ..util import items, params

CLOUDTRAIL = "cloudtrail.amazonaws.com"
GUARDDUTY = "guardduty.amazonaws.com"
CONFIG = "config.amazonaws.com"
EC2 = "ec2.amazonaws.com"


def _trail(event: dict) -> str:
    p = params(event)
    return p.get("name") or p.get("trailName") or "unknown-trail"


def trail_stopped(event: dict):
    return Detection(_trail(event), "CloudTrail logging was stopped")


def restart_trail(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("cloudtrail", event.get("awsRegion")).start_logging(Name=detection.resource)
    return "restarted logging on the trail"


def trail_deleted(event: dict):
    return Detection(_trail(event), "CloudTrail trail was deleted")


def trail_weakened(event: dict):
    p = params(event)
    weakened = []
    if p.get("enableLogFileValidation") is False:
        weakened.append("log file validation disabled")
    if p.get("isMultiRegionTrail") is False:
        weakened.append("multi-region logging disabled")
    if p.get("includeGlobalServiceEvents") is False:
        weakened.append("global service events excluded")
    if p.get("kmsKeyId") == "":
        weakened.append("encryption key removed")
    if not weakened:
        return None
    return Detection(_trail(event), "CloudTrail trail weakened: " + ", ".join(weakened))


def management_events_excluded(event: dict):
    selectors = params(event).get("eventSelectors") or []
    if selectors and all(s.get("includeManagementEvents") is False for s in selectors):
        return Detection(_trail(event), "Trail no longer records management events")
    return None


def guardduty_disabled(event: dict):
    p = params(event)
    detector = p.get("detectorId", "unknown-detector")
    if event["eventName"] == "DeleteDetector":
        return Detection(detector, "GuardDuty detector was deleted")
    if p.get("enable") is False:
        return Detection(detector, "GuardDuty detector was disabled")
    return None


def reenable_guardduty(event: dict, detection: Detection, clients: Clients) -> str:
    if event["eventName"] == "DeleteDetector":
        return "none: a deleted detector cannot be restored, create a new one"
    clients.get("guardduty", event.get("awsRegion")).update_detector(
        DetectorId=detection.resource, Enable=True
    )
    return "re-enabled the GuardDuty detector"


def config_recorder_stopped(event: dict):
    name = params(event).get("configurationRecorderName", "default")
    verb = "deleted" if event["eventName"].startswith("Delete") else "stopped"
    return Detection(name, f"AWS Config recorder was {verb}")


def restart_config_recorder(event: dict, detection: Detection, clients: Clients) -> str:
    if event["eventName"].startswith("Delete"):
        return "none: a deleted recorder must be recreated"
    clients.get("config", event.get("awsRegion")).start_configuration_recorder(
        ConfigurationRecorderName=detection.resource
    )
    return "restarted the Config recorder"


def flow_logs_deleted(event: dict):
    request = params(event).get("DeleteFlowLogsRequest") or params(event)
    ids = [i for i in items(request.get("FlowLogId")) if isinstance(i, str)]
    ids = ids or [i.get("content", "") for i in items(request.get("FlowLogId")) if isinstance(i, dict)]
    return Detection(", ".join(filter(None, ids)) or "unknown-flow-log", "VPC flow logs were deleted")


RULES = [
    Rule(
        id="LOG-001",
        title="CloudTrail logging stopped",
        severity=CRITICAL,
        source=CLOUDTRAIL,
        events=("StopLogging",),
        mitre=("T1562.008",),
        evaluate=trail_stopped,
        remediate=restart_trail,
        remediation="Restart logging on the trail",
    ),
    Rule(
        id="LOG-002",
        title="CloudTrail trail deleted",
        severity=CRITICAL,
        source=CLOUDTRAIL,
        events=("DeleteTrail",),
        mitre=("T1562.008",),
        evaluate=trail_deleted,
    ),
    Rule(
        id="LOG-003",
        title="CloudTrail trail weakened",
        severity=HIGH,
        source=CLOUDTRAIL,
        events=("UpdateTrail",),
        mitre=("T1562.008",),
        evaluate=trail_weakened,
    ),
    Rule(
        id="LOG-004",
        title="CloudTrail management events excluded",
        severity=HIGH,
        source=CLOUDTRAIL,
        events=("PutEventSelectors",),
        mitre=("T1562.008",),
        evaluate=management_events_excluded,
    ),
    Rule(
        id="LOG-005",
        title="GuardDuty disabled or deleted",
        severity=CRITICAL,
        source=GUARDDUTY,
        events=("DeleteDetector", "UpdateDetector"),
        mitre=("T1562.001",),
        evaluate=guardduty_disabled,
        remediate=reenable_guardduty,
        remediation="Re-enable the detector",
    ),
    Rule(
        id="LOG-006",
        title="AWS Config recorder stopped or deleted",
        severity=HIGH,
        source=CONFIG,
        events=("StopConfigurationRecorder", "DeleteConfigurationRecorder"),
        mitre=("T1562.001",),
        evaluate=config_recorder_stopped,
        remediate=restart_config_recorder,
        remediation="Restart the recorder",
    ),
    Rule(
        id="LOG-007",
        title="VPC flow logs deleted",
        severity=HIGH,
        source=EC2,
        events=("DeleteFlowLogs",),
        mitre=("T1562.008",),
        evaluate=flow_logs_deleted,
    ),
]
