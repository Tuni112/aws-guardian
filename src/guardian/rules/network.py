"""Network exposure: security groups opened to the internet."""

from __future__ import annotations

from ..models import CRITICAL, HIGH, Clients, Detection, Rule
from ..util import covers_any, ingress_permissions, open_to_world, params, port_range, to_boto_permission

EC2 = "ec2.amazonaws.com"
ADMIN_PORTS = (22, 3389)
DATA_PORTS = (1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017)


def _group(event: dict) -> str:
    p = params(event)
    return p.get("groupId") or p.get("groupName") or "unknown-security-group"


def _world_permissions(event: dict) -> list[dict]:
    return [perm for perm in ingress_permissions(event) if open_to_world(perm)]


def _is_everything(permission: dict) -> bool:
    return port_range(permission) == (0, 65535)


def _detect(event: dict, ports: tuple[int, ...], label: str):
    offending, hit = [], set()
    for perm in _world_permissions(event):
        if _is_everything(perm):
            continue  # reported once by NET-003 instead of by every port rule
        matched = covers_any(perm, ports)
        if matched:
            offending.append(to_boto_permission(perm))
            hit.update(matched)
    if not offending:
        return None
    listed = ", ".join(str(p) for p in sorted(hit))
    return Detection(
        _group(event),
        f"Security group allows the internet to reach {label} port(s) {listed}",
        {"revoke": offending, "ports": sorted(hit)},
    )


def admin_ports_open(event: dict):
    return _detect(event, ADMIN_PORTS, "remote administration")


def data_ports_open(event: dict):
    return _detect(event, DATA_PORTS, "database")


def all_ports_open(event: dict):
    offending = [to_boto_permission(p) for p in _world_permissions(event) if _is_everything(p)]
    if not offending:
        return None
    return Detection(
        _group(event),
        "Security group allows the internet to reach every port",
        {"revoke": offending},
    )


def revoke_ingress(event: dict, detection: Detection, clients: Clients) -> str:
    clients.get("ec2", event.get("awsRegion")).revoke_security_group_ingress(
        GroupId=detection.resource, IpPermissions=detection.context["revoke"]
    )
    return f"revoked {len(detection.context['revoke'])} internet-facing ingress rule(s)"


_COMMON = dict(
    source=EC2,
    events=("AuthorizeSecurityGroupIngress",),
    mitre=("T1562.007",),
    remediate=revoke_ingress,
    remediation="Revoke the offending ingress rules, leaving the rest of the group intact",
)

RULES = [
    Rule(
        id="NET-001",
        title="Security group opens SSH or RDP to the internet",
        severity=CRITICAL,
        evaluate=admin_ports_open,
        **_COMMON,
    ),
    Rule(
        id="NET-002",
        title="Security group opens a database port to the internet",
        severity=HIGH,
        evaluate=data_ports_open,
        **_COMMON,
    ),
    Rule(
        id="NET-003",
        title="Security group opens all ports to the internet",
        severity=CRITICAL,
        evaluate=all_ports_open,
        **_COMMON,
    ),
]
