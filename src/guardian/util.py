"""Helpers for picking apart CloudTrail events and IAM policy documents."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Iterator
from urllib.parse import unquote

WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"
PUBLIC_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)
PUBLIC_CANNED_ACLS = {"public-read", "public-read-write", "authenticated-read"}


def params(event: dict) -> dict:
    return event.get("requestParameters") or {}


def response(event: dict) -> dict:
    return event.get("responseElements") or {}


def identity(event: dict) -> dict:
    return event.get("userIdentity") or {}


def actor(event: dict) -> str:
    ident = identity(event)
    return ident.get("arn") or ident.get("principalId") or ident.get("type") or "unknown"


def actor_name(event: dict) -> str:
    """IAM user name of the caller, or '' for roles, root and services."""
    return identity(event).get("userName") or ""


def is_root(event: dict) -> bool:
    return identity(event).get("type") == "Root"


def items(node: Any) -> list:
    """CloudTrail wraps EC2 lists as {"items": [...]}; accept that or a bare list."""
    if isinstance(node, dict):
        node = node.get("items", [])
    return node if isinstance(node, list) else []


def as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def walk_strings(node: Any) -> Iterator[str]:
    """Yield every string value nested anywhere inside node."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from walk_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk_strings(value)


def load_policy(doc: Any) -> dict:
    """Policy documents arrive as dicts, JSON strings, or URL-encoded JSON strings."""
    if isinstance(doc, dict):
        return doc
    if not isinstance(doc, str) or not doc.strip():
        return {}
    for candidate in (doc, unquote(doc)):
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def statements(policy: dict) -> list[dict]:
    return [s for s in as_list(policy.get("Statement")) if isinstance(s, dict)]


def _principals(statement: dict) -> list[str]:
    principal = statement.get("Principal")
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        return [p for value in principal.values() for p in as_list(value) if isinstance(p, str)]
    return []


def allows_everyone(statement: dict) -> bool:
    """Allow statement whose principal is '*' and that has no Condition narrowing it."""
    return (
        statement.get("Effect") == "Allow"
        and "*" in _principals(statement)
        and not statement.get("Condition")
    )


def is_full_admin(statement: dict) -> bool:
    """Allow statement granting every action on every resource."""
    if statement.get("Effect") != "Allow":
        return False
    actions = [a for a in as_list(statement.get("Action")) if isinstance(a, str)]
    resources = [r for r in as_list(statement.get("Resource")) if isinstance(r, str)]
    return any(a in ("*", "*:*") for a in actions) and "*" in resources


_ACCOUNT_RE = re.compile(r"^(?:arn:aws[a-z-]*:(?:iam|sts)::)?(\d{12})(?::.*)?$")


def external_principals(policy: dict, own_account: str) -> list[str]:
    """AWS principals in a trust policy that are '*' or belong to another account."""
    found = []
    for statement in statements(policy):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            found.append("*")
            continue
        if not isinstance(principal, dict):
            continue
        for value in as_list(principal.get("AWS")):
            if value == "*":
                found.append("*")
                continue
            match = _ACCOUNT_RE.match(value) if isinstance(value, str) else None
            if match and match.group(1) != own_account:
                found.append(value)
    return found


def open_to_world(permission: dict) -> bool:
    cidrs = {r.get("cidrIp") for r in items(permission.get("ipRanges"))}
    cidrs |= {r.get("cidrIpv6") for r in items(permission.get("ipv6Ranges"))}
    return bool(cidrs & {WORLD_V4, WORLD_V6})


def port_range(permission: dict) -> tuple[int, int]:
    """Inclusive port range of an ingress permission; all-traffic rules cover 0-65535."""
    protocol = str(permission.get("ipProtocol", "-1"))
    if protocol == "-1":
        return (0, 65535)
    lo, hi = permission.get("fromPort"), permission.get("toPort")
    if lo is None or hi is None or lo == -1:
        return (0, 65535)
    return (int(lo), int(hi))


def covers_any(permission: dict, ports: Iterable[int]) -> list[int]:
    if str(permission.get("ipProtocol", "-1")) not in ("-1", "tcp", "6"):
        return []
    lo, hi = port_range(permission)
    return sorted(p for p in ports if lo <= p <= hi)


def ingress_permissions(event: dict) -> list[dict]:
    """Normalise both request shapes AuthorizeSecurityGroupIngress can log."""
    p = params(event)
    perms = list(items(p.get("ipPermissions")))
    if p.get("cidrIp") or p.get("cidrIpv6"):  # flat single-rule form
        perms.append(
            {
                "ipProtocol": p.get("ipProtocol", "-1"),
                "fromPort": p.get("fromPort"),
                "toPort": p.get("toPort"),
                "ipRanges": {"items": [{"cidrIp": p["cidrIp"]}] if p.get("cidrIp") else []},
                "ipv6Ranges": {"items": [{"cidrIpv6": p["cidrIpv6"]}] if p.get("cidrIpv6") else []},
            }
        )
    return perms


def to_boto_permission(permission: dict) -> dict:
    """Rebuild a CloudTrail ingress permission as a boto3 IpPermission, world CIDRs only."""
    out: dict[str, Any] = {"IpProtocol": str(permission.get("ipProtocol", "-1"))}
    if out["IpProtocol"] != "-1" and permission.get("fromPort") is not None:
        out["FromPort"] = int(permission["fromPort"])
        out["ToPort"] = int(permission["toPort"])
    v4 = [r for r in items(permission.get("ipRanges")) if r.get("cidrIp") == WORLD_V4]
    v6 = [r for r in items(permission.get("ipv6Ranges")) if r.get("cidrIpv6") == WORLD_V6]
    if v4:
        out["IpRanges"] = [{"CidrIp": WORLD_V4}]
    if v6:
        out["Ipv6Ranges"] = [{"CidrIpv6": WORLD_V6}]
    return out
