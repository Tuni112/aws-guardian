"""Privilege escalation and persistence through IAM."""

from __future__ import annotations

from ..models import CRITICAL, HIGH, MEDIUM, Clients, Detection, Rule
from ..util import actor_name, external_principals, is_full_admin, is_root, load_policy, params, response, statements

IAM = "iam.amazonaws.com"
ORGANIZATIONS = "organizations.amazonaws.com"
ADMIN_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess": "AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess": "IAMFullAccess",
}
MIN_PASSWORD_LENGTH = 14


def _target(event: dict) -> tuple[str, str]:
    """(kind, name) of the user, role or group an IAM call was aimed at."""
    p = params(event)
    for kind in ("user", "role", "group"):
        if p.get(f"{kind}Name"):
            return kind, p[f"{kind}Name"]
    return "user", actor_name(event) or "unknown"


def admin_policy_attached(event: dict):
    policy = ADMIN_POLICIES.get(params(event).get("policyArn", ""))
    if not policy:
        return None
    kind, name = _target(event)
    return Detection(f"{kind}/{name}", f"{policy} attached to {kind} {name}", {"kind": kind, "name": name})


def detach_admin_policy(event: dict, detection: Detection, clients: Clients) -> str:
    iam = clients.get("iam")
    kind, name = detection.context["kind"], detection.context["name"]
    arn = params(event)["policyArn"]
    if kind == "user":
        iam.detach_user_policy(UserName=name, PolicyArn=arn)
    elif kind == "role":
        iam.detach_role_policy(RoleName=name, PolicyArn=arn)
    else:
        iam.detach_group_policy(GroupName=name, PolicyArn=arn)
    return f"detached the policy from {kind} {name}"


def inline_admin_policy(event: dict):
    p = params(event)
    policy = load_policy(p.get("policyDocument"))
    if not any(is_full_admin(s) for s in statements(policy)):
        return None
    kind, name = _target(event)
    return Detection(
        f"{kind}/{name}",
        f"Inline policy {p.get('policyName')} grants every action on every resource",
        {"kind": kind, "name": name, "policy": p.get("policyName")},
    )


def delete_inline_policy(event: dict, detection: Detection, clients: Clients) -> str:
    iam = clients.get("iam")
    kind, name, policy = (detection.context[k] for k in ("kind", "name", "policy"))
    if kind == "user":
        iam.delete_user_policy(UserName=name, PolicyName=policy)
    elif kind == "role":
        iam.delete_role_policy(RoleName=name, PolicyName=policy)
    else:
        iam.delete_group_policy(GroupName=name, PolicyName=policy)
    return f"deleted the inline policy from {kind} {name}"


def access_key_for_other_user(event: dict):
    target = params(event).get("userName")
    if not target or target == actor_name(event):
        return None
    key = (response(event).get("accessKey") or {}).get("accessKeyId")
    return Detection(
        f"user/{target}",
        f"Access key created for {target} by a different identity",
        {"user": target, "access_key_id": key},
    )


def deactivate_access_key(event: dict, detection: Detection, clients: Clients) -> str:
    key = detection.context.get("access_key_id")
    if not key:
        return "none: the access key id was not present in the event"
    clients.get("iam").update_access_key(
        UserName=detection.context["user"], AccessKeyId=key, Status="Inactive"
    )
    return "deactivated the new access key"


def root_access_key_created(event: dict):
    if is_root(event):
        return Detection("root", "Access key created for the root user")
    return None


def console_password_for_other_user(event: dict):
    target = params(event).get("userName")
    if not target or target == actor_name(event):
        return None
    verb = "created" if event["eventName"] == "CreateLoginProfile" else "reset"
    return Detection(f"user/{target}", f"Console password {verb} for {target} by a different identity")


def mfa_removed(event: dict):
    p = params(event)
    target = p.get("userName") or actor_name(event) or "unknown"
    return Detection(f"user/{target}", f"MFA device {p.get('serialNumber', '')} deactivated".replace("  ", " "))


def trust_policy_external(event: dict):
    p = params(event)
    policy = load_policy(p.get("policyDocument") or p.get("assumeRolePolicyDocument"))
    outside = external_principals(policy, event.get("recipientAccountId", ""))
    if not outside:
        return None
    severity_note = "anyone" if "*" in outside else ", ".join(sorted(set(outside)))
    return Detection(
        f"role/{p.get('roleName', 'unknown')}",
        f"Role trust policy lets principals outside this account assume it: {severity_note}",
        {"principals": sorted(set(outside))},
    )


def password_policy_weakened(event: dict):
    account = event.get("recipientAccountId", "unknown-account")
    if event["eventName"] == "DeleteAccountPasswordPolicy":
        return Detection(account, "Account password policy was deleted")
    length = params(event).get("minimumPasswordLength")
    if isinstance(length, int) and length < MIN_PASSWORD_LENGTH:
        return Detection(account, f"Password policy minimum length lowered to {length}")
    return None


def leave_organization(event: dict):
    outcome = "was denied" if event.get("errorCode") else "succeeded"
    return Detection(
        event.get("recipientAccountId", "unknown-account"),
        f"Attempt to remove this account from its AWS Organization {outcome}",
    )


RULES = [
    Rule(
        id="IAM-001",
        title="Administrator policy attached to a user, role or group",
        severity=CRITICAL,
        source=IAM,
        events=("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"),
        mitre=("T1098.003",),
        evaluate=admin_policy_attached,
        remediate=detach_admin_policy,
        remediation="Detach the policy",
    ),
    Rule(
        id="IAM-002",
        title="Inline policy grants full administrator access",
        severity=CRITICAL,
        source=IAM,
        events=("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"),
        mitre=("T1098.003",),
        evaluate=inline_admin_policy,
        remediate=delete_inline_policy,
        remediation="Delete the inline policy",
    ),
    Rule(
        id="IAM-003",
        title="Access key created for another user",
        severity=HIGH,
        source=IAM,
        events=("CreateAccessKey",),
        mitre=("T1098.001",),
        evaluate=access_key_for_other_user,
        remediate=deactivate_access_key,
        remediation="Deactivate the new key",
    ),
    Rule(
        id="IAM-004",
        title="Root user access key created",
        severity=CRITICAL,
        source=IAM,
        events=("CreateAccessKey",),
        mitre=("T1098.001",),
        evaluate=root_access_key_created,
    ),
    Rule(
        id="IAM-005",
        title="Console password set for another user",
        severity=HIGH,
        source=IAM,
        events=("CreateLoginProfile", "UpdateLoginProfile"),
        mitre=("T1098",),
        evaluate=console_password_for_other_user,
    ),
    Rule(
        id="IAM-006",
        title="MFA device deactivated",
        severity=HIGH,
        source=IAM,
        events=("DeactivateMFADevice",),
        mitre=("T1556.006",),
        evaluate=mfa_removed,
    ),
    Rule(
        id="IAM-007",
        title="Role trust policy allows an external account",
        severity=HIGH,
        source=IAM,
        events=("UpdateAssumeRolePolicy", "CreateRole"),
        mitre=("T1098.003",),
        evaluate=trust_policy_external,
    ),
    Rule(
        id="IAM-008",
        title="Account password policy weakened or deleted",
        severity=MEDIUM,
        source=IAM,
        events=("DeleteAccountPasswordPolicy", "UpdateAccountPasswordPolicy"),
        mitre=("T1556",),
        evaluate=password_policy_weakened,
    ),
    Rule(
        id="IAM-009",
        title="Attempt to leave the AWS Organization",
        severity=CRITICAL,
        source=ORGANIZATIONS,
        events=("LeaveOrganization",),
        mitre=("T1666",),
        evaluate=leave_organization,
        include_failed=True,
    ),
]
