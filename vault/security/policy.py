"""AWS IAM policy semantics (the core of it): explicit Deny beats Allow; wildcards in
actions and resources; common conditions; bucket policies with Principal."""
from __future__ import annotations

import ipaddress
import json
from fnmatch import fnmatchcase

# Every S3 API name -> its IAM action. Keep this table in one place.
API_ACTIONS = {
    "ListBuckets": "s3:ListAllMyBuckets",
    "CreateBucket": "s3:CreateBucket", "DeleteBucket": "s3:DeleteBucket",
    "HeadBucket": "s3:ListBucket", "ListObjects": "s3:ListBucket",
    "ListObjectsV2": "s3:ListBucket", "ListObjectVersions": "s3:ListBucketVersions",
    "ListMultipartUploads": "s3:ListBucketMultipartUploads",
    "GetBucketLocation": "s3:GetBucketLocation",
    "GetBucketVersioning": "s3:GetBucketVersioning", "PutBucketVersioning": "s3:PutBucketVersioning",
    "GetBucketPolicy": "s3:GetBucketPolicy", "PutBucketPolicy": "s3:PutBucketPolicy",
    "DeleteBucketPolicy": "s3:DeleteBucketPolicy",
    "GetBucketLifecycleConfiguration": "s3:GetLifecycleConfiguration",
    "PutBucketLifecycleConfiguration": "s3:PutLifecycleConfiguration",
    "DeleteBucketLifecycle": "s3:PutLifecycleConfiguration",
    "GetBucketReplication": "s3:GetReplicationConfiguration",
    "PutBucketReplication": "s3:PutReplicationConfiguration",
    "DeleteBucketReplication": "s3:PutReplicationConfiguration",
    "GetBucketEncryption": "s3:GetEncryptionConfiguration",
    "PutBucketEncryption": "s3:PutEncryptionConfiguration",
    "DeleteBucketEncryption": "s3:PutEncryptionConfiguration",
    "GetBucketNotificationConfiguration": "s3:GetBucketNotification",
    "PutBucketNotificationConfiguration": "s3:PutBucketNotification",
    "GetBucketTagging": "s3:GetBucketTagging", "PutBucketTagging": "s3:PutBucketTagging",
    "DeleteBucketTagging": "s3:PutBucketTagging",
    "GetObject": "s3:GetObject", "HeadObject": "s3:GetObject",
    "GetObjectVersion": "s3:GetObjectVersion",
    "PutObject": "s3:PutObject", "CopyObject": "s3:PutObject",
    "CreateMultipartUpload": "s3:PutObject", "UploadPart": "s3:PutObject",
    "UploadPartCopy": "s3:PutObject",
    "CompleteMultipartUpload": "s3:PutObject",
    "AbortMultipartUpload": "s3:AbortMultipartUpload",
    "ListParts": "s3:ListMultipartUploadParts",
    "DeleteObject": "s3:DeleteObject", "DeleteObjectVersion": "s3:DeleteObjectVersion",
    "DeleteObjects": "s3:DeleteObject",
    "GetObjectTagging": "s3:GetObjectTagging", "PutObjectTagging": "s3:PutObjectTagging",
    "DeleteObjectTagging": "s3:DeleteObjectTagging",
    "RestoreObject": "s3:RestoreObject",
}

BUILTIN_POLICIES = {
    "readonly": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:GetObject", "s3:GetObjectVersion",
                                       "s3:ListBucket", "s3:ListBucketVersions", "s3:ListAllMyBuckets"],
         "Resource": ["arn:aws:s3:::*"]}]},
    "writeonly": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:AbortMultipartUpload",
                                       "s3:ListMultipartUploadParts"],
         "Resource": ["arn:aws:s3:::*"]}]},
    "readwrite": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::*"]}]},
    "consoleAdmin": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["admin:*", "kms:*", "s3:*"], "Resource": ["arn:aws:s3:::*"]}]},
}


def resource_arn(bucket: str = "", key: str = "") -> str:
    if not bucket:
        return "arn:aws:s3:::*"
    return f"arn:aws:s3:::{bucket}/{key}" if key else f"arn:aws:s3:::{bucket}"


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _match_any(patterns, value: str) -> bool:
    return any(fnmatchcase(value, p) for p in _as_list(patterns))


def _match_resource(patterns, resource: str) -> bool:
    for p in _as_list(patterns):
        if fnmatchcase(resource, p):
            return True
        # "arn:aws:s3:::bucket/*" should also cover bucket-level checks only via explicit ARN
    return False


def _cond_values(conditions: dict, key: str) -> list[str]:
    for k, v in conditions.items():
        if k.lower() == key.lower():
            return [str(x) for x in _as_list(v)]
    return []


def _eval_conditions(block: dict | None, conditions: dict) -> bool:
    if not block:
        return True
    for op, kv in block.items():
        opl = op.lower()
        if_exists = opl.endswith("ifexists")
        opl = opl.removesuffix("ifexists")
        for key, expected in kv.items():
            actual = _cond_values(conditions, key)
            exp = [str(x) for x in _as_list(expected)]
            if not actual:
                if if_exists:
                    continue
                if opl.startswith("stringnot") or opl.startswith("notip"):
                    continue
                return False
            if opl == "stringequals":
                ok = any(a in exp for a in actual)
            elif opl == "stringnotequals":
                ok = not any(a in exp for a in actual)
            elif opl == "stringequalsignorecase":
                ok = any(a.lower() in [e.lower() for e in exp] for a in actual)
            elif opl == "stringlike":
                ok = any(fnmatchcase(a, e) for a in actual for e in exp)
            elif opl == "stringnotlike":
                ok = not any(fnmatchcase(a, e) for a in actual for e in exp)
            elif opl in ("ipaddress", "notipaddress"):
                try:
                    hit = any(ipaddress.ip_address(a) in ipaddress.ip_network(e, strict=False)
                              for a in actual for e in exp)
                except ValueError:
                    hit = False
                ok = hit if opl == "ipaddress" else not hit
            elif opl == "bool":
                ok = any(a.lower() == e.lower() for a in actual for e in exp)
            elif opl in ("numericequals", "numericlessthan", "numericlessthanequals",
                         "numericgreaterthan", "numericgreaterthanequals"):
                try:
                    a, e = float(actual[0]), float(exp[0])
                except ValueError:
                    return False
                ok = {"numericequals": a == e, "numericlessthan": a < e,
                      "numericlessthanequals": a <= e, "numericgreaterthan": a > e,
                      "numericgreaterthanequals": a >= e}[opl]
            else:
                return False  # unknown operator: fail closed
            if not ok:
                return False
    return True


def _principal_matches(principal, who: str) -> bool:
    if principal is None:
        return True  # identity policies have no Principal
    if principal == "*":
        return True
    if isinstance(principal, dict):
        vals = _as_list(principal.get("AWS"))
        return "*" in vals or who in vals or any(v.endswith(f":user/{who}") for v in vals)
    return principal == who


def evaluate(policies: list[dict], action: str, resource: str, conditions: dict,
             principal: str | None = None) -> str | None:
    """Returns "deny", "allow" or None (no statement matched)."""
    allowed = False
    for p in policies:
        for s in _as_list(p.get("Statement")):
            if "Principal" in s and not _principal_matches(s["Principal"], principal or ""):
                continue
            if "Action" in s and not _match_any(s["Action"], action):
                continue
            if "NotAction" in s and _match_any(s["NotAction"], action):
                continue
            if "Resource" in s and not _match_resource(s["Resource"], resource):
                continue
            if "NotResource" in s and _match_resource(s["NotResource"], resource):
                continue
            if not _eval_conditions(s.get("Condition"), conditions):
                continue
            if s.get("Effect") == "Deny":
                return "deny"  # explicit deny always wins
            allowed = True
    return "allow" if allowed else None


def is_allowed(policies: list[dict], action: str, resource: str, conditions: dict) -> bool:
    return evaluate(policies, action, resource, conditions) == "allow"


def parse_policy(text: str) -> dict:
    doc = json.loads(text)
    if not isinstance(doc, dict) or "Statement" not in doc:
        raise ValueError("policy must have a Statement")
    for s in _as_list(doc["Statement"]):
        if s.get("Effect") not in ("Allow", "Deny"):
            raise ValueError("Effect must be Allow or Deny")
    return doc
