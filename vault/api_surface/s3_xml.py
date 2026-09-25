"""S3 XML: build responses with ElementTree, parse request bodies with defusedxml
(protects against XML attacks)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from defusedxml import ElementTree as DET

from .. import errors

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def E(tag: str, *children, text=None, **attrs) -> ET.Element:
    el = ET.Element(tag, {k: str(v) for k, v in attrs.items()})
    if text is not None:
        el.text = str(text)
    for c in children:
        if c is None:
            continue
        if isinstance(c, (list, tuple)):
            for cc in c:
                if cc is not None:
                    el.append(cc)
        else:
            el.append(c)
    return el


def T(tag: str, value) -> ET.Element | None:
    """Leaf element; skipped when value is None."""
    if value is None:
        return None
    if isinstance(value, bool):
        value = "true" if value else "false"
    return E(tag, text=value)


def to_bytes(root: ET.Element, ns: bool = True) -> bytes:
    if ns and "xmlns" not in root.attrib:
        root.set("xmlns", S3_NS)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def iso8601(ns: int) -> str:
    dt = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def http_date(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def error_xml(code: str, message: str, resource: str = "", request_id: str = "",
              bucket: str = "", key: str = "", **extra) -> bytes:
    root = E("Error", T("Code", code), T("Message", message), T("Resource", resource or None),
             T("BucketName", bucket or None), T("Key", key or None),
             *[T(k, v) for k, v in extra.items() if isinstance(v, (str, int))],
             T("RequestId", request_id))
    return to_bytes(root, ns=False)


def strip_ns(el: ET.Element) -> ET.Element:
    for e in el.iter():
        if isinstance(e.tag, str) and "}" in e.tag:
            e.tag = e.tag.split("}", 1)[1]
    return el


def parse(body: bytes) -> ET.Element:
    if not body:
        raise errors.S3Error("MalformedXML", "empty body")
    try:
        return strip_ns(DET.fromstring(body))
    except Exception:
        raise errors.S3Error("MalformedXML", "the XML you provided was not well-formed")


def parse_complete_multipart(body: bytes) -> list[tuple[int, str]]:
    root = parse(body)
    parts = []
    for p in root.findall("Part"):
        try:
            parts.append((int(p.findtext("PartNumber")), (p.findtext("ETag") or "").strip('"')))
        except (TypeError, ValueError):
            raise errors.S3Error("MalformedXML", "bad part")
    return parts


def parse_delete_objects(body: bytes) -> tuple[list[tuple[str, str | None]], bool]:
    root = parse(body)
    quiet = (root.findtext("Quiet") or "").lower() == "true"
    objs = [(o.findtext("Key") or "", o.findtext("VersionId")) for o in root.findall("Object")]
    if len(objs) > 1000:
        raise errors.S3Error("MalformedXML", "at most 1000 keys")
    return objs, quiet


def parse_versioning(body: bytes) -> str:
    status = parse(body).findtext("Status") or ""
    if status not in ("Enabled", "Suspended"):
        raise errors.S3Error("MalformedXML", "Status must be Enabled or Suspended")
    return status


def parse_tagging(body: bytes) -> dict[str, str]:
    root = parse(body)
    tags = {}
    for t in root.findall("TagSet/Tag"):
        k, v = t.findtext("Key") or "", t.findtext("Value") or ""
        if not k or len(k) > 128 or len(v) > 256:
            raise errors.S3Error("InvalidArgument", "bad tag")
        tags[k] = v
    if len(tags) > 50:
        raise errors.S3Error("InvalidArgument", "too many tags")
    return tags


def tagging_xml(tags: dict[str, str]) -> bytes:
    return to_bytes(E("Tagging", E("TagSet", [E("Tag", T("Key", k), T("Value", v))
                                                for k, v in tags.items()])))


def parse_encryption(body: bytes) -> dict:
    root = parse(body)
    rule = root.find("Rule/ApplyServerSideEncryptionByDefault")
    if rule is None:
        raise errors.S3Error("MalformedXML", "missing ApplyServerSideEncryptionByDefault")
    algo = rule.findtext("SSEAlgorithm") or ""
    if algo not in ("AES256", "aws:kms"):
        raise errors.S3Error("InvalidArgument", "SSEAlgorithm must be AES256 or aws:kms")
    return {"algo": algo, "kms_key_id": rule.findtext("KMSMasterKeyID") or ""}
