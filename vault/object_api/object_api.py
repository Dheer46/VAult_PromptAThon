"""Object API (diagram box) — arrow #6: Object API -> Object Metadata "handles metadata".

All object-level metadata assembly lives here: HTTP inputs (headers, user metadata,
tags, storage class, checksums) become FileVersion fields, and FileVersion fields
become response headers (ETag, Content-Type, Last-Modified, x-amz-meta-*, version id).
"""
from __future__ import annotations

import urllib.parse

from .. import errors
from ..api_surface.s3_xml import http_date
from ..storage_core.erasure_set import PutOpts
from ..storage_core.filemeta import (NULL_VERSION, REPL_STATUS, SSE_KEY, TRANSITIONED_OBJECT,
                                     FileVersion, new_version_id)

STORED_HEADERS = ("content-type", "content-encoding", "content-disposition", "content-language",
                  "cache-control", "expires")
REPLICA_MARKER = "x-amz-meta-vault-replication-status"


class ObjectAPI:
    def __init__(self, settings):
        self.s = settings

    # --------------------------------------------------------- request -> meta
    def version_id_for(self, versioning: str) -> str:
        return new_version_id() if versioning == "Enabled" else NULL_VERSION

    def parity_for(self, storage_class: str | None, bucket_parity: int | None) -> int | None:
        if storage_class in (None, "", "STANDARD"):
            return bucket_parity
        if storage_class == "REDUCED_REDUNDANCY":
            return self.s.rrs_parity
        raise errors.S3Error("InvalidStorageClass", f"unsupported storage class {storage_class}")

    def build_meta(self, headers) -> tuple[dict, dict]:
        """(meta_user, meta_sys) from request headers."""
        user: dict[str, str] = {}
        sys: dict = {}
        for h in STORED_HEADERS:
            if headers.get(h):
                user[h] = headers[h]
        user.setdefault("content-type", "application/octet-stream")
        size = 0
        for k, v in headers.items():
            kl = k.lower()
            if kl.startswith("x-amz-meta-"):
                if kl == REPLICA_MARKER:
                    if v.upper() == "REPLICA":  # incoming replica: never replicate it again
                        sys[REPL_STATUS] = "REPLICA"
                    continue
                user[kl] = v
                size += len(kl) + len(v)
        if size > 2048:
            raise errors.S3Error("MetadataTooLarge", "user metadata exceeds 2 KiB", 400)
        if headers.get("x-amz-tagging"):
            user["x-amz-tagging"] = self.normalize_tagging(headers["x-amz-tagging"])
        sc = headers.get("x-amz-storage-class")
        if sc and sc != "STANDARD":
            user["x-amz-storage-class"] = sc
        return user, sys

    @staticmethod
    def normalize_tagging(raw: str) -> str:
        pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
        if len(pairs) > 10:
            raise errors.S3Error("InvalidArgument", "at most 10 tags per object")
        return urllib.parse.urlencode(pairs)

    @staticmethod
    def tags(fv: FileVersion) -> dict[str, str]:
        return dict(urllib.parse.parse_qsl(fv.meta_user.get("x-amz-tagging", ""), keep_blank_values=True))

    def put_opts(self, bm, headers, versioning: str | None = None) -> PutOpts:
        user, sys = self.build_meta(headers)
        return PutOpts(version_id=self.version_id_for(versioning or bm.versioning),
                       versioned=bm.versioning == "Enabled",
                       parity=self.parity_for(headers.get("x-amz-storage-class"), bm.parity),
                       meta_user=user, meta_sys=sys)

    # --------------------------------------------------------- meta -> response
    @staticmethod
    def plain_size(fv: FileVersion) -> int:
        if "x-vault-actual-size" in fv.meta_sys:
            return int(fv.meta_sys["x-vault-actual-size"])
        if fv.parts:
            return sum(p.actual_size for p in fv.parts)
        return fv.size

    def response_headers(self, fv: FileVersion, is_latest: bool = True) -> dict[str, str]:
        h = {"etag": f'"{fv.etag}"', "last-modified": http_date(fv.mod_time_ns),
             "content-length": str(self.plain_size(fv)), "accept-ranges": "bytes"}
        for k, v in fv.meta_user.items():
            if k in STORED_HEADERS or k.startswith("x-amz-meta-"):
                h[k] = v
        if fv.version_id != NULL_VERSION:
            h["x-amz-version-id"] = fv.version_id
        sc = fv.meta_user.get("x-amz-storage-class")
        if sc:
            h["x-amz-storage-class"] = sc
        st = fv.meta_sys.get(REPL_STATUS)
        if st:
            h["x-amz-replication-status"] = st
        if "x-amz-tagging" in fv.meta_user:
            h["x-amz-tagging-count"] = str(len(self.tags(fv)))
        if fv.parts and len(fv.parts) > 1:
            h["x-amz-mp-parts-count"] = str(len(fv.parts))
        sse = fv.meta_sys.get(SSE_KEY)
        if sse:
            if sse["algo"] == "SSE-C":
                h["x-amz-server-side-encryption-customer-algorithm"] = "AES256"
                h["x-amz-server-side-encryption-customer-key-md5"] = sse.get("ssec_md5", "")
            else:
                h["x-amz-server-side-encryption"] = sse["algo"]
                if sse["algo"] == "aws:kms":
                    h["x-amz-server-side-encryption-aws-kms-key-id"] = sse.get("kms_key_id", "")
        if TRANSITIONED_OBJECT in fv.meta_sys:
            h["x-amz-storage-class"] = fv.meta_sys[TRANSITIONED_OBJECT].get("tier", sc or "")
        return h

    @staticmethod
    def parse_range(header: str | None, size: int) -> tuple[int, int] | None:
        """Returns (offset, length) or None for the whole object."""
        if not header or not header.startswith("bytes="):
            return None
        spec = header[6:].split(",")[0].strip()
        start_s, _, end_s = spec.partition("-")
        try:
            if start_s == "":
                n = int(end_s)
                if n <= 0:
                    raise errors.S3Error("InvalidRange", "bad range")
                start = max(0, size - n)
                end = size - 1
            else:
                start = int(start_s)
                end = int(end_s) if end_s else size - 1
        except ValueError:
            return None
        if start >= size or start > end:
            raise errors.S3Error("InvalidRange", "The requested range is not satisfiable",
                                 ActualObjectSize=str(size))
        end = min(end, size - 1)
        return start, end - start + 1
