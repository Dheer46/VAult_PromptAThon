"""Application Facade (diagram box): the orchestrator for one request. The single
place that combines the authorization result, bucket config, encryption, the
storage call, and events.

Arrows: #3 API Surface -> Application Facade "enters application" (callers),
#4 -> Storage Facade "delegates storage", #5 -> Bucket Metadata "reads config".
Implicit arrows (not drawn but required): -> IAM on every request, -> Encryption
KMS on PUT/GET, -> Event Notifications after each operation. The audit entry is
written by the API Surface middleware so failures are captured too.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import AsyncIterator

from .. import errors
from ..api_surface import s3_xml
from ..object_api import multipart as mp
from ..security import policy as pol
from ..security import sse
from ..security.lifecycle import parse_lifecycle
from ..ops.replication import parse_replication
from ..storage_core.erasure_set import PutOpts
from ..storage_core.filemeta import NULL_VERSION, SSE_KEY, TRANSITIONED_OBJECT
from .context import RequestContext

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
EMPTY_MD5 = hashlib.md5(b"").hexdigest()


def check_bucket_name(name: str) -> None:
    if not _BUCKET_RE.match(name) or ".." in name or name.startswith("xn--") or \
            re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
        raise errors.S3Error("InvalidBucketName", f"invalid bucket name {name!r}")


def check_key(key: str) -> None:
    if not key or len(key.encode()) > 1024:
        raise errors.S3Error("KeyTooLongError" if key else "InvalidArgument", "bad object key")
    if any(seg in ("..", ".") for seg in key.split("/")) or "\\" in key or key.startswith("/"):
        raise errors.S3Error("InvalidArgument", "object key contains an invalid path segment")


class HashingReader:
    """Streams the request body while computing MD5 (ETag), optional SHA-256 and
    the byte count. Mismatches raise at the end of the stream, i.e. before commit."""

    def __init__(self, body: AsyncIterator[bytes], size: int = -1, content_md5: str | None = None,
                 sha256: str | None = None):
        self.body = body
        self.size = size
        self.content_md5 = content_md5
        self.sha256 = sha256 if sha256 and re.fullmatch(r"[0-9a-f]{64}", sha256) else None
        self._md5 = hashlib.md5()
        self._sha = hashlib.sha256() if self.sha256 else None
        self.count = 0

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        async for chunk in self.body:
            if not chunk:
                continue
            self._md5.update(chunk)
            if self._sha:
                self._sha.update(chunk)
            self.count += len(chunk)
            yield chunk
        if self.size >= 0 and self.count != self.size:
            raise errors.S3Error("IncompleteBody", f"expected {self.size} bytes, got {self.count}", 400)
        if self.content_md5 and base64.b64encode(self._md5.digest()).decode() != self.content_md5:
            raise errors.S3Error("BadDigest", "The Content-MD5 you specified did not match what we received")
        if self._sha and self._sha.hexdigest() != self.sha256:
            raise errors.S3Error("XAmzContentSHA256Mismatch", "payload SHA-256 mismatch")

    def etag(self) -> str:
        return self._md5.hexdigest()

    def actual(self) -> int:
        return self.count


class AppFacade:
    def __init__(self, settings, storage, bucket_meta, object_api, iam, kms, events=None,
                 tiers=None, lifecycle=None):
        self.s = settings
        self.storage = storage  # arrow #4
        self.bucket_meta = bucket_meta  # arrow #5
        self.objects = object_api  # arrow #6 (via Object API)
        self.iam = iam
        self.kms = kms
        self.events = events
        self.tiers = tiers
        self.lifecycle = lifecycle

    # -------------------------------------------------------- authorization
    async def authorize(self, ctx: RequestContext, api: str, bucket: str = "", key: str = "",
                        conditions: dict | None = None) -> None:
        action = pol.API_ACTIONS.get(api, f"s3:{api}")
        cond = {"aws:SourceIp": ctx.source_ip, "aws:SecureTransport": str(ctx.secure).lower(),
                **(conditions or {})}
        bp = None
        if bucket:
            try:
                bm = await self.bucket_meta.get(bucket)
                bp = bm.parsed("policy", "policy", json.loads)
            except errors.S3Error:
                bp = None
        if not self.iam.authorize(ctx.identity, action, bucket, key, cond, bp):
            raise errors.S3Error("AccessDenied", "Access Denied")

    # -------------------------------------------------------------- SSE
    def _bucket_sse(self, bm) -> dict | None:
        return bm.parsed("encryption", "encryption_xml",
                         lambda x: s3_xml.parse_encryption(x.encode()))

    async def _sse_for_put(self, bm, bucket: str, key: str, headers) -> tuple[bytes | None, dict | None]:
        ssec = sse.parse_ssec(headers)
        if ssec:
            return ssec[0], {"algo": "SSE-C", "ssec_md5": ssec[1]}
        algo = headers.get("x-amz-server-side-encryption")
        key_id = headers.get("x-amz-server-side-encryption-aws-kms-key-id")
        if not algo:
            d = self._bucket_sse(bm)
            if d:
                algo, key_id = d["algo"], key_id or d["kms_key_id"]
        if not algo:
            return None, None
        if algo not in ("AES256", "aws:kms"):
            raise errors.S3Error("InvalidArgument", "x-amz-server-side-encryption must be AES256 or aws:kms")
        key_id = key_id or self.s.kms_default_key
        context = {"bucket": bucket, "key": key}
        dek, sealed = await self.kms.generate_key(key_id, context)  # -> KMS Provider (#16)
        return dek, {"algo": algo, "kms_key_id": key_id, "sealed_key": sealed, "context": context}

    async def _dek(self, meta: dict, headers, prefix: str = "x-amz-server-side-encryption-customer-") -> bytes:
        if meta["algo"] == "SSE-C":
            got = sse.parse_ssec(headers, prefix)
            if not got:
                raise errors.S3Error("InvalidRequest", "object is encrypted with SSE-C; provide the key")
            if got[1] != meta.get("ssec_md5"):
                raise errors.S3Error("AccessDenied", "SSE-C key does not match")
            return got[0]
        return await self.kms.decrypt_key(meta["kms_key_id"], meta["sealed_key"], meta["context"])

    def _sse_headers(self, meta: dict | None) -> dict:
        if not meta:
            return {}
        if meta["algo"] == "SSE-C":
            return {"x-amz-server-side-encryption-customer-algorithm": "AES256",
                    "x-amz-server-side-encryption-customer-key-md5": meta["ssec_md5"]}
        h = {"x-amz-server-side-encryption": meta["algo"]}
        if meta["algo"] == "aws:kms":
            h["x-amz-server-side-encryption-aws-kms-key-id"] = meta["kms_key_id"]
        return h

    # ------------------------------------------------------------ objects
    async def _store(self, bucket: str, key: str, bm, reader: HashingReader, size: int, opts: PutOpts,
                     headers) -> tuple:
        dek, meta = await self._sse_for_put(bm, bucket, key, headers)
        opts.etag = reader.etag
        opts.actual_size = reader.actual
        if dek is not None:
            opts.meta_sys[SSE_KEY] = meta
            stream = sse.encrypt_stream(reader, dek, part=1)
            opts.size = sse.encrypted_size(size) if size >= 0 else -1
        else:
            stream = reader
            opts.size = size
        oi = await self.storage.put_object(bucket, key, stream, opts)  # arrow #4 (+#8 inside)
        return oi, meta

    async def put_object(self, ctx: RequestContext, bucket: str, key: str,
                         body: AsyncIterator[bytes], size: int, headers) -> dict:
        check_key(key)
        await self.authorize(ctx, "PutObject", bucket, key)  # implicit arrow -> IAM
        bm = await self.bucket_meta.get(bucket)  # arrow #5 "reads config"
        opts = self.objects.put_opts(bm, headers)  # arrow #6 "handles metadata"
        reader = HashingReader(body, size, headers.get("content-md5"),
                               headers.get("x-amz-content-sha256"))
        oi, meta = await self._store(bucket, key, bm, reader, size, opts, headers)
        ctx.bytes_in = reader.count
        if self.events:  # implicit arrow -> Event Notifications
            await self.events.send("s3:ObjectCreated:Put", bucket, key, reader.count,
                                   oi.version.etag, oi.version.version_id, ctx)
        h = {"etag": f'"{oi.version.etag}"', **self._sse_headers(meta)}
        if oi.version.version_id != NULL_VERSION:
            h["x-amz-version-id"] = oi.version.version_id
        return h

    def _check_conditions(self, fv, headers) -> None:
        etag = f'"{fv.etag}"'
        im, inm = headers.get("if-match"), headers.get("if-none-match")
        if im and im not in (etag, fv.etag, "*"):
            raise errors.S3Error("PreconditionFailed", "If-Match failed")
        if inm and inm in (etag, fv.etag, "*"):
            raise errors.S3Error("NotModified", "not modified")
        from email.utils import parsedate_to_datetime
        mod = fv.mod_time_ns / 1e9
        for h, cmp_fail, code in (("if-unmodified-since", lambda t: mod > t + 1, "PreconditionFailed"),
                                  ("if-modified-since", lambda t: mod <= t + 1, "NotModified")):
            v = headers.get(h)
            if v and not (h == "if-modified-since" and inm):
                try:
                    t = parsedate_to_datetime(v).timestamp()
                except (TypeError, ValueError):
                    continue
                if cmp_fail(t):
                    raise errors.S3Error(code, h)

    def _reader(self, oi):
        fv = oi.version
        if TRANSITIONED_OBJECT in fv.meta_sys:  # stored on the Remote S3 tier
            info = fv.meta_sys[TRANSITIONED_OBJECT]
            return lambda off, ln: self.tiers.read(info, off, ln)
        return lambda off, ln: self.storage.read(oi, off, ln)

    async def open_plain(self, oi, headers, offset: int, length: int,
                         ssec_prefix: str = "x-amz-server-side-encryption-customer-") -> AsyncIterator[bytes]:
        fv = oi.version
        read = self._reader(oi)
        meta = fv.meta_sys.get(SSE_KEY)
        if meta:
            dek = await self._dek(meta, headers, ssec_prefix)  # -> KMS (#16) to unseal
            return sse.decrypt_range(fv.parts, dek, offset, length, read)
        return read(offset, length)

    async def get_object(self, ctx: RequestContext, bucket: str, key: str, version_id: str | None,
                         headers, head: bool = False) -> tuple[int, dict, AsyncIterator[bytes] | None]:
        api = ("HeadObject" if head else "GetObject") if not version_id else "GetObjectVersion"
        await self.authorize(ctx, api, bucket, key)
        await self.bucket_meta.get(bucket)  # arrow #5 (raises NoSuchBucket)
        try:
            oi = await self.storage.get_object_info(bucket, key, version_id)  # arrow #4
        except errors.S3Error as e:
            if e.extra.get("delete_marker"):
                e.extra["headers"] = {"x-amz-delete-marker": "true",
                                      "x-amz-version-id": e.extra.get("version_id", "")}
            raise
        fv = oi.version
        if fv.is_delete_marker:
            raise errors.S3Error("MethodNotAllowed", "The specified method is not allowed against this resource.",
                                 headers={"x-amz-delete-marker": "true", "x-amz-version-id": fv.version_id})
        self._check_conditions(fv, headers)
        h = self.objects.response_headers(fv, oi.is_latest)  # arrow #6
        size = self.objects.plain_size(fv)
        rng = self.objects.parse_range(headers.get("range"), size) if not head else None
        offset, length = rng if rng else (0, size)
        status = 200
        if rng:
            status = 206
            h["content-range"] = f"bytes {offset}-{offset + length - 1}/{size}"
            h["content-length"] = str(length)
        if head:
            if SSE_KEY in fv.meta_sys and fv.meta_sys[SSE_KEY]["algo"] == "SSE-C":
                await self._dek(fv.meta_sys[SSE_KEY], headers)
            if self.events:
                await self.events.send("s3:ObjectAccessed:Head", bucket, key, size, fv.etag, fv.version_id, ctx)
            return 200, h, None
        stream = await self.open_plain(oi, headers, offset, length)
        ctx.bytes_out = length
        if self.events:
            await self.events.send("s3:ObjectAccessed:Get", bucket, key, size, fv.etag, fv.version_id, ctx)
        return status, h, stream

    async def delete_object(self, ctx: RequestContext, bucket: str, key: str,
                            version_id: str | None) -> dict:
        await self.authorize(ctx, "DeleteObjectVersion" if version_id else "DeleteObject", bucket, key)
        bm = await self.bucket_meta.get(bucket)
        if version_id == "null":
            version_id = NULL_VERSION
        res = await self.storage.delete_object(bucket, key, version_id, bm.versioning)  # +#8 inside
        if self.lifecycle:
            self.lifecycle.journal_delete(res.get("deleted"))
        h = {}
        if res.get("delete_marker"):
            h["x-amz-delete-marker"] = "true"
        if res.get("version_id"):
            h["x-amz-version-id"] = res["version_id"]
        if self.events:
            ev = "s3:ObjectRemoved:DeleteMarkerCreated" if res.get("delete_marker") and not version_id \
                else "s3:ObjectRemoved:Delete"
            await self.events.send(ev, bucket, key, 0, "", res.get("version_id") or "", ctx)
        return h

    async def delete_objects(self, ctx: RequestContext, bucket: str, objs) -> list[dict]:
        out = []
        for key, vid in objs:
            try:
                h = await self.delete_object(ctx, bucket, key, vid)
                out.append({"key": key, "version_id": vid or h.get("x-amz-version-id"),
                            "delete_marker": h.get("x-amz-delete-marker") == "true",
                            "delete_marker_version_id": h.get("x-amz-version-id")})
            except errors.S3Error as e:
                out.append({"key": key, "version_id": vid, "error": e.code, "message": e.message})
        return out

    async def copy_object(self, ctx: RequestContext, bucket: str, key: str, src_bucket: str,
                          src_key: str, src_vid: str | None, headers) -> dict:
        check_key(key)
        await self.authorize(ctx, "GetObjectVersion" if src_vid else "GetObject", src_bucket, src_key)
        await self.authorize(ctx, "PutObject", bucket, key)
        bm = await self.bucket_meta.get(bucket)
        src = await self.storage.get_object_info(src_bucket, src_key, src_vid)
        self._check_copy_conditions(src.version, headers)
        directive = headers.get("x-amz-metadata-directive", "COPY").upper()
        if directive == "COPY":
            copied = {k: v for k, v in src.version.meta_user.items() if k != "etag"}
            base = dict(copied)
            for k, v in headers.items():
                if k.startswith("x-amz-server-side-encryption") or k == "x-amz-storage-class":
                    base[k] = v
            meta_headers = base
        else:
            meta_headers = dict(headers)
        if (headers.get("x-amz-tagging-directive", "COPY").upper() == "REPLACE"):
            meta_headers["x-amz-tagging"] = headers.get("x-amz-tagging", "")
        elif "x-amz-tagging" in src.version.meta_user:
            meta_headers["x-amz-tagging"] = src.version.meta_user["x-amz-tagging"]
        same = (src_bucket, src_key) == (bucket, key) and not src_vid
        if same and directive == "COPY" and not any(k.startswith("x-amz-server-side-encryption") for k in headers):
            raise errors.S3Error("InvalidRequest", "This copy request is illegal because it is trying to copy an "
                                 "object to itself without changing the object's metadata, storage class, "
                                 "website redirect location or encryption attributes.")
        size = self.objects.plain_size(src.version)
        plain = await self.open_plain(src, headers, 0, size,
                                      "x-amz-copy-source-server-side-encryption-customer-")
        opts = self.objects.put_opts(bm, _Headers(meta_headers))
        opts.meta_sys.pop("x-vault-replication-status", None)
        reader = HashingReader(plain, size)
        oi, meta = await self._store(bucket, key, bm, reader, size, opts, _Headers({**meta_headers, **{
            k: v for k, v in headers.items() if k.startswith("x-amz-server-side-encryption")}}))
        if self.events:
            await self.events.send("s3:ObjectCreated:Copy", bucket, key, size, oi.version.etag,
                                   oi.version.version_id, ctx)
        return {"etag": oi.version.etag, "last_modified": oi.version.mod_time_ns,
                "version_id": oi.version.version_id, "src_version_id": src.version.version_id,
                "headers": self._sse_headers(meta)}

    def _check_copy_conditions(self, fv, headers) -> None:
        mapped = {}
        for h in ("if-match", "if-none-match", "if-modified-since", "if-unmodified-since"):
            v = headers.get(f"x-amz-copy-source-{h}")
            if v:
                mapped[h] = v
        try:
            self._check_conditions(fv, mapped)
        except errors.S3Error:
            raise errors.S3Error("PreconditionFailed", "copy source precondition failed")

    # ---------------------------------------------------------- tagging
    async def get_object_tagging(self, ctx, bucket, key, vid) -> dict:
        await self.authorize(ctx, "GetObjectTagging", bucket, key)
        oi = await self.storage.get_object_info(bucket, key, vid)
        return self.objects.tags(oi.version)

    async def put_object_tagging(self, ctx, bucket, key, vid, tags: dict | None) -> None:
        await self.authorize(ctx, "PutObjectTagging" if tags is not None else "DeleteObjectTagging", bucket, key)
        import urllib.parse
        enc = urllib.parse.urlencode(list((tags or {}).items()))
        await self.storage.update_version_meta(bucket, key, vid, meta_user={"x-amz-tagging": enc})
        if self.events:
            await self.events.send("s3:ObjectTagging:Put" if tags else "s3:ObjectTagging:Delete",
                                   bucket, key, 0, "", vid or "", ctx)

    # ------------------------------------------------------------ multipart
    async def create_multipart_upload(self, ctx, bucket, key, headers) -> str:
        check_key(key)
        await self.authorize(ctx, "CreateMultipartUpload", bucket, key)
        bm = await self.bucket_meta.get(bucket)
        opts = self.objects.put_opts(bm, headers)
        _, meta = await self._sse_for_put(bm, bucket, key, headers)
        if meta:
            opts.meta_sys[SSE_KEY] = meta
        return await self.storage.new_multipart_upload(bucket, key, opts)

    async def _part(self, bucket, key, upload_id, part_number, plain: AsyncIterator[bytes], size, headers,
                    content_md5=None, sha=None):
        up = await self.storage.get_upload(bucket, key, upload_id)
        reader = HashingReader(plain, size, content_md5, sha)
        opts = PutOpts(etag=reader.etag, actual_size=reader.actual)
        meta = up.meta_sys.get(SSE_KEY)
        if meta:
            dek = await self._dek(meta, headers)
            stream = sse.encrypt_stream(reader, dek, part=part_number)
            opts.size = sse.encrypted_size(size) if size >= 0 else -1
        else:
            stream = reader
            opts.size = size
        part = await self.storage.put_object_part(bucket, key, upload_id, part_number, stream, opts)
        return part, reader

    async def upload_part(self, ctx, bucket, key, upload_id, part_number, body, size, headers) -> dict:
        await self.authorize(ctx, "UploadPart", bucket, key)
        n = mp.check_part_number(part_number)
        mp.check_part_size(size)
        part, reader = await self._part(bucket, key, upload_id, n, body, size, headers,
                                        headers.get("content-md5"), headers.get("x-amz-content-sha256"))
        ctx.bytes_in = reader.count
        return {"etag": f'"{part.etag}"'}

    async def upload_part_copy(self, ctx, bucket, key, upload_id, part_number, src_bucket, src_key,
                               src_vid, headers) -> dict:
        await self.authorize(ctx, "GetObject", src_bucket, src_key)
        await self.authorize(ctx, "UploadPart", bucket, key)
        n = mp.check_part_number(part_number)
        src = await self.storage.get_object_info(src_bucket, src_key, src_vid)
        self._check_copy_conditions(src.version, headers)
        size = self.objects.plain_size(src.version)
        rng = headers.get("x-amz-copy-source-range")
        offset, length = self.objects.parse_range(rng, size) if rng else (0, size)
        plain = await self.open_plain(src, headers, offset, length,
                                      "x-amz-copy-source-server-side-encryption-customer-")
        part, _ = await self._part(bucket, key, upload_id, n, plain, length, headers)
        return {"etag": part.etag, "last_modified": src.version.mod_time_ns}

    async def complete_multipart_upload(self, ctx, bucket, key, upload_id, parts) -> dict:
        await self.authorize(ctx, "CompleteMultipartUpload", bucket, key)
        bm = await self.bucket_meta.get(bucket)
        opts = PutOpts(version_id=self.objects.version_id_for(bm.versioning))
        oi = await self.storage.complete_multipart_upload(bucket, key, upload_id, parts, opts)  # +#8
        if self.events:
            await self.events.send("s3:ObjectCreated:CompleteMultipartUpload", bucket, key,
                                   self.objects.plain_size(oi.version), oi.version.etag,
                                   oi.version.version_id, ctx)
        h = self._sse_headers(oi.version.meta_sys.get(SSE_KEY))
        if oi.version.version_id != NULL_VERSION:
            h["x-amz-version-id"] = oi.version.version_id
        return {"etag": oi.version.etag, "headers": h}

    async def abort_multipart_upload(self, ctx, bucket, key, upload_id) -> None:
        await self.authorize(ctx, "AbortMultipartUpload", bucket, key)
        await self.storage.abort_multipart_upload(bucket, key, upload_id)

    async def list_parts(self, ctx, bucket, key, upload_id):
        await self.authorize(ctx, "ListParts", bucket, key)
        return await self.storage.list_parts(bucket, key, upload_id)

    async def list_multipart_uploads(self, ctx, bucket, prefix=""):
        await self.authorize(ctx, "ListMultipartUploads", bucket)
        await self.bucket_meta.get(bucket)
        return [mp.upload_info(v) for v in await self.storage.list_multipart_uploads(bucket, prefix)]

    # ---------------------------------------------------------------- lists
    async def list_objects(self, ctx, bucket, prefix="", delimiter="", marker="", max_keys=1000):
        await self.authorize(ctx, "ListObjectsV2", bucket, conditions={
            "s3:prefix": prefix, "s3:delimiter": delimiter, "s3:max-keys": str(max_keys)})
        await self.bucket_meta.get(bucket)
        return await self.storage.list_objects(bucket, prefix, delimiter, marker, max_keys)

    async def list_object_versions(self, ctx, bucket, prefix="", delimiter="", key_marker="",
                                   version_marker="", max_keys=1000):
        await self.authorize(ctx, "ListObjectVersions", bucket, conditions={"s3:prefix": prefix})
        await self.bucket_meta.get(bucket)
        return await self.storage.list_object_versions(bucket, prefix, delimiter, key_marker,
                                                       version_marker, max_keys)

    # --------------------------------------------------------------- buckets
    async def list_buckets(self, ctx) -> list[dict]:
        await self.authorize(ctx, "ListBuckets")
        out = []
        for b in await self.storage.list_buckets():
            try:
                bm = await self.bucket_meta.get(b["name"])
                out.append({"name": b["name"], "created": bm.created})
            except errors.S3Error:
                continue
        return out

    async def create_bucket(self, ctx, bucket: str, object_lock: bool = False) -> None:
        check_bucket_name(bucket)
        await self.authorize(ctx, "CreateBucket", bucket)
        await self.storage.make_bucket(bucket)
        await self.bucket_meta.create(bucket, versioning="Enabled" if object_lock else "Unversioned")
        if self.events:
            await self.events.send("s3:BucketCreated", bucket, "", ctx=ctx)

    async def delete_bucket(self, ctx, bucket: str, force: bool = False) -> None:
        await self.authorize(ctx, "DeleteBucket", bucket)
        await self.bucket_meta.get(bucket)
        await self.storage.delete_bucket(bucket, force)
        await self.bucket_meta.delete(bucket)

    async def head_bucket(self, ctx, bucket: str) -> None:
        await self.authorize(ctx, "HeadBucket", bucket)
        await self.bucket_meta.get(bucket)

    async def get_bucket_config(self, ctx, bucket: str, api: str, field: str):
        await self.authorize(ctx, api, bucket)
        bm = await self.bucket_meta.get(bucket)
        return getattr(bm, field), bm

    async def put_bucket_config(self, ctx, bucket: str, api: str, field: str, value) -> None:
        await self.authorize(ctx, api, bucket)
        bm = await self.bucket_meta.get(bucket)
        if value is not None:
            if field == "versioning" and value not in ("Enabled", "Suspended"):
                raise errors.S3Error("MalformedXML", "bad versioning status")
            if field == "policy":
                try:
                    pol.parse_policy(value)
                except (ValueError, json.JSONDecodeError) as e:
                    raise errors.S3Error("MalformedPolicy", str(e), 400)
            if field == "lifecycle_xml":
                parse_lifecycle(value)
            if field == "replication_xml":
                parse_replication(value)
                if bm.versioning != "Enabled":
                    raise errors.S3Error("InvalidRequest", "Versioning must be 'Enabled' on the bucket "
                                         "to apply a replication configuration")
            if field == "notification_xml" and self.events:
                self.events.validate(value)
            if field == "encryption_xml":
                s3_xml.parse_encryption(value.encode())
        if field == "versioning" and value == "Suspended" and bm.replication_xml:
            raise errors.S3Error("InvalidBucketState", "replication requires versioning")
        await self.bucket_meta.update(bucket, field, value)

    # ---------------------------------------------------------- replication
    async def open_for_replication(self, bucket: str, key: str, version_id: str | None):
        """Plaintext stream + headers for a replication worker (no client auth; SSE is
        decrypted here and the target applies its own encryption settings)."""
        oi = await self.storage.get_object_info(bucket, key, version_id)
        meta = oi.version.meta_sys.get(SSE_KEY)
        if meta and meta["algo"] == "SSE-C":
            raise errors.S3Error("InvalidRequest", "SSE-C objects can't be replicated")
        size = self.objects.plain_size(oi.version)
        headers = self.objects.response_headers(oi.version)
        return headers, await self.open_plain(oi, {}, 0, size)


class _Headers(dict):
    """Case-insensitive-ish dict for synthesized headers."""

    def __init__(self, d):
        super().__init__({k.lower(): v for k, v in d.items()})

    def get(self, k, default=None):
        return super().get(k.lower(), default)
