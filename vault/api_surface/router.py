"""S3 routing: one catch-all route, dispatched manually on method + path + query
(S3 routing depends on all three, which normal routers express badly). Each
handler parses inputs and calls the Application Facade (arrow #3 "enters application").
"""
from __future__ import annotations

import base64
import urllib.parse
from typing import AsyncIterator

from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from .. import errors
from ..app_facade.context import RequestContext
from ..app_facade.facade import AppFacade
from ..storage_core.filemeta import NULL_VERSION
from . import s3_xml as X
from .s3_xml import E, T


class S3Request:
    def __init__(self, request: Request, ctx: RequestContext, body: AsyncIterator[bytes], size: int):
        self.r = request
        self.ctx = ctx
        self.body = body
        self.size = size
        self.headers = {k.lower(): v for k, v in request.headers.items()}
        self.q = {k: v for k, v in urllib.parse.parse_qsl(request.url.query, keep_blank_values=True)}
        self.method = request.method
        path = urllib.parse.unquote(request.scope.get("raw_path", b"/").decode("latin-1").split("?")[0])
        parts = path.lstrip("/").split("/", 1)
        self.bucket = parts[0] if parts and parts[0] else ""
        self.key = parts[1] if len(parts) > 1 else ""

    async def read_body(self, limit: int = 1024 * 1024) -> bytes:
        out = bytearray()
        async for c in self.body:
            out += c
            if len(out) > limit:
                raise errors.S3Error("EntityTooLarge", "request body too large")
        return bytes(out)


def xml(root, status: int = 200, headers: dict | None = None) -> Response:
    return Response(X.to_bytes(root), status_code=status, media_type="application/xml",
                    headers=headers or {})


def _enc(key: str, encoding: str | None) -> str:
    return urllib.parse.quote(key, safe="/") if encoding == "url" else key


def _copy_source(h: dict) -> tuple[str, str, str | None]:
    src = urllib.parse.unquote(h["x-amz-copy-source"])
    src, _, qs = src.partition("?")
    vid = urllib.parse.parse_qs(qs).get("versionId", [None])[0]
    b, _, k = src.lstrip("/").partition("/")
    if not b or not k:
        raise errors.S3Error("InvalidArgument", "bad x-amz-copy-source")
    return b, k, vid


class S3Router:
    def __init__(self, app: AppFacade, oidc=None, settings=None):
        self.app = app
        self.oidc = oidc
        self.s = settings

    async def dispatch(self, req: S3Request) -> Response:
        m, q, b, k = req.method, req.q, req.bucket, req.key
        ctx = req.ctx
        ctx.bucket, ctx.key = b, k
        if not b:
            if m == "GET":
                return await self.list_buckets(req)
            if m == "POST" and (q.get("Action") or req.headers.get("content-type", "").startswith(
                    "application/x-www-form-urlencoded")):
                return await self.sts(req)
            raise errors.S3Error("MethodNotAllowed", "method not allowed", 405)
        if not k:
            for sub, api_put, api_get, api_del, field in (
                    ("versioning", "PutBucketVersioning", "GetBucketVersioning", None, "versioning"),
                    ("lifecycle", "PutBucketLifecycleConfiguration", "GetBucketLifecycleConfiguration",
                     "DeleteBucketLifecycle", "lifecycle_xml"),
                    ("replication", "PutBucketReplication", "GetBucketReplication",
                     "DeleteBucketReplication", "replication_xml"),
                    ("encryption", "PutBucketEncryption", "GetBucketEncryption",
                     "DeleteBucketEncryption", "encryption_xml"),
                    ("notification", "PutBucketNotificationConfiguration",
                     "GetBucketNotificationConfiguration", None, "notification_xml"),
                    ("policy", "PutBucketPolicy", "GetBucketPolicy", "DeleteBucketPolicy", "policy"),
                    ("tagging", "PutBucketTagging", "GetBucketTagging", "DeleteBucketTagging", "tagging_xml")):
                if sub in q:
                    if m == "PUT":
                        return await self.put_config(req, api_put, field, sub)
                    if m == "GET":
                        return await self.get_config(req, api_get, field, sub)
                    if m == "DELETE" and api_del:
                        return await self.delete_config(req, api_del, field)
            if m == "GET" and "location" in q:
                ctx.api = "GetBucketLocation"
                await self.app.authorize(ctx, ctx.api, b)
                await self.app.bucket_meta.get(b)
                return xml(E("LocationConstraint", text=self.s.region if self.s.region != "us-east-1" else None))
            if m == "GET" and "versions" in q:
                return await self.list_versions(req)
            if m == "GET" and "uploads" in q:
                return await self.list_uploads(req)
            if m == "GET" and q.get("list-type") == "2":
                return await self.list_v2(req)
            if m == "GET" and any(x in q for x in ("acl", "cors", "website", "logging", "object-lock",
                                                     "requestPayment", "accelerate", "ownershipControls")):
                return await self.unsupported_subresource(req)
            if m == "GET":
                return await self.list_v1(req)
            if m == "PUT":
                return await self.create_bucket(req)
            if m == "HEAD":
                ctx.api = "HeadBucket"
                await self.app.head_bucket(ctx, b)
                return Response(status_code=200, headers={"x-amz-bucket-region": self.s.region})
            if m == "DELETE":
                ctx.api = "DeleteBucket"
                await self.app.delete_bucket(ctx, b)
                return Response(status_code=204)
            if m == "POST" and "delete" in q:
                return await self.delete_objects(req)
            raise errors.S3Error("MethodNotAllowed", "method not allowed", 405)
        # object operations
        if "tagging" in q:
            return await self.object_tagging(req)
        if m == "PUT" and "partNumber" in q and "uploadId" in q:
            if "x-amz-copy-source" in req.headers:
                return await self.upload_part_copy(req)
            return await self.upload_part(req)
        if m == "PUT" and "x-amz-copy-source" in req.headers:
            return await self.copy_object(req)
        if m == "PUT":
            return await self.put_object(req)
        if m == "POST" and "uploads" in q:
            return await self.create_upload(req)
        if m == "POST" and "uploadId" in q:
            return await self.complete_upload(req)
        if m == "POST" and "restore" in q:
            ctx.api = "RestoreObject"
            raise errors.S3Error("NotImplemented", "RestoreObject: GET reads transitioned objects directly")
        if m == "GET" and "uploadId" in q:
            return await self.list_parts(req)
        if m == "GET" and "acl" in q:
            return await self.unsupported_subresource(req)
        if m == "GET":
            return await self.get_object(req, head=False)
        if m == "HEAD":
            return await self.get_object(req, head=True)
        if m == "DELETE" and "uploadId" in q:
            ctx.api = "AbortMultipartUpload"
            await self.app.abort_multipart_upload(ctx, b, k, q["uploadId"])
            return Response(status_code=204)
        if m == "DELETE":
            ctx.api = "DeleteObject"
            h = await self.app.delete_object(ctx, b, k, q.get("versionId"))
            return Response(status_code=204, headers=h)
        raise errors.S3Error("NotImplemented", "not implemented", 501)

    # ------------------------------------------------------------- service
    async def list_buckets(self, req: S3Request) -> Response:
        req.ctx.api = "ListBuckets"
        buckets = await self.app.list_buckets(req.ctx)
        ident = req.ctx.identity
        return xml(E("ListAllMyBucketsResult",
                     E("Owner", T("ID", ident.access_key), T("DisplayName", ident.user)),
                     E("Buckets", [E("Bucket", T("Name", b["name"]),
                                     T("CreationDate", X.iso8601(b["created"]))) for b in buckets])))

    async def sts(self, req: S3Request) -> Response:
        form = dict(req.q)
        if req.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            form.update(urllib.parse.parse_qsl((await req.read_body()).decode()))
        action = form.get("Action")
        req.ctx.api = f"STS:{action}"
        if action != "AssumeRoleWithWebIdentity" or not self.oidc:
            raise errors.S3Error("InvalidRequest", f"unsupported STS action {action}")
        res = await self.oidc.assume_role_with_web_identity(form.get("WebIdentityToken", ""),
                                                            int(form.get("DurationSeconds", 3600)))
        c = res["credentials"]
        root = E("AssumeRoleWithWebIdentityResponse",
                 E("AssumeRoleWithWebIdentityResult",
                   T("SubjectFromWebIdentityToken", res["subject"]),
                   T("Audience", str(res["audience"])), T("Provider", res["provider"]),
                   E("Credentials", T("AccessKeyId", c["AccessKeyId"]),
                     T("SecretAccessKey", c["SecretAccessKey"]), T("SessionToken", c["SessionToken"]),
                     T("Expiration", c["Expiration"]))),
                 E("ResponseMetadata", T("RequestId", req.ctx.request_id)),
                 xmlns="https://sts.amazonaws.com/doc/2011-06-15/")
        return xml(root)

    # -------------------------------------------------------------- bucket
    async def create_bucket(self, req: S3Request) -> Response:
        req.ctx.api = "CreateBucket"
        body = await req.read_body()
        if body:
            loc = X.parse(body).findtext("LocationConstraint")
            if loc and loc != self.s.region:
                raise errors.S3Error("InvalidLocationConstraint",
                                     f"this cluster's region is {self.s.region}", 400)
        lock = req.headers.get("x-amz-bucket-object-lock-enabled", "").lower() == "true"
        await self.app.create_bucket(req.ctx, req.bucket, object_lock=lock)
        return Response(status_code=200, headers={"location": f"/{req.bucket}"})

    async def put_config(self, req: S3Request, api: str, field: str, sub: str) -> Response:
        req.ctx.api = api
        body = await req.read_body(20 * 1024 * 1024)
        if field == "versioning":
            value = X.parse_versioning(body)
        elif field == "policy":
            value = body.decode()
        elif field == "tagging_xml":
            X.parse_tagging(body)
            value = body.decode()
        elif field == "notification_xml":
            X.parse(body)
            value = body.decode()
        else:
            X.parse(body)
            value = body.decode()
        await self.app.put_bucket_config(req.ctx, req.bucket, api, field, value)
        return Response(status_code=204 if field == "policy" else 200)

    async def get_config(self, req: S3Request, api: str, field: str, sub: str) -> Response:
        req.ctx.api = api
        value, bm = await self.app.get_bucket_config(req.ctx, req.bucket, api, field)
        if field == "versioning":
            status = None if value == "Unversioned" else value
            return xml(E("VersioningConfiguration", T("Status", status)))
        if field == "notification_xml" and not value:
            return xml(E("NotificationConfiguration"))
        if not value:
            code = {"policy": "NoSuchBucketPolicy", "lifecycle_xml": "NoSuchLifecycleConfiguration",
                    "replication_xml": "ReplicationConfigurationNotFoundError",
                    "encryption_xml": "ServerSideEncryptionConfigurationNotFoundError",
                    "tagging_xml": "NoSuchTagSet"}[field]
            raise errors.S3Error(code, "The configuration does not exist")
        if field == "policy":
            return Response(value, media_type="application/json")
        return Response(value.encode(), media_type="application/xml")

    async def delete_config(self, req: S3Request, api: str, field: str) -> Response:
        req.ctx.api = api
        await self.app.put_bucket_config(req.ctx, req.bucket, api, field, None)
        return Response(status_code=204)

    async def unsupported_subresource(self, req: S3Request) -> Response:
        req.ctx.api = "GetBucketAcl" if "acl" in req.q else "GetBucketSubresource"
        await self.app.authorize(req.ctx, "GetBucketLocation", req.bucket)
        if "acl" in req.q:
            ident = req.ctx.identity
            owner = E("Owner", T("ID", ident.access_key), T("DisplayName", ident.user))
            return xml(E("AccessControlPolicy", owner, E("AccessControlList", E(
                "Grant", E("Grantee", T("ID", ident.access_key), T("DisplayName", ident.user),
                           **{"xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                              "xsi:type": "CanonicalUser"}),
                T("Permission", "FULL_CONTROL")))))
        raise errors.S3Error("NotImplemented", "subresource not implemented", 501)

    # ---------------------------------------------------------------- lists
    def _contents(self, oi, enc, owner=None):
        v = oi.version
        return E("Contents", T("Key", _enc(oi.key, enc)), T("LastModified", X.iso8601(v.mod_time_ns)),
                 T("ETag", f'"{v.etag}"'), T("Size", self.app.objects.plain_size(v)),
                 T("StorageClass", v.meta_user.get("x-amz-storage-class", "STANDARD")), owner)

    async def list_v2(self, req: S3Request) -> Response:
        req.ctx.api = "ListObjectsV2"
        q = req.q
        prefix, delim = q.get("prefix", ""), q.get("delimiter", "")
        max_keys = min(int(q.get("max-keys", 1000) or 1000), 1000)
        token = q.get("continuation-token")
        marker = base64.urlsafe_b64decode(token.encode()).decode() if token else q.get("start-after", "")
        enc = q.get("encoding-type")
        res = await self.app.list_objects(req.ctx, req.bucket, prefix, delim, marker, max_keys)
        owner = None
        if q.get("fetch-owner") == "true":
            owner = E("Owner", T("ID", req.ctx.identity.access_key), T("DisplayName", req.ctx.identity.user))
        nxt = base64.urlsafe_b64encode(res.next_marker.encode()).decode() if res.is_truncated else None
        return xml(E("ListBucketResult", T("Name", req.bucket), T("Prefix", _enc(prefix, enc)),
                     T("Delimiter", _enc(delim, enc) if delim else None), T("MaxKeys", max_keys),
                     T("EncodingType", enc), T("KeyCount", len(res.objects) + len(res.prefixes)),
                     T("IsTruncated", res.is_truncated), T("ContinuationToken", token),
                     T("NextContinuationToken", nxt), T("StartAfter", q.get("start-after")),
                     [self._contents(o, enc, owner) for o in res.objects],
                     [E("CommonPrefixes", T("Prefix", _enc(p, enc))) for p in res.prefixes]))

    async def list_v1(self, req: S3Request) -> Response:
        req.ctx.api = "ListObjects"
        q = req.q
        prefix, delim, marker = q.get("prefix", ""), q.get("delimiter", ""), q.get("marker", "")
        max_keys = min(int(q.get("max-keys", 1000) or 1000), 1000)
        enc = q.get("encoding-type")
        res = await self.app.list_objects(req.ctx, req.bucket, prefix, delim, marker, max_keys)
        owner = E("Owner", T("ID", req.ctx.identity.access_key), T("DisplayName", req.ctx.identity.user))
        return xml(E("ListBucketResult", T("Name", req.bucket), T("Prefix", _enc(prefix, enc)),
                     T("Marker", _enc(marker, enc)), T("Delimiter", _enc(delim, enc) if delim else None),
                     T("MaxKeys", max_keys), T("EncodingType", enc), T("IsTruncated", res.is_truncated),
                     T("NextMarker", _enc(res.next_marker, enc) if res.is_truncated and delim else None),
                     [self._contents(o, enc, owner) for o in res.objects],
                     [E("CommonPrefixes", T("Prefix", _enc(p, enc))) for p in res.prefixes]))

    async def list_versions(self, req: S3Request) -> Response:
        req.ctx.api = "ListObjectVersions"
        q = req.q
        prefix, delim = q.get("prefix", ""), q.get("delimiter", "")
        max_keys = min(int(q.get("max-keys", 1000) or 1000), 1000)
        enc = q.get("encoding-type")
        res = await self.app.list_object_versions(req.ctx, req.bucket, prefix, delim,
                                                  q.get("key-marker", ""), q.get("version-id-marker", ""),
                                                  max_keys)
        owner = E("Owner", T("ID", req.ctx.identity.access_key), T("DisplayName", req.ctx.identity.user))
        items = []
        for oi in res.objects:
            v = oi.version
            vid = "null" if v.version_id == NULL_VERSION else v.version_id
            if v.is_delete_marker:
                items.append(E("DeleteMarker", T("Key", _enc(oi.key, enc)), T("VersionId", vid),
                               T("IsLatest", oi.is_latest), T("LastModified", X.iso8601(v.mod_time_ns)),
                               owner))
            else:
                items.append(E("Version", T("Key", _enc(oi.key, enc)), T("VersionId", vid),
                               T("IsLatest", oi.is_latest), T("LastModified", X.iso8601(v.mod_time_ns)),
                               T("ETag", f'"{v.etag}"'), T("Size", self.app.objects.plain_size(v)),
                               T("StorageClass", v.meta_user.get("x-amz-storage-class", "STANDARD")), owner))
        return xml(E("ListVersionsResult", T("Name", req.bucket), T("Prefix", _enc(prefix, enc)),
                     T("KeyMarker", q.get("key-marker", "")), T("VersionIdMarker", q.get("version-id-marker", "")),
                     T("NextKeyMarker", res.next_marker if res.is_truncated else None),
                     T("NextVersionIdMarker", res.next_version_marker if res.is_truncated else None),
                     T("MaxKeys", max_keys), T("Delimiter", delim or None), T("EncodingType", enc),
                     T("IsTruncated", res.is_truncated), items,
                     [E("CommonPrefixes", T("Prefix", _enc(p, enc))) for p in res.prefixes]))

    async def list_uploads(self, req: S3Request) -> Response:
        req.ctx.api = "ListMultipartUploads"
        prefix = req.q.get("prefix", "")
        ups = await self.app.list_multipart_uploads(req.ctx, req.bucket, prefix)
        return xml(E("ListMultipartUploadsResult", T("Bucket", req.bucket), T("KeyMarker", ""),
                     T("UploadIdMarker", ""), T("Prefix", prefix), T("MaxUploads", 1000),
                     T("IsTruncated", False),
                     [E("Upload", T("Key", u["key"]), T("UploadId", u["upload_id"]),
                        T("StorageClass", u["storage_class"]), T("Initiated", X.iso8601(u["initiated"])))
                      for u in ups]))

    # -------------------------------------------------------------- objects
    async def put_object(self, req: S3Request) -> Response:
        req.ctx.api = "PutObject"
        if req.size < 0 and "x-amz-decoded-content-length" not in req.headers and \
                req.headers.get("transfer-encoding") != "chunked":
            raise errors.S3Error("MissingContentLength", "You must provide the Content-Length HTTP header.")
        h = await self.app.put_object(req.ctx, req.bucket, req.key, req.body, req.size, req.headers)
        return Response(status_code=200, headers=h)

    async def get_object(self, req: S3Request, head: bool) -> Response:
        req.ctx.api = "HeadObject" if head else "GetObject"
        status, h, stream = await self.app.get_object(req.ctx, req.bucket, req.key,
                                                      req.q.get("versionId"), req.headers, head=head)
        for qk, hk in (("response-content-type", "content-type"),
                       ("response-content-disposition", "content-disposition"),
                       ("response-cache-control", "cache-control"),
                       ("response-content-encoding", "content-encoding"),
                       ("response-content-language", "content-language"),
                       ("response-expires", "expires")):
            if qk in req.q:
                h[hk] = req.q[qk]
        if head:
            return Response(status_code=200, headers=h)
        return StreamingResponse(stream, status_code=status, headers=h,
                                 media_type=h.get("content-type", "application/octet-stream"))

    async def copy_object(self, req: S3Request) -> Response:
        req.ctx.api = "CopyObject"
        sb, sk, svid = _copy_source(req.headers)
        res = await self.app.copy_object(req.ctx, req.bucket, req.key, sb, sk, svid, req.headers)
        h = dict(res["headers"])
        if res["version_id"] != NULL_VERSION:
            h["x-amz-version-id"] = res["version_id"]
        if res["src_version_id"] != NULL_VERSION:
            h["x-amz-copy-source-version-id"] = res["src_version_id"]
        return xml(E("CopyObjectResult", T("LastModified", X.iso8601(res["last_modified"])),
                     T("ETag", f'"{res["etag"]}"')), headers=h)

    async def delete_objects(self, req: S3Request) -> Response:
        req.ctx.api = "DeleteObjects"
        objs, quiet = X.parse_delete_objects(await req.read_body(2 * 1024 * 1024))
        results = await self.app.delete_objects(req.ctx, req.bucket, objs)
        items = []
        for r in results:
            if "error" in r:
                items.append(E("Error", T("Key", r["key"]), T("VersionId", r["version_id"]),
                               T("Code", r["error"]), T("Message", r["message"])))
            elif not quiet:
                items.append(E("Deleted", T("Key", r["key"]), T("VersionId", r["version_id"]),
                               T("DeleteMarker", True if r["delete_marker"] else None),
                               T("DeleteMarkerVersionId", r["delete_marker_version_id"]
                                 if r["delete_marker"] else None)))
        return xml(E("DeleteResult", items))

    async def object_tagging(self, req: S3Request) -> Response:
        vid = req.q.get("versionId")
        if req.method == "GET":
            req.ctx.api = "GetObjectTagging"
            tags = await self.app.get_object_tagging(req.ctx, req.bucket, req.key, vid)
            return Response(X.tagging_xml(tags), media_type="application/xml")
        if req.method == "PUT":
            req.ctx.api = "PutObjectTagging"
            tags = X.parse_tagging(await req.read_body())
            await self.app.put_object_tagging(req.ctx, req.bucket, req.key, vid, tags)
            return Response(status_code=200)
        if req.method == "DELETE":
            req.ctx.api = "DeleteObjectTagging"
            await self.app.put_object_tagging(req.ctx, req.bucket, req.key, vid, None)
            return Response(status_code=204)
        raise errors.S3Error("MethodNotAllowed", "method not allowed", 405)

    # ------------------------------------------------------------ multipart
    async def create_upload(self, req: S3Request) -> Response:
        req.ctx.api = "CreateMultipartUpload"
        uid = await self.app.create_multipart_upload(req.ctx, req.bucket, req.key, req.headers)
        return xml(E("InitiateMultipartUploadResult", T("Bucket", req.bucket), T("Key", req.key),
                     T("UploadId", uid)))

    async def upload_part(self, req: S3Request) -> Response:
        req.ctx.api = "UploadPart"
        h = await self.app.upload_part(req.ctx, req.bucket, req.key, req.q["uploadId"],
                                       req.q["partNumber"], req.body, req.size, req.headers)
        return Response(status_code=200, headers=h)

    async def upload_part_copy(self, req: S3Request) -> Response:
        req.ctx.api = "UploadPartCopy"
        sb, sk, svid = _copy_source(req.headers)
        res = await self.app.upload_part_copy(req.ctx, req.bucket, req.key, req.q["uploadId"],
                                              req.q["partNumber"], sb, sk, svid, req.headers)
        return xml(E("CopyPartResult", T("LastModified", X.iso8601(res["last_modified"])),
                     T("ETag", f'"{res["etag"]}"')))

    async def complete_upload(self, req: S3Request) -> Response:
        req.ctx.api = "CompleteMultipartUpload"
        parts = X.parse_complete_multipart(await req.read_body(10 * 1024 * 1024))
        res = await self.app.complete_multipart_upload(req.ctx, req.bucket, req.key, req.q["uploadId"], parts)
        loc = f"{self.s.public_url or ''}/{req.bucket}/{urllib.parse.quote(req.key)}"
        return xml(E("CompleteMultipartUploadResult", T("Location", loc), T("Bucket", req.bucket),
                     T("Key", req.key), T("ETag", f'"{res["etag"]}"')), headers=res["headers"])

    async def list_parts(self, req: S3Request) -> Response:
        req.ctx.api = "ListParts"
        parts = await self.app.list_parts(req.ctx, req.bucket, req.key, req.q["uploadId"])
        marker = int(req.q.get("part-number-marker", 0) or 0)
        max_parts = int(req.q.get("max-parts", 1000) or 1000)
        sel = [p for p in parts if p.number > marker]
        trunc = len(sel) > max_parts
        sel = sel[:max_parts]
        return xml(E("ListPartsResult", T("Bucket", req.bucket), T("Key", req.key),
                     T("UploadId", req.q["uploadId"]), T("PartNumberMarker", marker),
                     T("NextPartNumberMarker", sel[-1].number if sel else 0), T("MaxParts", max_parts),
                     T("IsTruncated", trunc), T("StorageClass", "STANDARD"),
                     [E("Part", T("PartNumber", p.number), T("ETag", f'"{p.etag}"'),
                        T("Size", p.actual_size)) for p in sel]))
