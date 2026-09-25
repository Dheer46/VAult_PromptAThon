"""AWS Signature Version 4 verification: header auth, presigned URLs and
aws-chunked (STREAMING-*) bodies.

Pitfall: S3 does not double-encode the path — the canonical URI is the path
exactly as the client sent it."""
from __future__ import annotations

import hashlib
import hmac
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import AsyncIterator, Callable

from .. import errors

ALGO = "AWS4-HMAC-SHA256"
EMPTY_SHA = hashlib.sha256(b"").hexdigest()
MAX_SKEW = 15 * 60
STREAMING_SIGNED = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
STREAMING_SIGNED_TRAILER = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
STREAMING_UNSIGNED_TRAILER = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signing_key(secret: str, date: str, region: str, service: str = "s3") -> bytes:
    k = _sign(("AWS4" + secret).encode(), date)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="-_.~")


def canonical_query(raw_query: str, exclude: str | None = None) -> str:
    items = []
    for part in raw_query.split("&") if raw_query else []:
        if not part:
            continue
        k, _, v = part.partition("=")
        k, v = urllib.parse.unquote(k), urllib.parse.unquote(v)
        if exclude and k == exclude:
            continue
        items.append((_q(k), _q(v)))
    return "&".join(f"{k}={v}" for k, v in sorted(items))


def canonical_request(method: str, raw_path: str, raw_query: str, headers: dict,
                      signed_headers: list[str], payload_hash: str, exclude_q: str | None = None) -> str:
    ch = "".join(f"{h}:{' '.join(str(headers.get(h, '')).split())}\n" for h in signed_headers)
    return "\n".join([method, raw_path or "/", canonical_query(raw_query, exclude_q), ch,
                      ";".join(signed_headers), payload_hash])


def string_to_sign(amz_date: str, scope: str, creq: str) -> str:
    return "\n".join([ALGO, amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])


def _parse_amz_date(s: str) -> float:
    try:
        return datetime.strptime(s, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        raise errors.S3Error("AccessDenied", "bad X-Amz-Date")


@dataclass
class AuthResult:
    access_key: str
    identity: object
    signature: str
    signing_key: bytes
    scope: str
    amz_date: str
    payload_hash: str
    presigned: bool = False


def parse_authorization(header: str) -> dict:
    if not header.startswith(ALGO + " "):
        raise errors.S3Error("AccessDenied", "unsupported authorization scheme (use SigV4)")
    fields = {}
    for part in header[len(ALGO) + 1:].split(","):
        k, _, v = part.strip().partition("=")
        fields[k] = v
    try:
        ak, date, region, service, term = fields["Credential"].split("/")
    except (KeyError, ValueError):
        raise errors.S3Error("AuthorizationHeaderMalformed", "bad Credential", 400)
    return {"access_key": ak, "date": date, "region": region, "service": service,
            "signed_headers": fields.get("SignedHeaders", "").split(";"),
            "signature": fields.get("Signature", "")}


def verify(method: str, raw_path: str, raw_query: str, headers: dict,
           lookup: Callable[[str], tuple[str, object] | None], now: float | None = None) -> AuthResult:
    """headers: lowercase names. lookup(access_key) -> (secret, identity) or None."""
    now = now or time.time()
    query = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
    if "X-Amz-Signature" in query:  # presigned URL
        q = {k: v[0] for k, v in query.items()}
        if q.get("X-Amz-Algorithm") != ALGO:
            raise errors.S3Error("AccessDenied", "unsupported presign algorithm")
        try:
            ak, date, region, service, _ = q["X-Amz-Credential"].split("/")
        except (KeyError, ValueError):
            raise errors.S3Error("AuthorizationQueryParametersError", "bad X-Amz-Credential", 400)
        amz_date = q.get("X-Amz-Date", "")
        expires = int(q.get("X-Amz-Expires", "0") or 0)
        if expires <= 0 or expires > 604800:
            raise errors.S3Error("AuthorizationQueryParametersError", "X-Amz-Expires must be 1..604800", 400)
        t = _parse_amz_date(amz_date)
        if now > t + expires:
            raise errors.S3Error("AccessDenied", "Request has expired")
        if t - now > MAX_SKEW:
            raise errors.S3Error("RequestTimeTooSkewed", "request time too far in the future")
        signed = q.get("X-Amz-SignedHeaders", "host").split(";")
        found = lookup(ak)
        if not found:
            raise errors.S3Error("InvalidAccessKeyId", "The access key ID you provided does not exist")
        secret, ident = found
        payload = headers.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        creq = canonical_request(method, raw_path, raw_query, headers, signed, payload,
                                 exclude_q="X-Amz-Signature")
        scope = f"{date}/{region}/{service}/aws4_request"
        key = signing_key(secret, date, region, service)
        sig = hmac.new(key, string_to_sign(amz_date, scope, creq).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, q["X-Amz-Signature"]):
            raise errors.S3Error("SignatureDoesNotMatch", "The request signature we calculated does not "
                                 "match the signature you provided.")
        if q.get("X-Amz-Security-Token") and getattr(ident, "session_token", "") != q["X-Amz-Security-Token"]:
            raise errors.S3Error("InvalidToken", "bad security token", 400)
        return AuthResult(ak, ident, sig, key, scope, amz_date, payload, presigned=True)

    auth = headers.get("authorization")
    if not auth:
        raise errors.S3Error("AccessDenied", "missing authorization")
    p = parse_authorization(auth)
    amz_date = headers.get("x-amz-date") or ""
    if not amz_date:
        raise errors.S3Error("AccessDenied", "missing X-Amz-Date")
    if abs(now - _parse_amz_date(amz_date)) > MAX_SKEW:
        raise errors.S3Error("RequestTimeTooSkewed", "The difference between the request time and the "
                             "server's time is too large.")
    found = lookup(p["access_key"])
    if not found:
        raise errors.S3Error("InvalidAccessKeyId", "The access key ID you provided does not exist")
    secret, ident = found
    payload = headers.get("x-amz-content-sha256", EMPTY_SHA)
    creq = canonical_request(method, raw_path, raw_query, headers, p["signed_headers"], payload)
    scope = f"{p['date']}/{p['region']}/{p['service']}/aws4_request"
    key = signing_key(secret, p["date"], p["region"], p["service"])
    sig = hmac.new(key, string_to_sign(amz_date, scope, creq).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, p["signature"]):
        raise errors.S3Error("SignatureDoesNotMatch", "The request signature we calculated does not match "
                             "the signature you provided. Check your key and signing method.")
    tok = headers.get("x-amz-security-token")
    if getattr(ident, "session_token", "") and tok != ident.session_token:
        raise errors.S3Error("InvalidToken", "The provided token is malformed or otherwise invalid.", 400)
    return AuthResult(p["access_key"], ident, sig, key, scope, amz_date, payload)


async def decode_aws_chunked(stream: AsyncIterator[bytes], auth: AuthResult | None,
                             signed: bool) -> AsyncIterator[bytes]:
    """Decode `hex-size[;chunk-signature=sig]\\r\\n<data>\\r\\n ... 0...\\r\\n[trailers]\\r\\n`,
    verifying the chunk signature chain when `signed`."""
    buf = bytearray()
    it = stream.__aiter__()
    prev = auth.signature if auth else ""
    eof = False

    async def fill(n: int) -> bool:
        nonlocal eof
        while len(buf) < n and not eof:
            try:
                buf.extend(await it.__anext__())
            except StopAsyncIteration:
                eof = True
        return len(buf) >= n

    async def readline() -> bytes:
        nonlocal eof
        while True:
            i = buf.find(b"\r\n")
            if i >= 0:
                line = bytes(buf[:i])
                del buf[:i + 2]
                return line
            if eof:
                raise errors.S3Error("IncompleteBody", "truncated aws-chunked body", 400)
            try:
                buf.extend(await it.__anext__())
            except StopAsyncIteration:
                eof = True

    while True:
        header = (await readline()).decode("latin-1")
        size_s, _, ext = header.partition(";")
        try:
            size = int(size_s.strip(), 16)
        except ValueError:
            raise errors.S3Error("IncompleteBody", "bad aws-chunked header", 400)
        if not await fill(size):
            raise errors.S3Error("IncompleteBody", "truncated chunk", 400)
        data = bytes(buf[:size])
        del buf[:size]
        if signed and auth:
            sig = ext.partition("chunk-signature=")[2].strip()
            sts = "\n".join(["AWS4-HMAC-SHA256-PAYLOAD", auth.amz_date, auth.scope, prev, EMPTY_SHA,
                             hashlib.sha256(data).hexdigest()])
            good = hmac.new(auth.signing_key, sts.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(good, sig):
                raise errors.S3Error("SignatureDoesNotMatch", "chunk signature mismatch")
            prev = sig
        if size == 0:
            # trailers (x-amz-checksum-*, x-amz-trailer-signature) until an empty line
            while True:
                if not buf and eof:
                    break
                line = await readline() if (buf or not eof) else b""
                if not line:
                    break
            return
        yield data
        if not await fill(2) or bytes(buf[:2]) != b"\r\n":
            raise errors.S3Error("IncompleteBody", "missing chunk terminator", 400)
        del buf[:2]
