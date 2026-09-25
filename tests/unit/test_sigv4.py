"""SigV4 verification against botocore's own signer."""
import hashlib
import time
import urllib.parse

import pytest
from botocore.auth import S3SigV4Auth, S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from vault import errors
from vault.api_surface import sigv4

CREDS = Credentials("AKID", "secret-key-123")


def lookup(ak):
    return ("secret-key-123", "ident") if ak == "AKID" else None


def signed(method, url, body=b"", headers=None):
    req = AWSRequest(method=method, url=url, data=body, headers=headers or {})
    S3SigV4Auth(CREDS, "s3", "us-east-1").add_auth(req)
    p = urllib.parse.urlsplit(url)
    h = {k.lower(): v for k, v in req.headers.items()}
    h["host"] = p.netloc
    return p.path, p.query, h


@pytest.mark.parametrize("path", ["/bucket/key", "/bucket/with%20space/and%2Bplus", "/b/%C3%BC/x~y"])
def test_header_auth_matches_botocore(path):
    raw_path, q, h = signed("PUT", f"http://localhost:9000{path}?partNumber=1&uploadId=a%2Fb",
                            b"hello", {"content-type": "text/plain"})
    res = sigv4.verify("PUT", raw_path, q, h, lookup)
    assert res.access_key == "AKID" and res.identity == "ident"


def test_wrong_secret_rejected():
    raw_path, q, h = signed("GET", "http://localhost:9000/b/k")
    with pytest.raises(errors.S3Error) as e:
        sigv4.verify("GET", raw_path, q, h, lambda ak: ("other", "i"))
    assert e.value.code == "SignatureDoesNotMatch"


def test_clock_skew_rejected():
    raw_path, q, h = signed("GET", "http://localhost:9000/b/k")
    with pytest.raises(errors.S3Error) as e:
        sigv4.verify("GET", raw_path, q, h, lookup, now=time.time() + 3600)
    assert e.value.code == "RequestTimeTooSkewed"


def test_presigned_url():
    req = AWSRequest(method="GET", url="http://localhost:9000/b/some%20key")
    S3SigV4QueryAuth(CREDS, "s3", "us-east-1", expires=60).add_auth(req)
    p = urllib.parse.urlsplit(req.url)
    res = sigv4.verify("GET", p.path, p.query, {"host": p.netloc}, lookup)
    assert res.presigned
    with pytest.raises(errors.S3Error) as e:
        sigv4.verify("GET", p.path, p.query, {"host": p.netloc}, lookup, now=time.time() + 120)
    assert e.value.message == "Request has expired"


async def test_aws_chunked_signed_decoding():
    """Build a STREAMING-AWS4-HMAC-SHA256-PAYLOAD body by hand and decode it."""
    import hmac
    key = sigv4.signing_key("secret-key-123", "20260926", "us-east-1")
    auth = sigv4.AuthResult("AKID", "i", "seedsig", key, "20260926/us-east-1/s3/aws4_request",
                            "20260926T000000Z", sigv4.STREAMING_SIGNED)
    chunks = [b"a" * 70000, b"b" * 12, b""]
    prev = "seedsig"
    body = b""
    for c in chunks:
        sts = "\n".join(["AWS4-HMAC-SHA256-PAYLOAD", auth.amz_date, auth.scope, prev, sigv4.EMPTY_SHA,
                         hashlib.sha256(c).hexdigest()])
        sig = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()
        body += f"{len(c):x};chunk-signature={sig}\r\n".encode() + c + b"\r\n"
        prev = sig

    async def stream():
        for i in range(0, len(body), 1000):
            yield body[i:i + 1000]
    out = b"".join([x async for x in sigv4.decode_aws_chunked(stream(), auth, signed=True)])
    assert out == b"a" * 70000 + b"b" * 12

    tampered = body.replace(b"b" * 12, b"c" * 12)

    async def stream2():
        yield tampered
    with pytest.raises(errors.S3Error):
        _ = [x async for x in sigv4.decode_aws_chunked(stream2(), auth, signed=True)]


async def test_unsigned_trailer_decoding():
    body = b"5\r\nhello\r\n3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n"

    async def stream():
        yield body
    out = b"".join([x async for x in sigv4.decode_aws_chunked(stream(), None, signed=False)])
    assert out == b"helloabc"
