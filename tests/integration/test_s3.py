"""S3 compatibility through boto3 against a live node (arrows #1, #2, #3, #4...)."""
import base64
import hashlib
import json
import os
import time
import uuid

import boto3
import httpx
import pytest
from botocore.exceptions import ClientError

from tests.conftest import ROOT_PASS, ROOT_USER, make_s3


def rand(n):
    return os.urandom(n)


def bname():
    return f"b-{uuid.uuid4().hex[:10]}"


def code(e: ClientError) -> str:
    return e.response["Error"]["Code"]


def test_bucket_lifecycle_basic(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    assert b in [x["Name"] for x in s3.list_buckets()["Buckets"]]
    s3.head_bucket(Bucket=b)
    with pytest.raises(ClientError) as e:
        s3.create_bucket(Bucket=b)
    assert code(e.value) == "BucketAlreadyOwnedByYou"
    s3.put_object(Bucket=b, Key="x", Body=b"1")
    with pytest.raises(ClientError) as e:
        s3.delete_bucket(Bucket=b)
    assert code(e.value) == "BucketNotEmpty"
    s3.delete_object(Bucket=b, Key="x")
    s3.delete_bucket(Bucket=b)
    with pytest.raises(ClientError) as e:
        s3.head_bucket(Bucket=b)
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404


@pytest.mark.parametrize("size", [0, 1, 1000, 128 * 1024, (1 << 20) - 1, 1 << 20, 3 * (1 << 20) + 7])
def test_put_get_sizes(s3, size):
    b = bname()
    s3.create_bucket(Bucket=b)
    data = rand(size)
    r = s3.put_object(Bucket=b, Key="obj", Body=data, ContentType="text/x-test", Metadata={"a": "1"})
    assert r["ETag"] == f'"{hashlib.md5(data).hexdigest()}"'
    g = s3.get_object(Bucket=b, Key="obj")
    assert g["Body"].read() == data
    assert g["ContentType"] == "text/x-test"
    assert g["Metadata"] == {"a": "1"}
    h = s3.head_object(Bucket=b, Key="obj")
    assert h["ContentLength"] == size


def test_range_get(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    data = rand(2 * (1 << 20) + 100)
    s3.put_object(Bucket=b, Key="r", Body=data)
    for a, z in [(0, 0), (5, 99), ((1 << 20) - 10, (1 << 20) + 10), (len(data) - 50, len(data) - 1)]:
        g = s3.get_object(Bucket=b, Key="r", Range=f"bytes={a}-{z}")
        assert g["Body"].read() == data[a:z + 1]
        assert g["ResponseMetadata"]["HTTPStatusCode"] == 206
    g = s3.get_object(Bucket=b, Key="r", Range="bytes=-10")
    assert g["Body"].read() == data[-10:]
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=b, Key="r", Range=f"bytes={len(data) + 5}-")
    assert code(e.value) == "InvalidRange"


def test_missing_key(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=b, Key="nope")
    assert code(e.value) == "NoSuchKey"
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket="no-such-bucket-xyz", Key="nope")
    assert code(e.value) == "NoSuchBucket"


def test_list_prefix_delimiter_pagination(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    keys = [f"dir{i % 3}/file{i:03d}" for i in range(25)] + ["top1", "top2", "sp ace+plus/ü"]
    for k in keys:
        s3.put_object(Bucket=b, Key=k, Body=b"x")
    got = []
    token = None
    while True:
        kw = {"Bucket": b, "MaxKeys": 7}
        if token:
            kw["ContinuationToken"] = token
        r = s3.list_objects_v2(**kw)
        got += [o["Key"] for o in r.get("Contents", [])]
        if not r["IsTruncated"]:
            break
        token = r["NextContinuationToken"]
    assert got == sorted(keys)
    r = s3.list_objects_v2(Bucket=b, Delimiter="/")
    assert [p["Prefix"] for p in r["CommonPrefixes"]] == ["dir0/", "dir1/", "dir2/", "sp ace+plus/"]
    assert [o["Key"] for o in r["Contents"]] == ["top1", "top2"]
    r = s3.list_objects_v2(Bucket=b, Prefix="dir1/")
    assert len(r["Contents"]) == 8
    r = s3.list_objects(Bucket=b, Prefix="dir2/", MaxKeys=3)
    assert len(r["Contents"]) == 3 and r["IsTruncated"]
    paginator = s3.get_paginator("list_objects_v2")
    total = sum(len(p.get("Contents", [])) for p in paginator.paginate(Bucket=b, PaginationConfig={"PageSize": 4}))
    assert total == len(keys)


def test_multipart_upload(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    parts_data = [rand(5 * 1024 * 1024), rand(5 * 1024 * 1024 + 3), rand(1234)]
    mpu = s3.create_multipart_upload(Bucket=b, Key="big", ContentType="application/x-big")
    uid = mpu["UploadId"]
    ups = s3.list_multipart_uploads(Bucket=b)
    assert uid in [u["UploadId"] for u in ups.get("Uploads", [])]
    parts = []
    for i, d in enumerate(parts_data, 1):
        r = s3.upload_part(Bucket=b, Key="big", UploadId=uid, PartNumber=i, Body=d)
        parts.append({"PartNumber": i, "ETag": r["ETag"]})
    lp = s3.list_parts(Bucket=b, Key="big", UploadId=uid)
    assert [p["PartNumber"] for p in lp["Parts"]] == [1, 2, 3]
    r = s3.complete_multipart_upload(Bucket=b, Key="big", UploadId=uid, MultipartUpload={"Parts": parts})
    md5s = b"".join(hashlib.md5(d).digest() for d in parts_data)
    assert r["ETag"] == f'"{hashlib.md5(md5s).hexdigest()}-3"'
    full = b"".join(parts_data)
    g = s3.get_object(Bucket=b, Key="big")
    assert g["Body"].read() == full
    assert g["ContentType"] == "application/x-big"
    a, z = 5 * 1024 * 1024 - 5, 5 * 1024 * 1024 + 5
    assert s3.get_object(Bucket=b, Key="big", Range=f"bytes={a}-{z}")["Body"].read() == full[a:z + 1]
    assert s3.list_multipart_uploads(Bucket=b).get("Uploads", []) == []


def test_multipart_too_small_and_abort(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    uid = s3.create_multipart_upload(Bucket=b, Key="k")["UploadId"]
    e1 = s3.upload_part(Bucket=b, Key="k", UploadId=uid, PartNumber=1, Body=b"a" * 100)["ETag"]
    e2 = s3.upload_part(Bucket=b, Key="k", UploadId=uid, PartNumber=2, Body=b"b" * 100)["ETag"]
    with pytest.raises(ClientError) as e:
        s3.complete_multipart_upload(Bucket=b, Key="k", UploadId=uid, MultipartUpload={
            "Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]})
    assert code(e.value) == "EntityTooSmall"
    s3.abort_multipart_upload(Bucket=b, Key="k", UploadId=uid)
    with pytest.raises(ClientError) as e:
        s3.list_parts(Bucket=b, Key="k", UploadId=uid)
    assert code(e.value) == "NoSuchUpload"


def test_managed_transfer_large(s3, tmp_path):
    """boto3 switches to multipart automatically above its threshold."""
    b = bname()
    s3.create_bucket(Bucket=b)
    data = rand(12 * 1024 * 1024 + 11)
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    from boto3.s3.transfer import TransferConfig
    cfg = TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024)
    s3.upload_file(str(p), b, "managed.bin", Config=cfg)
    out = tmp_path / "o.bin"
    s3.download_file(b, "managed.bin", str(out), Config=cfg)
    assert out.read_bytes() == data


def test_copy_object(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    data = rand(300_000)
    s3.put_object(Bucket=b, Key="src", Body=data, Metadata={"m": "1"})
    s3.copy_object(Bucket=b, Key="dst", CopySource={"Bucket": b, "Key": "src"})
    g = s3.get_object(Bucket=b, Key="dst")
    assert g["Body"].read() == data and g["Metadata"] == {"m": "1"}
    s3.copy_object(Bucket=b, Key="dst2", CopySource={"Bucket": b, "Key": "src"},
                   MetadataDirective="REPLACE", Metadata={"n": "2"}, ContentType="a/b")
    g = s3.get_object(Bucket=b, Key="dst2")
    assert g["Metadata"] == {"n": "2"} and g["ContentType"] == "a/b"
    with pytest.raises(ClientError) as e:
        s3.copy_object(Bucket=b, Key="src", CopySource={"Bucket": b, "Key": "src"})
    assert code(e.value) == "InvalidRequest"


def test_versioning(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    assert "Status" not in s3.get_bucket_versioning(Bucket=b)
    s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket=b)["Status"] == "Enabled"
    v1 = s3.put_object(Bucket=b, Key="k", Body=b"one")["VersionId"]
    v2 = s3.put_object(Bucket=b, Key="k", Body=b"two")["VersionId"]
    assert v1 != v2
    assert s3.get_object(Bucket=b, Key="k")["Body"].read() == b"two"
    assert s3.get_object(Bucket=b, Key="k", VersionId=v1)["Body"].read() == b"one"
    d = s3.delete_object(Bucket=b, Key="k")
    assert d["DeleteMarker"] is True
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=b, Key="k")
    assert code(e.value) == "NoSuchKey"
    vs = s3.list_object_versions(Bucket=b)
    assert len(vs["Versions"]) == 2 and len(vs["DeleteMarkers"]) == 1
    assert vs["DeleteMarkers"][0]["IsLatest"]
    s3.delete_object(Bucket=b, Key="k", VersionId=d["VersionId"])  # remove the marker
    assert s3.get_object(Bucket=b, Key="k")["Body"].read() == b"two"
    s3.delete_object(Bucket=b, Key="k", VersionId=v2)
    assert s3.get_object(Bucket=b, Key="k")["Body"].read() == b"one"


def test_delete_objects(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    for i in range(5):
        s3.put_object(Bucket=b, Key=f"k{i}", Body=b"x")
    r = s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": f"k{i}"} for i in range(5)]})
    assert len(r["Deleted"]) == 5
    assert s3.list_objects_v2(Bucket=b)["KeyCount"] == 0


def test_presigned_url(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="p", Body=b"presigned!")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": b, "Key": "p"}, ExpiresIn=60)
    assert httpx.get(url).content == b"presigned!"
    put = s3.generate_presigned_url("put_object", Params={"Bucket": b, "Key": "up"}, ExpiresIn=60)
    assert httpx.put(put, content=b"via-url").status_code == 200
    assert s3.get_object(Bucket=b, Key="up")["Body"].read() == b"via-url"
    bad = url.replace("X-Amz-Signature=", "X-Amz-Signature=0")
    assert httpx.get(bad).status_code == 403


def test_bad_signature(server):
    c = make_s3(server.endpoint, ROOT_USER, "wrong-secret")
    with pytest.raises(ClientError) as e:
        c.list_buckets()
    assert code(e.value) == "SignatureDoesNotMatch"
    c = make_s3(server.endpoint, "nobody", "whatever-secret")
    with pytest.raises(ClientError) as e:
        c.list_buckets()
    assert code(e.value) == "InvalidAccessKeyId"


def test_content_md5_mismatch(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=b, Key="k", Body=b"abc",
                      ContentMD5=base64.b64encode(hashlib.md5(b"xyz").digest()).decode())
    assert code(e.value) == "BadDigest"
    with pytest.raises(ClientError):
        s3.head_object(Bucket=b, Key="k")


def test_sse_s3_and_kms(s3, server):
    b = bname()
    s3.create_bucket(Bucket=b)
    data = rand(200_000)
    r = s3.put_object(Bucket=b, Key="enc", Body=data, ServerSideEncryption="AES256")
    assert r["ServerSideEncryption"] == "AES256"
    g = s3.get_object(Bucket=b, Key="enc")
    assert g["Body"].read() == data and g["ServerSideEncryption"] == "AES256"
    assert s3.get_object(Bucket=b, Key="enc", Range="bytes=70000-140000")["Body"].read() == data[70000:140001]
    s3.put_object(Bucket=b, Key="kms", Body=data, ServerSideEncryption="aws:kms", SSEKMSKeyId="my-key")
    h = s3.head_object(Bucket=b, Key="kms")
    assert h["SSEKMSKeyId"] == "my-key"
    assert s3.get_object(Bucket=b, Key="kms")["Body"].read() == data
    # data at rest is not plaintext
    needle = data[1000:1032]
    for root, _, files in os.walk(server.tmp):
        for f in files:
            if f.startswith("part.") or f == "xl.meta":
                with open(os.path.join(root, f), "rb") as fh:
                    assert needle not in fh.read()


def test_bucket_default_encryption_and_multipart(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    s3.put_bucket_encryption(Bucket=b, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    data = rand(5 * 1024 * 1024 + 99) + rand(70_000)
    uid = s3.create_multipart_upload(Bucket=b, Key="m")["UploadId"]
    e1 = s3.upload_part(Bucket=b, Key="m", UploadId=uid, PartNumber=1, Body=data[:5 * 1024 * 1024 + 99])["ETag"]
    e2 = s3.upload_part(Bucket=b, Key="m", UploadId=uid, PartNumber=2, Body=data[5 * 1024 * 1024 + 99:])["ETag"]
    s3.complete_multipart_upload(Bucket=b, Key="m", UploadId=uid, MultipartUpload={
        "Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]})
    g = s3.get_object(Bucket=b, Key="m")
    assert g["ServerSideEncryption"] == "AES256" and g["Body"].read() == data
    a = 5 * 1024 * 1024 - 1000
    assert s3.get_object(Bucket=b, Key="m", Range=f"bytes={a}-{a + 5000}")["Body"].read() == data[a:a + 5001]


def test_sse_c(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    key = os.urandom(32)
    data = rand(100_000)
    s3.put_object(Bucket=b, Key="c", Body=data, SSECustomerAlgorithm="AES256", SSECustomerKey=key)
    g = s3.get_object(Bucket=b, Key="c", SSECustomerAlgorithm="AES256", SSECustomerKey=key)
    assert g["Body"].read() == data
    with pytest.raises(ClientError):
        s3.get_object(Bucket=b, Key="c")
    with pytest.raises(ClientError):
        s3.get_object(Bucket=b, Key="c", SSECustomerAlgorithm="AES256", SSECustomerKey=os.urandom(32))


def test_object_tagging(s3):
    b = bname()
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="t", Body=b"x", Tagging="a=1&b=2")
    assert {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=b, Key="t")["TagSet"]} == {"a": "1", "b": "2"}
    s3.put_object_tagging(Bucket=b, Key="t", Tagging={"TagSet": [{"Key": "z", "Value": "9"}]})
    assert s3.get_object_tagging(Bucket=b, Key="t")["TagSet"] == [{"Key": "z", "Value": "9"}]
    s3.delete_object_tagging(Bucket=b, Key="t")
    assert s3.get_object_tagging(Bucket=b, Key="t")["TagSet"] == []


def test_bucket_policy_anonymous_read(s3, server):
    b = bname()
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="public.txt", Body=b"hello world")
    assert httpx.get(f"{server.endpoint}/{b}/public.txt").status_code == 403
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"],
        "Resource": [f"arn:aws:s3:::{b}/*"]}]}
    s3.put_bucket_policy(Bucket=b, Policy=json.dumps(policy))
    r = httpx.get(f"{server.endpoint}/{b}/public.txt")
    assert r.status_code == 200 and r.content == b"hello world"
    assert httpx.put(f"{server.endpoint}/{b}/x", content=b"no").status_code == 403
    assert json.loads(s3.get_bucket_policy(Bucket=b)["Policy"]) == policy
    s3.delete_bucket_policy(Bucket=b)
    assert httpx.get(f"{server.endpoint}/{b}/public.txt").status_code == 403


def test_iam_readonly_user_via_admin_api(s3, server):
    from vault.admin.vaultctl import Client
    admin = Client(server.endpoint, ROOT_USER, ROOT_PASS)
    admin.call("PUT", "users/alice", {"secret_key": "alice-secret-1", "policies": ["readonly"]})
    assert "alice" in [u["access_key"] for u in admin.call("GET", "users")]
    b = bname()
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="k", Body=b"data")
    alice = make_s3(server.endpoint, "alice", "alice-secret-1")
    assert alice.get_object(Bucket=b, Key="k")["Body"].read() == b"data"
    with pytest.raises(ClientError) as e:
        alice.put_object(Bucket=b, Key="k2", Body=b"no")
    assert code(e.value) == "AccessDenied"
    with pytest.raises(SystemExit):  # non-admins can't use the admin API
        Client(server.endpoint, "alice", "alice-secret-1").call("GET", "users")
    admin.call("PUT", "policies/put-only-uploads", {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{b}/uploads/*"]}]})
    admin.call("POST", "attach", {"policy": "put-only-uploads", "user": "alice"})
    alice.put_object(Bucket=b, Key="uploads/ok", Body=b"yes")
    with pytest.raises(ClientError):
        alice.put_object(Bucket=b, Key="other/no", Body=b"no")


def test_notifications_to_file_target(s3, server, tmp_path):
    from vault.admin.vaultctl import Client
    admin = Client(server.endpoint, ROOT_USER, ROOT_PASS)
    path = str(tmp_path / "events.jsonl")
    arn = admin.call("PUT", "targets/file/evtest", {"role": "events", "path": path})["arn"]
    b = bname()
    s3.create_bucket(Bucket=b)
    s3.put_bucket_notification_configuration(Bucket=b, NotificationConfiguration={
        "QueueConfigurations": [{"Id": "n1", "QueueArn": arn, "Events": ["s3:ObjectCreated:*"],
                                 "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "img/"}]}}}]})
    s3.put_object(Bucket=b, Key="img/cat.jpg", Body=b"meow")
    s3.put_object(Bucket=b, Key="doc/x.txt", Body=b"skip")
    deadline = time.time() + 10
    while time.time() < deadline and not os.path.exists(path):
        time.sleep(0.2)
    time.sleep(0.5)
    lines = [json.loads(line) for line in open(path)]
    assert len(lines) == 1
    rec = lines[0]["Records"][0]
    assert rec["eventName"] == "s3:ObjectCreated:Put"
    assert rec["s3"]["bucket"]["name"] == b and rec["s3"]["object"]["key"] == "img/cat.jpg"
    with pytest.raises(ClientError):
        s3.put_bucket_notification_configuration(Bucket=b, NotificationConfiguration={
            "QueueConfigurations": [{"QueueArn": "arn:vault:sqs::nope:webhook", "Events": ["s3:ObjectCreated:*"]}]})


def test_health_and_metrics(server):
    assert httpx.get(f"{server.endpoint}/vault/health/live").status_code == 200
    assert httpx.get(f"{server.endpoint}/vault/health/ready").status_code == 200
    assert httpx.get(f"{server.endpoint}/vault/health/cluster").status_code == 200
    m = httpx.get(f"{server.endpoint}/metrics").text
    assert "vault_s3_requests_total" in m and "vault_erasure_set_online_drives" in m


def test_admin_info(server):
    from vault.admin.vaultctl import Client
    info = Client(server.endpoint, ROOT_USER, ROOT_PASS).call("GET", "info")
    assert info["storage"]["sets"][0]["online"] == 8
