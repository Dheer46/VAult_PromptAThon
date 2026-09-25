"""Multipart upload helpers used by the Application Facade (the storage side lives
in ErasureSet: new_multipart_upload / put_object_part / complete / abort)."""
from __future__ import annotations

from .. import errors

MAX_PARTS = 10_000
MAX_PART_SIZE = 5 * 1024 ** 3


def check_part_number(n: str | int) -> int:
    try:
        n = int(n)
    except (TypeError, ValueError):
        raise errors.S3Error("InvalidArgument", "partNumber must be an integer")
    if not 1 <= n <= MAX_PARTS:
        raise errors.S3Error("InvalidArgument", f"partNumber must be 1..{MAX_PARTS}")
    return n


def check_part_size(size: int) -> None:
    if size > MAX_PART_SIZE:
        raise errors.S3Error("EntityTooLarge", "part larger than 5 GiB")


def upload_info(fv) -> dict:
    return {"upload_id": fv.version_id, "key": fv.meta_sys.get("key", ""),
            "initiated": fv.mod_time_ns,
            "storage_class": fv.meta_user.get("x-amz-storage-class", "STANDARD")}
