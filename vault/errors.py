"""Typed errors. Storage errors are counted by the erasure layer to decide quorum;
S3Error carries the S3 error code and HTTP status for the API Surface."""
from __future__ import annotations


class StorageError(Exception):
    """Base class for drive-level errors."""


class DiskNotFound(StorageError):
    pass


class FileNotFound(StorageError):
    pass


class FileVersionNotFound(StorageError):
    pass


class FileCorrupt(StorageError):
    pass


class VolumeNotFound(StorageError):
    pass


class VolumeExists(StorageError):
    pass


class VolumeNotEmpty(StorageError):
    pass


class DiskFull(StorageError):
    pass


class UnformattedDisk(StorageError):
    pass


class LockLost(Exception):
    """Raised when a distributed lock loses its majority mid-operation."""


class S3Error(Exception):
    STATUS = {
        "NoSuchBucket": 404, "NoSuchKey": 404, "NoSuchVersion": 404, "NoSuchUpload": 404,
        "NoSuchBucketPolicy": 404, "NoSuchLifecycleConfiguration": 404,
        "ReplicationConfigurationNotFoundError": 404,
        "ServerSideEncryptionConfigurationNotFoundError": 404, "NoSuchTagSet": 404,
        "BucketAlreadyOwnedByYou": 409, "BucketAlreadyExists": 409, "BucketNotEmpty": 409,
        "InvalidBucketState": 409,
        "AccessDenied": 403, "SignatureDoesNotMatch": 403, "InvalidAccessKeyId": 403,
        "RequestTimeTooSkewed": 403, "ExpiredToken": 400,
        "InvalidRange": 416, "BadDigest": 400, "EntityTooSmall": 400, "EntityTooLarge": 400,
        "InvalidPart": 400, "InvalidPartOrder": 400, "InvalidArgument": 400,
        "InvalidRequest": 400, "MalformedXML": 400, "InvalidBucketName": 400,
        "XAmzContentSHA256Mismatch": 400, "InvalidDigest": 400, "KeyTooLongError": 400,
        "InvalidStorageClass": 400, "InvalidEncryptionAlgorithmError": 400,
        "MissingContentLength": 411, "PreconditionFailed": 412, "NotModified": 304,
        "MethodNotAllowed": 405, "NotImplemented": 501,
        "SlowDown": 503, "ServiceUnavailable": 503, "KMSNotConfigured": 501,
        "KMSUnavailable": 503, "InternalError": 500,
    }

    def __init__(self, code: str, message: str = "", status: int | None = None, **extra):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message or code
        self.status = status or self.STATUS.get(code, 400)
        self.extra = extra


class InsufficientReadQuorum(S3Error):
    def __init__(self, message: str = "insufficient read quorum"):
        super().__init__("SlowDown", message, 503)


class InsufficientWriteQuorum(S3Error):
    def __init__(self, message: str = "insufficient write quorum"):
        super().__init__("SlowDown", message, 503)
