"""Prometheus metrics (exposed at /metrics on every node)."""
from prometheus_client import Counter, Gauge, Histogram

S3_REQUESTS = Counter("vault_s3_requests_total", "S3 requests", ["api", "status"])
S3_DURATION = Histogram("vault_s3_request_duration_seconds", "S3 request latency", ["api"],
                        buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30))
S3_BYTES_RX = Counter("vault_s3_bytes_received_total", "Bytes received", ["api"])
S3_BYTES_TX = Counter("vault_s3_bytes_sent_total", "Bytes sent", ["api"])

DRIVE_ONLINE = Gauge("vault_drive_online", "1 if the drive is online", ["endpoint", "set"])
DRIVE_USED = Gauge("vault_drive_used_bytes", "Used bytes", ["endpoint"])
DRIVE_TOTAL = Gauge("vault_drive_total_bytes", "Total bytes", ["endpoint"])
DRIVE_IO_ERRORS = Counter("vault_drive_io_errors_total", "Drive I/O errors", ["endpoint", "op"])
SET_ONLINE_DRIVES = Gauge("vault_erasure_set_online_drives", "Online drives per set", ["set"])
QUORUM_FAILURES = Counter("vault_quorum_failures_total", "Quorum failures", ["op"])

HEAL_OBJECTS = Counter("vault_heal_objects_total", "Objects healed", ["kind", "result"])
HEAL_BYTES = Counter("vault_heal_bytes_total", "Bytes healed", ["kind"])
HEAL_DRIVE_PROGRESS = Gauge("vault_heal_drive_progress_ratio", "Drive heal progress", ["endpoint"])
MRF_QUEUE = Gauge("vault_mrf_queue_length", "MRF queue length")

SCANNER_CYCLE = Gauge("vault_scanner_cycle", "Scanner cycle number")
SCANNER_OBJECTS = Counter("vault_scanner_objects_scanned_total", "Objects scanned")
BITROT_DETECTED = Counter("vault_bitrot_detected_total", "Bitrot detections", ["endpoint"])

REPL_QUEUED_OBJECTS = Gauge("vault_replication_queued_objects", "Queued replication tasks",
                            ["target", "bucket"])
REPL_QUEUED_BYTES = Gauge("vault_replication_queued_bytes", "Queued replication bytes",
                          ["target", "bucket"])
REPL_FAILED = Counter("vault_replication_failed_total", "Failed replications", ["target", "bucket"])
REPL_COMPLETED = Counter("vault_replication_completed_total", "Completed replications",
                         ["target", "bucket"])
REPL_LATENCY = Histogram("vault_replication_latency_seconds", "Replication latency", ["target"])
REPL_LAG = Gauge("vault_replication_lag_seconds", "Age of the oldest queued task", ["target"])

LIFECYCLE_ACTIONS = Counter("vault_lifecycle_actions_total", "Lifecycle actions", ["action"])

EVENTS_SENT = Counter("vault_events_sent_total", "Events delivered", ["target"])
EVENTS_DROPPED = Counter("vault_events_dropped_total", "Events dropped", ["target"])
EVENTS_QUEUED = Gauge("vault_events_queued", "Events waiting in the queue store", ["target"])

KMS_REQUESTS = Counter("vault_kms_requests_total", "KMS requests", ["op"])
KMS_ERRORS = Counter("vault_kms_errors_total", "KMS errors", ["op"])
KEYSTONE_REQUESTS = Counter("vault_keystone_requests_total", "Keystone requests", ["result"])
LOCK_WAIT = Histogram("vault_lock_wait_seconds", "Time to acquire distributed locks",
                      buckets=(.001, .005, .01, .05, .1, .5, 1, 5, 10))
