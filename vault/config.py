"""Configuration: environment variables (VAULT_*), optionally overlaid by a YAML file.

Brace ranges are expanded like MinIO: "http://node{1...4}:9000" -> 4 URLs.
"""
from __future__ import annotations

import itertools
import os
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml

_RANGE = re.compile(r"\{(\d+)\.\.\.(\d+)\}")


def expand(pattern: str) -> list[str]:
    parts = _RANGE.split(pattern)
    if len(parts) == 1:
        return [pattern]
    literals = parts[0::3]
    ranges = [range(int(a), int(b) + 1) for a, b in zip(parts[1::3], parts[2::3])]
    out = []
    for combo in itertools.product(*ranges):
        s = literals[0]
        for n, lit in zip(combo, literals[1:]):
            s += str(n) + lit
        out.append(s)
    return out


def _expand_list(value: str) -> list[str]:
    out: list[str] = []
    for item in re.split(r"[\s,]+", value.strip()):
        if item:
            out.extend(expand(item))
    return out


def _env(name: str, default=None):
    return os.environ.get(name, default)


@dataclass
class Settings:
    node_name: str = ""
    nodes: list[str] = field(default_factory=list)  # S3 URLs of every node, incl. this one
    drives: list[str] = field(default_factory=list)  # local drive paths (same on every node)
    set_size: int = 0  # 0 = auto
    default_parity: int = 3
    rrs_parity: int = 2
    s3_port: int = 9000
    grpc_port: int = 9100
    region: str = "us-east-1"
    root_user: str = "vaultadmin"
    root_password: str = "vaultadmin-secret"
    cluster_secret: str = "change-me-cluster-secret"
    kms_addr: str = ""
    kms_token: str = ""
    kms_default_key: str = "vault-default-key"
    keystone_url: str = ""
    keystone_service_user: str = ""
    keystone_service_password: str = ""
    keystone_service_project: str = "service"
    keystone_domain: str = "Default"
    oidc_jwks_url: str = ""
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_claim: str = "policy"
    queue_dir: str = "/var/lib/vault/queues"
    audit_targets: list[dict] = field(default_factory=list)
    event_targets: list[dict] = field(default_factory=list)
    lifecycle_day_seconds: int = 86400
    scanner_speed: float = 0.1  # fraction of disk time the scanner may use
    scanner_cycle_pause: float = 60.0
    scanner_deep_every: int = 16
    scanner_heal_every: int = 4
    replication_workers: int = 8
    multipart_expiry_hours: int = 24
    public_url: str = ""

    @property
    def distributed(self) -> bool:
        return len(self.nodes) > 1

    def node_host(self, url: str) -> str:
        return urlparse(url).hostname or url

    @property
    def this_node(self) -> str:
        return self.node_name

    def grpc_addr(self, node_url: str) -> str:
        return f"{self.node_host(node_url)}:{self.grpc_port}"

    def endpoints(self) -> list[tuple[str, str, str]]:
        """Every drive in round-robin order across nodes: (node_host, path, endpoint)."""
        hosts = [self.node_host(u) for u in self.nodes] if self.nodes else [self.node_name]
        out = []
        for d in self.drives:
            for h in hosts:
                out.append((h, d, f"{h}:{d}"))
        return out


def load_settings() -> Settings:
    s = Settings()
    s.node_name = _env("VAULT_NODE_NAME") or socket.gethostname()
    if _env("VAULT_NODES"):
        s.nodes = _expand_list(_env("VAULT_NODES"))
    s.drives = _expand_list(_env("VAULT_DRIVES", "./data/disk{1...8}"))
    ints = {"VAULT_SET_SIZE": "set_size", "VAULT_DEFAULT_PARITY": "default_parity",
            "VAULT_RRS_PARITY": "rrs_parity", "VAULT_S3_PORT": "s3_port",
            "VAULT_GRPC_PORT": "grpc_port", "VAULT_LIFECYCLE_DAY_SECONDS": "lifecycle_day_seconds",
            "VAULT_SCANNER_DEEP_EVERY": "scanner_deep_every",
            "VAULT_SCANNER_HEAL_EVERY": "scanner_heal_every",
            "VAULT_REPLICATION_WORKERS": "replication_workers",
            "VAULT_MULTIPART_EXPIRY_HOURS": "multipart_expiry_hours"}
    for env, attr in ints.items():
        if _env(env):
            setattr(s, attr, int(_env(env)))
    floats = {"VAULT_SCANNER_SPEED": "scanner_speed", "VAULT_SCANNER_CYCLE_PAUSE": "scanner_cycle_pause"}
    for env, attr in floats.items():
        if _env(env):
            setattr(s, attr, float(_env(env)))
    strs = {"VAULT_REGION": "region", "VAULT_ROOT_USER": "root_user",
            "VAULT_ROOT_PASSWORD": "root_password", "VAULT_CLUSTER_SECRET": "cluster_secret",
            "VAULT_KMS_ADDR": "kms_addr", "VAULT_KMS_TOKEN": "kms_token",
            "VAULT_KMS_DEFAULT_KEY": "kms_default_key", "VAULT_KEYSTONE_URL": "keystone_url",
            "VAULT_KEYSTONE_SERVICE_USER": "keystone_service_user",
            "VAULT_KEYSTONE_SERVICE_PASSWORD": "keystone_service_password",
            "VAULT_KEYSTONE_SERVICE_PROJECT": "keystone_service_project",
            "VAULT_KEYSTONE_DOMAIN": "keystone_domain",
            "VAULT_OIDC_JWKS_URL": "oidc_jwks_url", "VAULT_OIDC_ISSUER": "oidc_issuer",
            "VAULT_OIDC_AUDIENCE": "oidc_audience", "VAULT_OIDC_CLAIM": "oidc_claim",
            "VAULT_QUEUE_DIR": "queue_dir", "VAULT_PUBLIC_URL": "public_url"}
    for env, attr in strs.items():
        if _env(env) is not None:
            setattr(s, attr, _env(env))
    # simple target shortcuts: VAULT_AUDIT_WEBHOOK=http://..., VAULT_AUDIT_FILE=/path, VAULT_AUDIT_KAFKA=broker/topic
    for kind, var in (("webhook", "VAULT_AUDIT_WEBHOOK"), ("file", "VAULT_AUDIT_FILE"),
                      ("kafka", "VAULT_AUDIT_KAFKA")):
        if _env(var):
            s.audit_targets.append(_target_from_env(kind, _env(var), "audit"))
    for kind, var in (("webhook", "VAULT_EVENT_WEBHOOK"), ("kafka", "VAULT_EVENT_KAFKA")):
        if _env(var):
            s.event_targets.append(_target_from_env(kind, _env(var), "events"))
    path = _env("VAULT_CONFIG_FILE")
    if path and os.path.exists(path):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        for k, v in data.items():
            if k == "audit":
                s.audit_targets.extend(v.get("targets", []))
            elif k == "events":
                s.event_targets.extend(v.get("targets", []))
            elif hasattr(s, k):
                setattr(s, k, v)
    return s


def _target_from_env(kind: str, value: str, name: str) -> dict:
    if kind == "webhook":
        return {"type": "webhook", "name": name, "url": value}
    if kind == "file":
        return {"type": "file", "name": name, "path": value}
    broker, _, topic = value.partition("/")
    return {"type": "kafka", "name": name, "brokers": broker, "topic": topic or f"vault-{name}"}
