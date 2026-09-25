from .base import Target
from .file import FileTarget
from .kafka import KafkaTarget
from .webhook import WebhookTarget

KINDS = {"webhook": WebhookTarget, "kafka": KafkaTarget, "file": FileTarget}


def make_target(cfg: dict, queue_dir: str) -> Target:
    cfg = dict(cfg)
    kind = cfg.pop("type")
    if kind not in KINDS:
        raise ValueError(f"unknown target type {kind}")
    return KINDS[kind](queue_dir=queue_dir, **cfg)


__all__ = ["Target", "FileTarget", "KafkaTarget", "WebhookTarget", "make_target", "KINDS"]
