from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..security.iam import ANONYMOUS, Identity


@dataclass
class RequestContext:
    request_id: str
    identity: Identity = field(default_factory=lambda: ANONYMOUS)
    source_ip: str = ""
    secure: bool = False
    api: str = ""  # "PutObject", filled by the router
    bucket: str = ""
    key: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    started: float = field(default_factory=time.time)
    tags: dict = field(default_factory=dict)  # extra info for audit (error, version id...)

    @property
    def principal(self) -> str:
        return self.identity.user if self.identity else ""


def system_context(api: str = "internal") -> RequestContext:
    from ..security.iam import Identity
    return RequestContext(request_id="internal", identity=Identity("", "vault", "root"), api=api)
