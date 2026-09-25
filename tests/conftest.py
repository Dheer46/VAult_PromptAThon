import asyncio
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT_USER, ROOT_PASS = "vaultadmin", "vaultadmin-secret"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread:
    """Runs a single Vault node (8 local drives, EC 5+3) in a background thread."""

    def __init__(self, tmp: str, **overrides):
        from vault.config import Settings, expand
        self.port = free_port()
        self.tmp = tmp
        s = Settings(node_name="local", drives=expand(os.path.join(tmp, "disk{1...8}")),
                     s3_port=self.port, queue_dir=os.path.join(tmp, "queues"),
                     scanner_cycle_pause=3600, root_user=ROOT_USER, root_password=ROOT_PASS)
        for k, v in overrides.items():
            setattr(s, k, v)
        self.settings = s
        self.node = None
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        import uvicorn
        from vault.api_surface.server import create_app
        from vault.main import VaultNode
        asyncio.set_event_loop(self.loop)

        async def go():
            self.node = VaultNode(self.settings)
            await self.node.start()
            cfg = uvicorn.Config(create_app(self.node), host="127.0.0.1", port=self.port,
                                 log_level="warning", lifespan="off")
            self.server = uvicorn.Server(cfg)
            try:
                await self.server.serve()
            finally:
                await self.node.stop()
        self.loop.run_until_complete(go())

    def start(self):
        self.thread.start()
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server did not start")

    def run(self, coro, timeout=60):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self):
        if getattr(self, "server", None):
            self.server.should_exit = True
        self.thread.join(5)

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    srv = ServerThread(str(tmp_path_factory.mktemp("vault"))).start()
    yield srv
    srv.stop()


def make_s3(endpoint, ak=ROOT_USER, sk=ROOT_PASS, **kw):
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=ak, aws_secret_access_key=sk,
                        region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}, signature_version="s3v4",
                                      request_checksum_calculation="when_required",
                                      response_checksum_validation="when_required", **kw))


@pytest.fixture(scope="session")
def s3(server):
    return make_s3(server.endpoint)
