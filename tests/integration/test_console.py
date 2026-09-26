"""Web console: login, buckets, upload/list/download/delete, admin views."""
import httpx

from tests.conftest import ROOT_PASS, ROOT_USER


def test_console_flow(server):
    c = httpx.Client(base_url=server.endpoint)
    assert c.get("/vault/console").status_code == 200
    assert c.get("/vault/console/api/buckets").status_code == 401
    assert c.post("/vault/console/api/login", json={"access_key": ROOT_USER, "secret_key": "bad"}).status_code == 401
    r = c.post("/vault/console/api/login", json={"access_key": ROOT_USER, "secret_key": ROOT_PASS})
    assert r.status_code == 200 and r.json()["admin"]
    assert c.post("/vault/console/api/buckets", json={"name": "console-b", "versioning": True}).status_code == 200
    r = c.put("/vault/console/api/objects", params={"bucket": "console-b", "key": "dir/hello.txt"},
              content=b"hi there", headers={"x-content-type": "text/plain", "x-encrypt": "1"})
    assert r.status_code == 200, r.text
    ls = c.get("/vault/console/api/objects", params={"bucket": "console-b"}).json()
    assert ls["prefixes"] == ["dir/"]
    ls = c.get("/vault/console/api/objects", params={"bucket": "console-b", "prefix": "dir/"}).json()
    assert ls["objects"][0]["encrypted"] and ls["objects"][0]["size"] == 8
    assert c.get("/vault/console/api/download", params={"bucket": "console-b", "key": "dir/hello.txt"}).content == b"hi there"
    ov = c.get("/vault/console/api/overview").json()
    b = next(x for x in ov["buckets"] if x["name"] == "console-b")
    assert b["objects"] == 1 and b["bytes"] == 8
    assert ov["recent"][0]["key"] == "dir/hello.txt" and ov["recent"][0]["encrypted"]
    for view in ("cluster", "healing", "replication", "usage", "services", "users"):
        assert c.get(f"/vault/console/api/{view}").status_code == 200, view
    assert c.delete("/vault/console/api/objects", params={"bucket": "console-b", "key": "dir/hello.txt"}).status_code == 200
