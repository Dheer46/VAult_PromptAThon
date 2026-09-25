"""OpenStack Keystone integration — arrow #17: IAM and OIDC -> Keystone Service
"authenticates users" (dotted, HTTP).

Swift-style `X-Auth-Token` requests are validated with GET /v3/auth/tokens
(the service authenticates with its own token and asks about the user's token).
SigV4 requests with an access key unknown to local IAM can fall back to Keystone
EC2 credentials via POST /v3/ec2tokens.
"""
from __future__ import annotations

import time

import httpx

from .. import errors
from ..observability import metrics
from ..observability.log import log
from .iam import Identity

TOKEN_CACHE_TTL = 60.0

# Keystone role -> Vault policies
ROLE_POLICIES = {"admin": ["consoleAdmin"], "member": ["readwrite"], "_member_": ["readwrite"],
                 "reader": ["readonly"]}


def identity_from_token(body: dict) -> Identity:
    tok = body.get("token", {})
    user = tok.get("user", {})
    project = tok.get("project", {}) or {}
    roles = [r.get("name", "") for r in tok.get("roles", [])]
    pols: list[str] = []
    for r in roles:
        for p in ROLE_POLICIES.get(r.lower(), []):
            if p not in pols:
                pols.append(p)
    return Identity(access_key=user.get("id", ""), user=user.get("name", ""), source="keystone",
                    policies=pols, project=project.get("name", ""), groups=roles)


class KeystoneClient:
    def __init__(self, settings):
        self.s = settings
        self.url = settings.keystone_url.rstrip("/")
        self._svc_token: tuple[str, float] = ("", 0.0)
        self._cache: dict[str, tuple[Identity, float]] = {}
        self._http = httpx.AsyncClient(timeout=5.0)

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    async def _service_token(self) -> str:
        tok, exp = self._svc_token
        if tok and time.time() < exp - 60:
            return tok
        body = {"auth": {
            "identity": {"methods": ["password"], "password": {"user": {
                "name": self.s.keystone_service_user, "password": self.s.keystone_service_password,
                "domain": {"name": self.s.keystone_domain}}}},
            "scope": {"project": {"name": self.s.keystone_service_project,
                                  "domain": {"name": self.s.keystone_domain}}}}}
        r = await self._http.post(f"{self.url}/v3/auth/tokens", json=body)
        if r.status_code != 201:
            raise errors.S3Error("ServiceUnavailable", f"keystone service auth failed: {r.status_code}", 503)
        self._svc_token = (r.headers["X-Subject-Token"], time.time() + 3000)
        return self._svc_token[0]

    async def validate(self, user_token: str) -> Identity:
        cached = self._cache.get(user_token)
        if cached and cached[1] > time.time():
            return cached[0]  # cached tokens keep working (until TTL) if Keystone is down
        try:
            svc = await self._service_token()
            r = await self._http.get(f"{self.url}/v3/auth/tokens",
                                     headers={"X-Auth-Token": svc, "X-Subject-Token": user_token})
        except httpx.HTTPError as e:
            metrics.KEYSTONE_REQUESTS.labels("error").inc()
            log.warning("keystone unreachable", error=str(e))
            raise errors.S3Error("ServiceUnavailable", "keystone unreachable", 503)
        if r.status_code != 200:
            metrics.KEYSTONE_REQUESTS.labels("denied").inc()
            raise errors.S3Error("AccessDenied", "invalid keystone token")
        metrics.KEYSTONE_REQUESTS.labels("ok").inc()
        ident = identity_from_token(r.json())
        self._cache[user_token] = (ident, time.time() + TOKEN_CACHE_TTL)
        return ident

    async def ec2_validate(self, access: str, signature: str, host: str, verb: str, path: str,
                           headers: dict, body_hash: str) -> Identity | None:
        """Validate a SigV4 request against Keystone EC2 credentials."""
        body = {"credentials": {"access": access, "signature": signature, "host": host,
                                "verb": verb, "path": path, "params": {}, "headers": headers,
                                "body_hash": body_hash}}
        try:
            r = await self._http.post(f"{self.url}/v3/ec2tokens", json=body)
        except httpx.HTTPError:
            metrics.KEYSTONE_REQUESTS.labels("error").inc()
            return None
        if r.status_code not in (200, 201):
            metrics.KEYSTONE_REQUESTS.labels("denied").inc()
            return None
        metrics.KEYSTONE_REQUESTS.labels("ok").inc()
        return identity_from_token(r.json())

    async def healthy(self) -> bool:
        try:
            r = await self._http.get(f"{self.url}/v3")
            return r.status_code == 200
        except httpx.HTTPError:
            return False
