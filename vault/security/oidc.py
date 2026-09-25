"""OIDC: STS AssumeRoleWithWebIdentity.

Validates the JWT against the identity provider's JWKS (signature, iss, aud, exp),
maps a claim (default "policy", or "groups") to Vault policies, and issues
temporary access key / secret / session token."""
from __future__ import annotations

import asyncio

import jwt

from .. import errors
from .iam import IAMSys


class OIDCProvider:
    def __init__(self, settings, iam: IAMSys):
        self.s = settings
        self.iam = iam
        self._jwks = jwt.PyJWKClient(settings.oidc_jwks_url) if settings.oidc_jwks_url else None

    @property
    def enabled(self) -> bool:
        return self._jwks is not None

    def _validate(self, token: str) -> dict:
        key = self._jwks.get_signing_key_from_jwt(token)
        opts = {"verify_aud": bool(self.s.oidc_audience)}
        return jwt.decode(token, key.key, algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                          audience=self.s.oidc_audience or None,
                          issuer=self.s.oidc_issuer or None, options=opts)

    async def assume_role_with_web_identity(self, token: str, duration: int = 3600) -> dict:
        if not self.enabled:
            raise errors.S3Error("InvalidRequest", "OIDC is not configured")
        try:
            claims = await asyncio.to_thread(self._validate, token)
        except jwt.PyJWTError as e:
            raise errors.S3Error("AccessDenied", f"invalid web identity token: {e}")
        raw = claims.get(self.s.oidc_claim) or []
        names = raw.split(",") if isinstance(raw, str) else list(raw)
        policies = [p.strip() for p in names if p.strip() in self.iam.policies]
        if not policies:
            raise errors.S3Error("AccessDenied", f"no Vault policy in claim {self.s.oidc_claim!r}")
        duration = max(900, min(duration, 43200))
        creds = await self.iam.issue_temp_credentials(
            parent=claims.get("preferred_username") or claims.get("sub", "oidc-user"),
            source="oidc", policies=policies, duration=duration)
        return {"credentials": creds, "subject": claims.get("sub", ""),
                "audience": claims.get("aud", ""), "provider": claims.get("iss", "")}
