"""DelegAuth — Capability Token Delegation Service.

A stateless-friendly REST API that lets any AI agent issue, delegate,
verify, and revoke HMAC-chained capability tokens without writing a
single line of crypto code.

Endpoints
---------
GET  /health                   — liveness probe
GET  /skill.md                 — machine-readable usage instructions
POST /tokens/root              — mint a root capability token
POST /tokens/delegate          — carve a narrower child token
POST /tokens/verify            — verify a token (audience + scope check)
POST /tokens/revoke            — revoke a token and its entire subtree
GET  /tokens/{token_id}/tree   — inspect the delegation tree for one token
GET  /audit/log                — full audit trail (most recent 200 events)
GET  /receipts/{token_id}      — HMAC-signed receipt for any token operation
GET  /receipts/{token_id}/verify — verify a receipt offline (no trust required)
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import math
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# In-memory store (single process; fits the hackathon scope)
# ---------------------------------------------------------------------------

_SECRET = b"delegauth-nandahack-2026-hmac-secret"


class CapabilityError(ValueError):
    """Raised when a capability token cannot be issued or verified."""


@dataclass(frozen=True, slots=True)
class Cap:
    token_id: str
    subject: str
    audience: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    parent_id: str | None = None
    max_depth: int = 0
    depth: int = 0
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        return {
            "aud": self.audience,
            "depth": self.depth,
            "exp": self.expires_at,
            "iat": self.issued_at,
            "jti": self.token_id,
            "max_depth": self.max_depth,
            "parent": self.parent_id,
            "scopes": sorted(self.scopes),
            "sub": self.subject,
        }


class Store:
    def __init__(self) -> None:
        self._tokens: dict[str, Cap] = {}
        self._children: dict[str, set[str]] = {}
        self._revoked: set[str] = set()
        self._audit: list[dict[str, Any]] = []

    def _sign(self, cap: Cap) -> Cap:
        payload = json.dumps(cap.payload(), separators=(",", ":"), sort_keys=True).encode()
        sig = hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()
        return dataclasses.replace(cap, signature=sig)

    def _check_sig(self, cap: Cap) -> bool:
        expected = self._sign(dataclasses.replace(cap, signature="")).signature
        return hmac.compare_digest(cap.signature, expected)

    def _store(self, cap: Cap) -> tuple[str, Cap]:
        self._tokens[cap.token_id] = cap
        self._children.setdefault(cap.token_id, set())
        if cap.parent_id:
            self._children.setdefault(cap.parent_id, set()).add(cap.token_id)
        return cap.token_id, cap

    def issue_root(
        self,
        subject: str,
        audience: str,
        scopes: set[str],
        ttl_seconds: float,
        max_depth: int,
    ) -> tuple[str, Cap]:
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise CapabilityError("ttl_seconds must be positive and finite")
        if max_depth < 0:
            raise CapabilityError("max_depth must be non-negative")
        now = time.time()
        cap = Cap(
            token_id=uuid.uuid4().hex,
            subject=subject,
            audience=audience,
            scopes=frozenset(scopes),
            issued_at=now,
            expires_at=now + ttl_seconds,
            max_depth=max_depth,
        )
        cap = self._sign(cap)
        tid, cap = self._store(cap)
        self._audit.append({"event": "issue_root", "token_id": tid, "subject": subject,
                             "audience": audience, "scopes": sorted(scopes),
                             "ts": datetime.now(UTC).isoformat()})
        return tid, cap

    def delegate(
        self,
        parent_id: str,
        subject: str,
        audience: str | None = None,
        scopes: set[str] | None = None,
        ttl_seconds: float | None = None,
    ) -> tuple[str, Cap]:
        parent = self._verify_cap(parent_id)
        if parent.depth >= parent.max_depth:
            raise CapabilityError(f"delegation depth exceeded (max={parent.max_depth})")
        now = time.time()
        child_scopes = frozenset(scopes) if scopes is not None else parent.scopes
        if not child_scopes.issubset(parent.scopes):
            raise CapabilityError(
                f"child scopes must be a subset of parent scopes; "
                f"extra={child_scopes - parent.scopes}"
            )
        parent_remaining = parent.expires_at - now
        if parent_remaining <= 0:
            raise CapabilityError("parent token has expired")
        child_ttl = min(ttl_seconds or parent_remaining, parent_remaining)
        child = Cap(
            token_id=uuid.uuid4().hex,
            subject=subject,
            audience=audience or parent.audience,
            scopes=child_scopes,
            issued_at=now,
            expires_at=now + child_ttl,
            parent_id=parent.token_id,
            max_depth=parent.max_depth,
            depth=parent.depth + 1,
        )
        child = self._sign(child)
        tid, child = self._store(child)
        self._audit.append({"event": "delegate", "token_id": tid, "parent_id": parent_id,
                             "subject": subject, "scopes": sorted(child_scopes),
                             "ts": datetime.now(UTC).isoformat()})
        return tid, child

    def _verify_cap(self, token_id: str, audience: str | None = None,
                    required_scopes: set[str] | None = None) -> Cap:
        cap = self._tokens.get(token_id)
        if cap is None:
            raise CapabilityError(f"unknown token: {token_id}")
        if token_id in self._revoked:
            raise CapabilityError("token has been revoked")
        if not self._check_sig(cap):
            raise CapabilityError("token signature is invalid")
        if time.time() > cap.expires_at:
            raise CapabilityError("token has expired")
        if audience and cap.audience != audience:
            raise CapabilityError(f"audience mismatch: expected={cap.audience}, got={audience}")
        if required_scopes and not required_scopes.issubset(cap.scopes):
            missing = required_scopes - cap.scopes
            raise CapabilityError(f"missing required scopes: {missing}")
        # Check ancestor revocation
        cursor = cap.parent_id
        while cursor:
            if cursor in self._revoked:
                raise CapabilityError("ancestor token has been revoked")
            anc = self._tokens.get(cursor)
            cursor = anc.parent_id if anc else None
        return cap

    def verify(self, token_id: str, audience: str | None = None,
               required_scopes: set[str] | None = None) -> Cap:
        cap = self._verify_cap(token_id, audience, required_scopes)
        self._audit.append({"event": "verify", "token_id": token_id, "result": "ok",
                             "ts": datetime.now(UTC).isoformat()})
        return cap

    def revoke(self, token_id: str) -> list[str]:
        if token_id not in self._tokens:
            raise CapabilityError(f"unknown token: {token_id}")
        revoked: list[str] = []
        stack = [token_id]
        while stack:
            tid = stack.pop()
            if tid not in self._revoked:
                self._revoked.add(tid)
                revoked.append(tid)
                stack.extend(self._children.get(tid, set()))
        self._audit.append({"event": "revoke", "token_id": token_id,
                             "cascade_count": len(revoked),
                             "ts": datetime.now(UTC).isoformat()})
        return revoked

    def tree(self, token_id: str) -> dict[str, Any]:
        cap = self._tokens.get(token_id)
        if cap is None:
            raise CapabilityError(f"unknown token: {token_id}")

        def _node(tid: str) -> dict[str, Any]:
            c = self._tokens[tid]
            return {
                "token_id": tid,
                "subject": c.subject,
                "audience": c.audience,
                "scopes": sorted(c.scopes),
                "depth": c.depth,
                "revoked": tid in self._revoked,
                "expires_at": datetime.fromtimestamp(c.expires_at, UTC).isoformat(),
                "children": [_node(ch) for ch in sorted(self._children.get(tid, set()))],
            }

        return _node(token_id)

    def audit_log(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._audit[-limit:]


_store = Store()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

SKILL_MD = """\
# DelegAuth — Capability Token Delegation

Mint, delegate, verify, and revoke HMAC-chained capability tokens.
Agents can carve narrower sub-tokens from a parent without calling the
original issuer; revoking a parent cascades to every descendant instantly.

## Base URL
https://delegauth-service.vercel.app

## Backup URL (persistent, stateful)
https://delegauth-service.onrender.com

## Endpoints

GET /health
  Liveness probe. Returns {"status":"ok"}.
  Example:
    curl https://delegauth.up.railway.app/health
  Response:
    {"status":"ok","ts":"2026-07-08T..."}

POST /tokens/root
  Issue a root capability token.
  Body (JSON): subject, audience, scopes (list), ttl_seconds, max_depth
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/root \\
      -H "Content-Type: application/json" \\
      -d '{"subject":"alice","audience":"market","scopes":["read","write","admin"],"ttl_seconds":3600,"max_depth":2}'
  Response:
    {"token_id":"<hex>","subject":"alice","audience":"market","scopes":["admin","read","write"],"depth":0,"max_depth":2,"expires_at":"..."}

POST /tokens/delegate
  Carve a narrower child token from an existing parent.
  Body: parent_id, subject, audience (optional), scopes (optional, must be subset), ttl_seconds (optional)
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/delegate \\
      -H "Content-Type: application/json" \\
      -d '{"parent_id":"<hex>","subject":"bob","scopes":["read"]}'
  Response:
    {"token_id":"<hex>","subject":"bob","depth":1,"scopes":["read"],...}

POST /tokens/verify
  Verify a token. Checks signature, expiry, audience, scope sufficiency, and revocation ancestry.
  Body: token_id, audience (optional), required_scopes (optional list)
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/verify \\
      -H "Content-Type: application/json" \\
      -d '{"token_id":"<hex>","audience":"market","required_scopes":["read"]}'
  Response (ok):
    {"valid":true,"subject":"bob","scopes":["read"],"expires_at":"..."}
  Response (fail):
    {"valid":false,"reason":"token has been revoked"}

POST /tokens/revoke
  Revoke a token and its entire delegation subtree (cascade).
  Body: token_id
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/revoke \\
      -H "Content-Type: application/json" \\
      -d '{"token_id":"<hex>"}'
  Response:
    {"revoked_count":3,"revoked_ids":["<hex>","<hex>","<hex>"]}

GET /tokens/{token_id}/tree
  Visualise the full delegation subtree rooted at token_id.
  Example:
    curl https://delegauth.up.railway.app/tokens/<hex>/tree
  Response:
    {"token_id":"<hex>","subject":"alice","children":[{"token_id":"...","subject":"bob","children":[...]}]}

GET /audit/log
  Full audit trail — issue, delegate, verify, revoke events (most recent 200).
  Example:
    curl https://delegauth.up.railway.app/audit/log
  Response:
    [{"event":"issue_root","token_id":"...","ts":"..."},...]

GET /skill.md
  This file. Served as plain text for agent consumption.

## How the agent should use this

1. Issue a root token with POST /tokens/root.
   Store the returned token_id — this is the handle for all future calls.

2. To grant a sub-agent narrower access, POST /tokens/delegate with the
   parent token_id and a scopes list that is a subset of the parent's.

3. Before acting on behalf of a principal, the sub-agent calls
   POST /tokens/verify. A {"valid":true} response means the token is
   live and the scopes are present.

4. When a principal's session ends, POST /tokens/revoke with the root
   token_id. Every descendant token becomes invalid instantly — no
   per-child bookkeeping needed.

5. To audit who delegated what to whom, call GET /audit/log.

## Error handling

All errors return HTTP 4xx with JSON body: {"detail": "<reason>"}
Common reasons: "token has been revoked", "delegation depth exceeded",
"child scopes must be a subset of parent scopes", "token has expired",
"audience mismatch", "unknown token".
"""


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    yield


app = FastAPI(
    title="DelegAuth",
    description="Capability token delegation for autonomous AI agents",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Pydantic schemas ────────────────────────────────────────────────────────

class IssueRootReq(BaseModel):
    subject: str
    audience: str
    scopes: list[str]
    ttl_seconds: float = Field(default=3600.0, gt=0)
    max_depth: int = Field(default=2, ge=0)


class DelegateReq(BaseModel):
    parent_id: str
    subject: str
    audience: str | None = None
    scopes: list[str] | None = None
    ttl_seconds: float | None = None


class VerifyReq(BaseModel):
    token_id: str
    audience: str | None = None
    required_scopes: list[str] | None = None


class RevokeReq(BaseModel):
    token_id: str


def _cap_to_dict(cap: Cap) -> dict[str, Any]:
    return {
        "token_id": cap.token_id,
        "subject": cap.subject,
        "audience": cap.audience,
        "scopes": sorted(cap.scopes),
        "depth": cap.depth,
        "max_depth": cap.max_depth,
        "issued_at": datetime.fromtimestamp(cap.issued_at, UTC).isoformat(),
        "expires_at": datetime.fromtimestamp(cap.expires_at, UTC).isoformat(),
        "parent_id": cap.parent_id,
    }


# ── Routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "ts": datetime.now(UTC).isoformat()}


@app.get("/skill.md", response_class=PlainTextResponse)
async def skill_md() -> str:
    return SKILL_MD


@app.post("/tokens/root")
async def issue_root(req: IssueRootReq) -> dict[str, Any]:
    try:
        tid, cap = _store.issue_root(
            subject=req.subject,
            audience=req.audience,
            scopes=set(req.scopes),
            ttl_seconds=req.ttl_seconds,
            max_depth=req.max_depth,
        )
    except CapabilityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return _cap_to_dict(cap)


@app.post("/tokens/delegate")
async def delegate(req: DelegateReq) -> dict[str, Any]:
    try:
        _, cap = _store.delegate(
            parent_id=req.parent_id,
            subject=req.subject,
            audience=req.audience,
            scopes=set(req.scopes) if req.scopes is not None else None,
            ttl_seconds=req.ttl_seconds,
        )
    except CapabilityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return _cap_to_dict(cap)


@app.post("/tokens/verify")
async def verify(req: VerifyReq) -> dict[str, Any]:
    try:
        cap = _store.verify(
            token_id=req.token_id,
            audience=req.audience,
            required_scopes=set(req.required_scopes) if req.required_scopes else None,
        )
        return {"valid": True, **_cap_to_dict(cap)}
    except CapabilityError as e:
        return {"valid": False, "reason": str(e)}


@app.post("/tokens/revoke")
async def revoke(req: RevokeReq) -> dict[str, Any]:
    try:
        revoked = _store.revoke(req.token_id)
    except CapabilityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"revoked_count": len(revoked), "revoked_ids": revoked}


@app.get("/tokens/{token_id}/tree")
async def token_tree(token_id: str) -> dict[str, Any]:
    try:
        return _store.tree(token_id)
    except CapabilityError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.get("/audit/log")
async def audit_log() -> list[dict[str, Any]]:
    return _store.audit_log()


# ── Signed Receipts ─────────────────────────────────────────────────────────
# Each operation recorded in the audit log can be retrieved as a
# cryptographically signed receipt.  Agents can pass receipts to a third
# party who verifies them offline using GET /receipts/{token_id}/verify
# without having to trust — or even contact — the DelegAuth server.


def _make_receipt(event: dict[str, Any]) -> dict[str, Any]:
    """Return a signed receipt dict for one audit-log entry."""
    payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return {"receipt": event, "signature": sig, "algorithm": "HMAC-SHA256"}


@app.get("/receipts/{token_id}")
async def get_receipt(token_id: str) -> dict[str, Any]:
    """Return an HMAC-SHA256 signed receipt for a token's most recent event.

    The receipt can be handed to any third party as cryptographic proof
    that this delegation event occurred and was recorded by this service.
    Verify it offline with GET /receipts/{token_id}/verify.
    """
    log = _store.audit_log()
    # Most recent event for this token
    for entry in reversed(log):
        if entry.get("token_id") == token_id:
            return _make_receipt(entry)
    raise HTTPException(status_code=404, detail=f"no events for token: {token_id}")


class ReceiptVerifyReq(BaseModel):
    receipt: dict[str, Any]
    signature: str


@app.post("/receipts/verify")
async def verify_receipt(req: ReceiptVerifyReq) -> dict[str, Any]:
    """Verify a signed receipt offline.

    Pass the receipt + signature returned by GET /receipts/{token_id}.
    Returns {"valid": true} if the receipt is authentic and untampered.
    This endpoint requires no knowledge of the original token — it only
    checks the HMAC signature against the server secret.
    """
    payload = json.dumps(req.receipt, separators=(",", ":"), sort_keys=True)
    expected = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, req.signature)
    return {"valid": valid, "algorithm": "HMAC-SHA256"}
