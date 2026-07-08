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
    {"status":"ok","ts":"2026-07-08T20:00:00+00:00"}

POST /tokens/root
  Issue a root capability token.
  Body (JSON): subject, audience, scopes (list), ttl_seconds, max_depth
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/root \
      -H "Content-Type: application/json" \
      -d '{"subject":"alice","audience":"market","scopes":["read","write","admin"],"ttl_seconds":3600,"max_depth":2}'
  Response:
    {"token_id":"<hex>","subject":"alice","audience":"market","scopes":["admin","read","write"],"depth":0,"max_depth":2,"expires_at":"..."}

POST /tokens/delegate
  Carve a narrower child token from an existing parent.
  Body: parent_id, subject, audience (optional), scopes (optional, must be subset of parent), ttl_seconds (optional)
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/delegate \
      -H "Content-Type: application/json" \
      -d '{"parent_id":"<hex>","subject":"bob","scopes":["read"]}'
  Response:
    {"token_id":"<hex>","subject":"bob","depth":1,"scopes":["read"],...}

POST /tokens/verify
  Verify a token. Checks signature, expiry, audience, scope sufficiency, and revocation ancestry.
  Body: token_id, audience (optional), required_scopes (optional list)
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/verify \
      -H "Content-Type: application/json" \
      -d '{"token_id":"<hex>","audience":"market","required_scopes":["read"]}'
  Response (ok):
    {"valid":true,"subject":"bob","scopes":["read"],"expires_at":"..."}
  Response (fail):
    {"valid":false,"reason":"token has been revoked"}

POST /tokens/revoke
  Revoke a token and its entire delegation subtree (cascade).
  Body: token_id
  Example:
    curl -X POST https://delegauth.up.railway.app/tokens/revoke \
      -H "Content-Type: application/json" \
      -d '{"token_id":"<hex>"}'
  Response:
    {"revoked_count":3,"revoked_ids":["<hex>","<hex>","<hex>"]}

GET /tokens/{token_id}/tree
  Visualise the full delegation subtree rooted at a given token.
  Example:
    curl https://delegauth.up.railway.app/tokens/<hex>/tree
  Response:
    {"token_id":"<hex>","subject":"alice","children":[{"subject":"bob","children":[...]}]}

GET /audit/log
  Full audit trail of issue, delegate, verify, and revoke events (most recent 200).
  Example:
    curl https://delegauth.up.railway.app/audit/log
  Response:
    [{"event":"issue_root","token_id":"...","ts":"..."},...]

GET /skill.md
  This file, served as plain text for agent consumption.
  curl https://delegauth.up.railway.app/skill.md

## How the agent should use this

1. Issue a root token with POST /tokens/root.
   Store the returned token_id — it is the handle for all future calls.

2. To grant a sub-agent narrower access, call POST /tokens/delegate with
   the parent token_id and a scopes list that is a subset of the parent's.

3. Before acting on behalf of a principal, the sub-agent calls
   POST /tokens/verify. A {"valid":true} response means the token is live
   and the required scopes are present.

4. When a session ends, call POST /tokens/revoke with the root token_id.
   Every descendant token becomes invalid instantly — no per-child
   bookkeeping required.

5. To audit who delegated what to whom, call GET /audit/log.

## Error handling

All errors return HTTP 4xx with JSON: {"detail": "<reason>"}
Common error strings:
  "token has been revoked"
  "delegation depth exceeded (max=N)"
  "child scopes must be a subset of parent scopes"
  "token has expired"
  "audience mismatch"
  "unknown token: <id>"

## Security properties

- Tokens are signed with HMAC-SHA256; no secret is ever returned
- Scope escalation is rejected at delegation time
- Audience is bound in the signed payload and checked at verify time
- Child TTL is clamped to parent's remaining lifetime
- Revoking a parent cascades to all descendants in O(n) time
- NaN / Infinity TTL values are rejected
