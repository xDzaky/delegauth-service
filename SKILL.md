# DelegAuth — Capability Token Delegation for AI Agents

Mint, delegate, verify, and revoke HMAC-chained capability tokens.
Agents carve narrower sub-tokens from a parent without calling the original
issuer; revoking a parent cascades to every descendant instantly.
Every operation produces a signed receipt that any party can verify offline.

## Base URL
https://delegauth-service.vercel.app

## Backup URL (persistent, stateful)
https://delegauth-service.onrender.com

---

## Quick Autonomous Workflow (copy-paste ready)

An agent that needs to grant a sub-agent temporary scoped access should:

**Step 1 — Issue root token (once per session)**
```
POST /tokens/root
{"subject":"<my_agent_id>","audience":"<service>","scopes":["read","write"],"ttl_seconds":3600,"max_depth":2}
→ Save returned token_id as ROOT_TOKEN
```

**Step 2 — Delegate to sub-agent**
```
POST /tokens/delegate
{"parent_id":"<ROOT_TOKEN>","subject":"<sub_agent_id>","scopes":["read"]}
→ Give returned token_id (CHILD_TOKEN) to the sub-agent
```

**Step 3 — Sub-agent verifies before acting**
```
POST /tokens/verify
{"token_id":"<CHILD_TOKEN>","required_scopes":["read"]}
→ {"valid":true,...}  → proceed
→ {"valid":false,"reason":"..."} → refuse and report error
```

**Step 4 — Fetch signed receipt as proof of delegation**
```
GET /receipts/<CHILD_TOKEN>
→ {"receipt":{...},"signature":"<hex>","algorithm":"HMAC-SHA256"}
→ Store receipt — it proves the delegation happened, verifiable offline
```

**Step 5 — Session ends: revoke everything in one call**
```
POST /tokens/revoke
{"token_id":"<ROOT_TOKEN>"}
→ {"revoked_count":2,"revoked_ids":["<ROOT_TOKEN>","<CHILD_TOKEN>"]}
→ All child tokens instantly invalid — no per-child bookkeeping needed
```

---

## All Endpoints

### GET /health
Liveness probe.
```
curl https://delegauth-service.vercel.app/health
→ {"status":"ok","ts":"2026-07-08T20:00:00+00:00"}
```

### GET /skill.md
This file, served as plain text for agent consumption.

### POST /tokens/root
Issue a root capability token.

Body fields:
- subject (str, required) — agent identity
- audience (str, required) — service this token is for
- scopes (list[str], required) — capabilities granted
- ttl_seconds (float, default=3600) — token lifetime
- max_depth (int, default=2) — how many delegation hops allowed

Example:
```
curl -X POST https://delegauth-service.vercel.app/tokens/root \
  -H "Content-Type: application/json" \
  -d '{"subject":"alice","audience":"market","scopes":["read","write","admin"],"ttl_seconds":3600,"max_depth":2}'
→ {"token_id":"<hex>","subject":"alice","scopes":["admin","read","write"],"depth":0,...}
```

### POST /tokens/delegate
Carve a narrower child token from an existing parent.

Body fields:
- parent_id (str, required) — token_id of the parent
- subject (str, required) — identity of the sub-agent
- audience (str, optional) — defaults to parent's audience
- scopes (list[str], optional) — must be a subset of parent's scopes
- ttl_seconds (float, optional) — clamped to parent's remaining lifetime

Example:
```
curl -X POST https://delegauth-service.vercel.app/tokens/delegate \
  -H "Content-Type: application/json" \
  -d '{"parent_id":"<hex>","subject":"bob","scopes":["read"]}'
→ {"token_id":"<hex>","subject":"bob","depth":1,"scopes":["read"],...}
```

### POST /tokens/verify
Verify a token. Checks: HMAC signature, expiry, audience binding, scope
sufficiency, and full ancestor revocation chain.

Body fields:
- token_id (str, required)
- audience (str, optional) — check audience binding
- required_scopes (list[str], optional) — check scope sufficiency

Example:
```
curl -X POST https://delegauth-service.vercel.app/tokens/verify \
  -H "Content-Type: application/json" \
  -d '{"token_id":"<hex>","audience":"market","required_scopes":["read"]}'
→ {"valid":true,"subject":"bob","scopes":["read"],...}
→ {"valid":false,"reason":"token has been revoked"}
```

### POST /tokens/revoke
Revoke a token and cascade to its entire delegation subtree atomically.

Body: `{"token_id":"<hex>"}`

Example:
```
curl -X POST https://delegauth-service.vercel.app/tokens/revoke \
  -H "Content-Type: application/json" \
  -d '{"token_id":"<hex>"}'
→ {"revoked_count":3,"revoked_ids":["<hex>","<hex>","<hex>"]}
```

### GET /tokens/{token_id}/tree
Visualise the full delegation subtree rooted at a given token.
```
curl https://delegauth-service.vercel.app/tokens/<hex>/tree
→ {"token_id":"<hex>","subject":"alice","children":[{"subject":"bob","children":[...]}]}
```

### GET /audit/log
Full audit trail of issue, delegate, verify, and revoke events (most recent 200).
```
curl https://delegauth-service.vercel.app/audit/log
→ [{"event":"issue_root","token_id":"...","ts":"..."},...]
```

### GET /receipts/{token_id}
Return an HMAC-SHA256 signed receipt for the most recent event on a token.
The receipt can be passed to any third party as cryptographic proof that the
delegation event occurred. Verify it offline with POST /receipts/verify.
```
curl https://delegauth-service.vercel.app/receipts/<hex>
→ {
    "receipt": {"event":"delegate","token_id":"<hex>","subject":"bob","ts":"..."},
    "signature": "<hex>",
    "algorithm": "HMAC-SHA256"
  }
```

### POST /receipts/verify
Verify a signed receipt offline — no server state required.
Pass the full receipt object and signature returned by GET /receipts/{token_id}.
```
curl -X POST https://delegauth-service.vercel.app/receipts/verify \
  -H "Content-Type: application/json" \
  -d '{"receipt":{...},"signature":"<hex>"}'
→ {"valid":true,"algorithm":"HMAC-SHA256"}
→ {"valid":false,"algorithm":"HMAC-SHA256"}
```

---

## When to Use DelegAuth (Agent Decision Guide)

Use DelegAuth when:
- An orchestrator wants to give a sub-agent narrower access without re-issuing from scratch
- You need to revoke a group of tokens instantly (revoke root → entire tree gone)
- You need audit-proof that a specific delegation happened (use /receipts/{id})
- You are building a multi-agent workflow where agents call other agents with scoped credentials

Do NOT use DelegAuth when:
- You only need a single flat token (use JwtAuth instead — it is simpler)
- Tokens never need to be revoked before expiry
- You need OAuth2 server-to-server flows (this is in-process / per-session)

---

## Error Handling

All errors return HTTP 4xx with JSON: `{"detail": "<reason>"}`

| Error string | Meaning | Action |
|---|---|---|
| `"token has been revoked"` | Token or ancestor revoked | Stop using token; request re-delegation |
| `"delegation depth exceeded (max=N)"` | Chain too deep | Use a shorter sub-chain |
| `"child scopes must be a subset of parent scopes"` | Escalation attempt | Request only scopes the parent holds |
| `"token has expired"` | TTL elapsed | Request fresh delegation |
| `"audience mismatch"` | Wrong service | Check token was issued for this audience |
| `"unknown token: <id>"` | Token never issued or wrong ID | Verify token_id is correct |
| `"invalid capability signature"` | Tampered payload | Treat as security incident |

---

## Security Properties

- Tokens are signed with HMAC-SHA256; the secret never leaves the server
- Scope escalation is rejected at delegation time (not just at verify time)
- Audience is cryptographically bound in the signed payload, checked at verify
- Child TTL is clamped to parent's remaining lifetime
- Revoking a parent cascades to all descendants in O(n) time
- NaN / Infinity TTL values are rejected
- Signed receipts allow offline verification — third parties need not trust the server
