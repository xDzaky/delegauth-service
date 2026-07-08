# DelegAuth — Capability Token Delegation Service

**NandaHack Phase 2 submission** by Achmad Dzaki (xDzaky)

A live REST API that lets any AI agent issue, delegate, verify, and revoke HMAC-chained capability tokens — without writing a single line of crypto code.

## Live Endpoint

```
https://delegauth.up.railway.app
```

## Quick start (curl)

```bash
# 1. Health check
curl https://delegauth.up.railway.app/health

# 2. Issue root token
ROOT=$(curl -s -X POST https://delegauth.up.railway.app/tokens/root \
  -H "Content-Type: application/json" \
  -d '{"subject":"alice","audience":"market","scopes":["read","write","admin"],"ttl_seconds":3600,"max_depth":2}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token_id'])")

# 3. Delegate to Bob
CHILD=$(curl -s -X POST https://delegauth.up.railway.app/tokens/delegate \
  -H "Content-Type: application/json" \
  -d "{\"parent_id\":\"$ROOT\",\"subject\":\"bob\",\"scopes\":[\"read\"]}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token_id'])")

# 4. Verify Bob's token
curl -X POST https://delegauth.up.railway.app/tokens/verify \
  -H "Content-Type: application/json" \
  -d "{\"token_id\":\"$CHILD\",\"required_scopes\":[\"read\"]}"

# 5. Revoke root (cascades to Bob automatically)
curl -X POST https://delegauth.up.railway.app/tokens/revoke \
  -H "Content-Type: application/json" \
  -d "{\"token_id\":\"$ROOT\"}"

# 6. Verify Bob's token now — should return {"valid":false,"reason":"...revoked"}
curl -X POST https://delegauth.up.railway.app/tokens/verify \
  -H "Content-Type: application/json" \
  -d "{\"token_id\":\"$CHILD\"}"
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness probe |
| GET | `/skill.md` | Agent-readable usage instructions |
| POST | `/tokens/root` | Issue a root capability token |
| POST | `/tokens/delegate` | Carve a narrower child token |
| POST | `/tokens/verify` | Verify token (sig + expiry + audience + scopes + revocation) |
| POST | `/tokens/revoke` | Revoke token + entire subtree |
| GET | `/tokens/{id}/tree` | Visualise delegation subtree |
| GET | `/audit/log` | Full audit trail (last 200 events) |

## Deploy yourself

```bash
git clone https://github.com/xDzaky/delegauth-service
cd delegauth-service
pip install -r requirements.txt
uvicorn main:app --reload
```

Or one-click deploy to Railway:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/template/delegauth)

## Related

- Phase 1 PR: https://github.com/projnanda/nandatown/pull/106
- NandaHack: https://nandahack.media.mit.edu
