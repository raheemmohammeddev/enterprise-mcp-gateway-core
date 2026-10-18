# Enterprise MCP Gateway

**Multi-Tenant Model Context Protocol Gateway with Dynamic RBAC, Multi-Backend Integration, and Defense-in-Depth Observability**

An enterprise-grade MCP server that mediates AI agent and IDE copilot access to backend systems through a unified, governed interface with authentication, authorization, rate limiting, audit logging, and encryption.

---

## Key Metrics

| Metric | Value |
|---|---|
| MCP Tools | 15 registered (1 built-in, 4 Jira, 4 BRE stubs, 3 Neo4j, 3 Teradata) |
| Backend Systems | 4 backend modules (Jira, BRE/RDS, Neo4j, Teradata) plus DocumentDB as the config/audit store |
| Authentication Modes | 3 (API Key + JWT, Kiro RBAC, Legacy opt-in loopback only) |
| Security Guardrails | 7 composable checks per request |
| Audit Pipelines | 3 parallel (Jira, Generic, Access) |
| Rate Limiting | 2-layer sliding window (per-consumer + per-group) |
| Encryption | AES-256-GCM with AWS KMS envelope encryption |
| RBAC Roles | 5 AD-group-mapped tiers |

---

## Architecture Overview

```
Client (AI Agent / Kiro IDE / REST)
    |
    v
AuthMiddleware (3-mode: API Key+JWT, Kiro RBAC, Legacy)
    |
    v
Guardrail Pipeline (7 composable security checks)
    |
    v
Two-Layer Rate Limiter (per-consumer + per-tool-group)
    |
    v
Backend Dispatcher
    |
    +--- Jira REST API / LLM Orchestrator
    +--- Business Rule Engine (RDS API)
    +--- Neo4j (Bolt driver)
    +--- Teradata (MCP Sidecar)
    |
    v
Audit Pipelines (Jira | Generic | Access) --> DocumentDB
```

---

## MCP Capabilities

Exactly what the server advertises over `/mcp`, and nothing more:

| Capability | Served | Methods |
|---|---|---|
| Tools | 15 | `tools/list`, `tools/call` |
| Resources | 1 (`graph://neo4j/schema`) | `resources/list`, `resources/read` |
| Prompts | 1 (`cypher_query_guidance`) | `prompts/list`, `prompts/get` |

- `graph://neo4j/schema` (`application/json`) returns node labels,
  relationship types, property keys and connected
  `(:Label)-[:REL]->(:Label)` relationship patterns read from
  `CALL db.schema.visualization()`. When that procedure is unavailable the
  pattern list is empty and a `notes` field explains why; patterns are never
  fabricated.
- `cypher_query_guidance(question)` returns Cypher composition guidance that
  embeds the live schema and the constraints the gateway actually enforces
  (read-only keyword blocking and the auto-injected `LIMIT`, capped at 500
  rows).
- Both are registered only when `NEO4J_ENABLED=true`. With the backend
  disabled `resources/list` and `prompts/list` return empty and a
  `resources/read` of `graph://neo4j/schema` fails with `Resource not found`.
  The `resources` and `prompts` capability flags themselves are advertised
  unconditionally: the FastMCP layer builds the `initialize` capability object
  from its own server features, not from what the backends registered. The
  registration guard controls the lists, which is what a discovering client
  enumerates.
- Both pass through the same guardrail pipeline as the tools before any
  database work: the resource authorizes against `neo4j_get_schema` and the
  prompt against `neo4j_validate_query`, and the prompt withholds the live
  schema unless the caller is also authorized for `neo4j_get_schema`. A
  caller denied the tool cannot read the data through the resource or the
  prompt, and a caller with no identity is denied outright.
- A guardrail denial is delivered in the body, not as a JSON-RPC error, which
  follows the gateway convention that handler errors are returned at HTTP 200:
  a denied `resources/read` returns `contents[0].text` holding the
  `{"error": "forbidden", "guardrail": "tool_authorization", ...}` document,
  and a denied `prompts/get` returns that same document as the prompt text. A
  client has to inspect the payload; it gets no protocol-level signal.
- No other resources or prompts are registered.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (for local infrastructure)

### Local Development

```bash
# Clone the repository
git clone <repo-url> && cd enterprise-mcp-gateway-core

# Copy environment config
cp .env.example .env

# Start infrastructure (MongoDB + Redis)
docker compose up -d mongodb redis

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\Activate.ps1  # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Run the gateway
python src/gateway/app.py --transport=streamable-http --port=8100

# In another terminal, run tests
pytest tests/ -v
```

### Docker Compose (Full Stack)

```bash
docker compose up -d
# Gateway at http://localhost:8100
# MongoDB at localhost:27017
# Redis at localhost:6379
```

---

## Project Structure

```
enterprise-mcp-gateway-core/
  src/gateway/
    app.py                      # ASGI entry point (Starlette + FastMCP)
    config/
      settings.py               # All env-var configuration with defaults
      db.py                     # DocumentDB/MongoDB connection
    middleware/
      auth.py                   # AuthMiddleware (3-mode authentication)
    security/
      jwt_validator.py          # IdP-agnostic JWT validation
      consumer_registry.py      # Consumer profile management
      kms_envelope.py           # AES-256-GCM envelope encryption
    guardrails/
      pipeline.py               # 7-step composable security pipeline
    ratelimit/
      limiter.py                # Two-layer sliding-window rate limiter
    audit/
      loggers.py                # 3 audit pipelines + sanitization
    backends/
      jira_backend.py           # Jira tools (read + write)
      bre_backend.py            # Business Rule Engine tools (stubs, not implemented)
      neo4j_backend.py          # Neo4j Knowledge Graph tools
      teradata_backend.py       # Teradata via MCP sidecar
  tests/                        # Unit test suite
  docs/                         # Architecture docs and whitepaper
  Dockerfile                    # Production container image
  docker-compose.yml            # Local dev environment
  pyproject.toml                # Build configuration
  requirements.txt              # Pinned dependencies
```

---

## Environment Variables

### Server
| Variable | Default | Description |
|---|---|---|
| `MCP_SERVER_PORT` | `8100` | Gateway HTTP port |
| `LOG_LEVEL` | `INFO` | Logging level |

### Authentication
| Variable | Default | Description |
|---|---|---|
| `JWT_AUTH_ENABLED` | `false` | Enable JWT bearer token validation |
| `JWT_SECRET` | _(empty)_ | Shared secret for JWT signing/validation |
| `JWT_ALGORITHMS` | `HS512` | Accepted JWT signing algorithms. Must stay within one key family (HMAC, RSA or EC); a mixed list is refused |
| `JWT_VERIFY_AUD` | `true` | Verify the `aud` claim. Requires `JWT_AUDIENCE` to be set |
| `JWT_AUDIENCE` | _(empty)_ | Expected audience; required when `JWT_VERIFY_AUD=true` |
| `JWT_ISSUER` | _(empty)_ | Expected issuer; always required, see the fail-closed note below |
| `JWT_CLAIM_USER_ID` | `sAMAccountName,sub` | Comma-separated candidate claim keys for user ID |
| `JWT_CLAIM_GROUPS` | `groups,roles` | Candidate claim keys for group membership |
| `KIRO_RBAC_ENABLED` | `true` | Require a gateway-signed token for IDE consumers |
| `GATEWAY_ALLOW_INSECURE_LOCAL` | `false` | Opt-in escape hatch for the legacy auto-whitelist. Also requires `KIRO_RBAC_ENABLED=false` and a loopback client |
| `GATEWAY_STDIO_TRUST_LOCAL` | `false` | Grant a local stdio caller (no AuthMiddleware, therefore no identity) unrestricted tool and project scope. Keep false for any HTTP deployment |
| `KIRO_TOKEN_TTL_HOURS` | `24` | Kiro token expiry in hours |

The token validator is fail-closed and the configuration check runs on every
validation, independently of `JWT_AUTH_ENABLED`. With `KIRO_RBAC_ENABLED=true`
(the default) the Mode 2 gateway-signed token is validated by the same code
path, so that mode requires `JWT_SECRET`, `JWT_ISSUER`, and either
`JWT_AUDIENCE` or `JWT_VERIFY_AUD=false`. Any other combination makes the
gateway refuse to validate tokens at all. This documents today's effective
behaviour rather than changing it: validation already failed on the empty
`JWT_SECRET` default.

### Rate Limiting
| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding window duration |
| `RATE_LIMIT_JIRA` | `30` | Global Jira calls per window |
| `RATE_LIMIT_DEFAULT` | `59` | Default group limit, enforced per pod (not a global cap) |
| `WRITE_RATE_LIMIT` | `5` | Max writes per consumer per write window |

### Backends
| Variable | Default | Description |
|---|---|---|
| `JIRA_BASE_URL` | `https://jira.example.com` | Jira REST API base URL |
| `JIRA_BACKEND` | `pat` | Backend mode: `pat`, `basic`, or `llm-orchestrator` |
| `NEO4J_ENABLED` | `true` | Enable Neo4j backend |
| `TERADATA_MCP_ENABLED` | `true` | Enable Teradata sidecar |
| `TERADATA_MCP_URL` | `http://localhost:8001/mcp` | Teradata sidecar URL |

### Encryption
| Variable | Default | Description |
|---|---|---|
| `ENCRYPTION_ENABLED` | `false` | Enable KMS envelope encryption |
| `KMS_KEY_ID` | `alias/enterprise-mcp-gateway-tokens` | AWS KMS CMK ARN or alias |

### DocumentDB
| Variable | Default | Description |
|---|---|---|
| `DOCDB_HOST` | `localhost` | MongoDB/DocumentDB host |
| `DOCDB_DATABASE` | `ENTERPRISE_MCP_GATEWAY` | Database name |
| `DOCDB_TLS_ENABLED` | `true` | Connect with TLS and full certificate validation. The DocumentDB/RDS CA bundle must be in the host trust store |

---

## Authentication Modes

### Mode 1: API Key + JWT Bearer Token
For service-to-service consumers (AI agents, REST clients):
```
X-MCP-API-Key: <consumer-api-key>
Authorization: Bearer <jwt-token>
```

### Mode 2: Kiro IDE RBAC (Gateway-Signed Token)
For IDE copilots authenticated via browser-based flow:
```
X-MCP-App-Name: kiro-username
X-MCP-Auth-Token: <gateway-signed-jwt>
```

### Mode 3: Legacy (Auto-Whitelist) - local development only, off by default
Disabled unless all three conditions hold: `GATEWAY_ALLOW_INSECURE_LOCAL=true`,
`KIRO_RBAC_ENABLED=false`, and the request arrives from a loopback peer with no
forwarding headers (`X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`,
`Forwarded`). The peer address is the immediate TCP peer, so in a deployment
where a reverse proxy or sidecar on the same host fronts the gateway and strips
forwarding headers, a remote caller would appear loopback - keep this flag off
anywhere behind a proxy. Any other request without a credential receives
HTTP 401.
```
X-MCP-App-Name: kiro-local
```

### stdio transport
`AuthMiddleware` only runs on the HTTP transport, so a tool call arriving over
stdio carries no caller identity. The absence of an identity is not a grant:
such calls are denied by the tool authorization guardrail (`forbidden` /
`tool_authorization`) unless `GATEWAY_STDIO_TRUST_LOCAL=true` is set, which
grants the local caller unrestricted tool and project scope and logs a warning
on every call.

### JSON-RPC error codes

An authentication failure on the MCP JSON-RPC endpoint (`/mcp` and
`/mcp/<...>`, excluding the public `/mcp/portal`, `/mcp/dashboard` and
`/mcp/api/` prefixes) is returned as HTTP 401 with a well-formed JSON-RPC 2.0
error object. The inbound request `id` is echoed when it is readable and is
`null` otherwise (batch array, notification, or an unreadable, oversized or
non-JSON body). The pre-existing machine-readable error key is preserved at
`error.data.error`, so consumers that already branch on it keep working.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "An API key is required. Set the X-MCP-API-Key header.",
    "data": {
      "error": "unauthorized",
      "message": "An API key is required. Set the X-MCP-API-Key header."
    }
  }
}
```

Gateway-defined codes, from the `-32000` to `-32099` range the specification
reserves for server-defined errors:

| Code | Condition | `error.data.error` |
|---|---|---|
| `-32001` | Authentication required: no credential presented | `unauthorized`, `kiro_auth_required` |
| `-32002` | Authentication failed: credential presented but rejected | `unauthorized` (unregistered key), `kiro_token_invalid` |
| `-32003` | Authorization precondition not met | `jwt_required` |

`-32002` overlaps a code MCP itself defines: the FastMCP layer returns
`-32002` with the message `Resource not found` on this same `/mcp` endpoint,
for example on a `resources/read` of an unregistered URI. The gateway keeps
its three codes in one contiguous block rather than renumbering around the
overlap, so do not branch on the code alone. The discriminators for a gateway
authentication failure are the HTTP `401` status, which the protocol-level
errors never carry, and the `error.data.error` key.

The standard codes `-32700` (parse error), `-32600` (invalid request),
`-32601` (method not found), `-32602` (invalid params) and `-32603` (internal
error) are produced by the FastMCP JSON-RPC layer, as are MCP-defined codes
such as the `-32002` above, so that list is not exhaustive; the gateway does
not override any of them and does not invent codes for conditions it never
detects.

Requests to any other path keep their plain `{"error": ..., "message": ...}`
body: wrapping a health check or a dashboard API response in a `jsonrpc`
object would misrepresent the protocol in use on that path. No error body
ever carries a stack trace, exception text, token or key material.

---

## Security Guardrails

Every tool invocation passes through 7 composable checks:

| # | Guardrail | Fail Mode | Description |
|---|---|---|---|
| 0 | Tool Active | Fail-open | Registry lookup; disabled tools blocked |
| 1 | Tool Authorization | Fail-closed | Consumer's allowed_tools whitelist |
| 2 | User Write Auth | Fail-closed | AD group gate for write operations |
| 3 | Write Attribution | Fail-closed | Personal PAT required for writes |
| 4 | JQL Validation | Fail-closed | Injection pattern blocking |
| 5 | SQL Read-Only | Fail-closed | DDL/DML blocking for Teradata |
| 6 | Project Scope | Fail-closed | Consumer project whitelist |
| 7 | Write Rate Limit | Fail-closed | Per-consumer mutation throttle |

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=gateway --cov-report=term-missing

# Run specific test module
pytest tests/test_guardrails.py -v
```

`requirements.txt` declares `starlette>=1.0,<2` and the suite is exercised
locally against `starlette 1.0.0`, where it reports zero warnings. A clean CI
install resolves a newer release in the same `1.x` line, which emits one
`StarletteDeprecationWarning` from `starlette.testclient` about its httpx
dependency. The warning comes from the test client, not from gateway code, and
no gate turns warnings into errors, so the suite passes either way; the
zero-warning property is a property of the local pin, not of the declared
range. The range is kept deliberately: the pure-ASGI middleware is written
against stable ASGI primitives and is expected to hold across `1.x`, and
pinning an upper bound the project has never needed would claim more than the
evidence supports.

---

## License

MIT

---

## Documentation

- [Technical Whitepaper](docs/Gateway_MCP_Technical_Paper.md) - Full architecture paper with threat model and academic mapping
- [Architecture Baseline](docs/MCP_Gateway_Architecture_Baseline.md) - Detailed discovery baseline with inventory tables
