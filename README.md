# Enterprise MCP Gateway

**Multi-Tenant Model Context Protocol Gateway with Dynamic RBAC, Multi-Backend Integration, and Defense-in-Depth Observability**

An enterprise-grade MCP server that mediates AI agent and IDE copilot access to backend systems through a unified, governed interface with authentication, authorization, rate limiting, audit logging, and encryption.

---

## Key Metrics

| Metric | Value |
|---|---|
| MCP Tools | 39 (Jira, BRE, Neo4j, Teradata, built-in) |
| Backend Systems | 7 (Jira, BRE/RDS, Neo4j, Teradata, DocumentDB, SQL Server, LLM Orchestrator) |
| Authentication Modes | 3 (API Key + JWT, Kiro RBAC, Legacy) |
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
      bre_backend.py            # Business Rule Engine tools
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
| `JWT_ALGORITHMS` | `HS512,HS256,RS256` | Accepted JWT signing algorithms |
| `JWT_CLAIM_USER_ID` | `sAMAccountName,sub` | Comma-separated candidate claim keys for user ID |
| `JWT_CLAIM_GROUPS` | `groups,roles` | Candidate claim keys for group membership |
| `KIRO_RBAC_ENABLED` | `false` | Enable gateway-signed token RBAC for IDE consumers |
| `KIRO_TOKEN_TTL_HOURS` | `24` | Kiro token expiry in hours |

### Rate Limiting
| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding window duration |
| `RATE_LIMIT_JIRA` | `30` | Global Jira calls per window |
| `RATE_LIMIT_DEFAULT` | `59` | Default group limit (one under Jira's 60 burst) |
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

### Mode 3: Legacy (Auto-Whitelist)
For local development (no authentication required):
```
X-MCP-App-Name: kiro-local
```

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

---

## License

MIT

---

## Documentation

- [Technical Whitepaper](docs/Gateway_MCP_Technical_Paper.md) - Full architecture paper with threat model and academic mapping
- [Architecture Baseline](docs/MCP_Gateway_Architecture_Baseline.md) - Detailed discovery baseline with inventory tables
