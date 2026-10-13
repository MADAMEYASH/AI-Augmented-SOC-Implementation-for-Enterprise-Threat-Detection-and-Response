# AegisSOC Enterprise — Production Deployment & Architecture Guide

AegisSOC is an enterprise-grade AI-Augmented Security Operations Center (SOC) integrating:
- **Relational Persistence**: Cloud SQL PostgreSQL with connection pooling and schema migrations.
- **Authentication & RBAC**: Google OAuth / Firebase ID token validation with Tiered Roles (`admin`, `analyst`, `auditor`).
- **SIEM Ingestion Engine**: Splunk HTTP Event Collector (`/api/siem/splunk-hec`) and Elastic Bulk (`/api/siem/ingest`) streaming with automated correlation.
- **Incident Response Platform**: Sophos Central API and Shuffle SOAR playbook execution protected by Tier-0 Approval Gates.
- **Diagnostics & Audit Trail**: Real-time `/api/health`, cryptographic audit logging, and automated test suite runner (`/api/tests/run`).

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Enterprise Telemetry Sources     |
                      | (Splunk HEC, Elastic, Syslog, Zeek)  |
                      +-------------------+-------------------+
                                          |
                              JSON / HEC Stream (HTTPS)
                                          v
                      +---------------------------------------+
                      |        AegisSOC Express API           |
                      |   - Rate Limiting (express-rate-limit)|
                      |   - Zod Schema Validation             |
                      |   - Firebase Bearer Token RBAC        |
                      +-------------------+-------------------+
                                          |
                        +-----------------+-----------------+
                        |                                   |
                        v                                   v
          +---------------------------+       +---------------------------+
          | Cloud SQL (PostgreSQL 16) |       | Sophos Central & Shuffle  |
          |  - security_logs          |       |  - Network Isolation API  |
          |  - security_alerts        |       |  - SOAR Playbook Runners  |
          |  - incident_actions       |       |  - Tier-0 Approval Gates  |
          |  - audit_logs             |       +---------------------------+
          |  - users & RBAC           |
          +---------------------------+
```

---

## 5-Phase Production Capabilities

### Phase 1 — Real Backend Foundation
- **Database**: Cloud SQL PostgreSQL managed through Drizzle ORM (`src/db/schema.ts`).
- **Connection Pool**: Lazy `pg.Pool` with idle error trapping and zero startup loops.
- **Validation**: Strict runtime validation using `zod`.
- **Health Endpoint**: `GET /api/health` reports PostgreSQL connectivity, latency in ms, table row counts, and uptime.

### Phase 2 — Authentication & Security
- **Identity Provider**: Google OAuth / Firebase Auth token validation (`src/middleware/auth.ts`).
- **Role-Based Access Control**:
  - `admin`: Can approve critical containment actions, elevate user permissions, and trigger destructive playbooks.
  - `analyst`: Can ingest telemetry, run hunts, and request containment actions.
  - `auditor`: Read-only access to audit trail and compliance matrices.
- **Rate Limiting**: Tiered limits protecting public endpoints against alert fatigue and denial-of-service.
- **Audit Logging**: Every incident update, containment action, and role change writes to `audit_logs`.

### Phase 3 — Real SIEM Data
- **Splunk HEC**: `POST /api/siem/splunk-hec` accepts standard Splunk events with sourcetype parsing.
- **Elasticsearch Ingest**: `POST /api/siem/ingest` accepts single or batch events, assigns clusters, and auto-generates critical alerts.
- **Aggregated Metrics**: `GET /api/siem/stats` calculates live Events Per Second (EPS) over rolling 60-second database windows.

### Phase 4 — Real Incident Response & Approval Gates
- **Sophos Central Host Containment**: Network isolation commands dispatched to agent interfaces.
- **Shuffle SOAR Playbook Dispatcher**: Webhook runners with step-by-step audit logs.
- **Approval Gate**: Containment actions targeting critical Tier-0 assets (e.g. Domain Controllers `DC-*`, production databases) enter `pending_approval` until signed off by a SOC Administrator.
- **Safe Simulation Mode**: Operators can toggle `SAFE SIM` in the UI to safely test attack paths without altering production network states.

### Phase 5 — Production Readiness & Testing
- **Automated Test Suite**: Triggerable via `POST /api/tests/run` or via the **OPS & HEALTH** button in the header. Validates database connectivity, ingestion pipeline, response actions, audit trail, and AI engine.
- **Docker Deployment**: Multi-stage `Dockerfile` and `docker-compose.yml` included.
