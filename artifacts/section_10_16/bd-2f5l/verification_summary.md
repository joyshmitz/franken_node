# bd-2f5l: fastapi_rust Service Skeleton

**Section:** 10.16 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust API module tests | 73 | 73 |
| Rust conformance tests | 38 | 38 |
| Python verification checks | 109 | 109 |
| Python unit tests | 29 | 29 |

## Implementation (src/api/)

### Modules Created

| Module | Purpose |
|--------|---------|
| `error.rs` | RFC 7807 ProblemDetail, ApiError enum, FRANKEN_* → HTTP mapping |
| `middleware.rs` | TraceContext, Auth, Authz, RateLimiter, middleware chain executor |
| `operator_routes.rs` | 4 operator endpoints with handlers and route metadata |
| `verifier_routes.rs` | 3 verifier endpoints with handlers and route metadata |
| `fleet_control_routes.rs` | 5 fleet-control endpoints with handlers and route metadata |
| `service.rs` | ControlPlaneService, endpoint catalog, coverage check, report |

### Event Codes

FASTAPI_SERVICE_START, FASTAPI_REQUEST_RECEIVED, FASTAPI_AUTH_SUCCESS, FASTAPI_AUTH_FAIL, FASTAPI_POLICY_DENY, FASTAPI_RATE_LIMITED, FASTAPI_ENDPOINT_ERROR, FASTAPI_RESPONSE_SENT

## Endpoint Coverage

| Group | Count | Auth Method | Paths |
|-------|-------|-------------|-------|
| Operator | 4 | ApiKey (health: None) | status, health, config, rollout |
| Verifier | 3 | BearerToken | conformance, evidence/{id}, audit-log |
| Fleet Control | 5 | BearerToken + MtlsClientCert | leases (GET/POST/DELETE), fence, coordinate |
| **Total** | **12** | — | All under `/v1/` |

## Middleware Pipeline

All 6 layers wired: TraceContext → Authentication → Authorization → RateLimit → Handler → Response+Telemetry

Rate limiting: operator 100rps/200burst, verifier 50rps/100burst, fleet 20rps/40burst (fail-closed).

## Contract Compliance

- bd-3ndj dependency satisfied (all endpoint groups, auth, policy hooks, middleware per contract)
- RFC 7807 error formatting with FRANKEN_* error registry integration
- W3C traceparent propagation on all routes
- All paths explicitly versioned (`/v1/`)
