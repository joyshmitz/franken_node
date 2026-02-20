# Claims Registry

All external product claims about franken_node must be registered here with links to verifier artifacts. Claims without evidence are not claims.

## Format

Each claim entry uses this structure:

```
### CLAIM-<ID>: <Short Title>
- **Category**: compatibility | security | performance | resilience | migration
- **Claim**: <Exact claim text>
- **Evidence artifacts**: <path(s) to verification evidence>
- **Verification command**: <command to reproduce>
- **Last verified**: <ISO 8601 timestamp>
- **Status**: verified | pending | stale
```

## Registered Claims

_No external claims registered yet. Claims will be added as capabilities are implemented and verified._

<!--
Example entry (uncomment and fill when first claim is ready):

### CLAIM-001: Node.js Compatibility Target
- **Category**: compatibility
- **Claim**: franken_node achieves >=95% pass rate on targeted Node.js compatibility corpus.
- **Evidence artifacts**: artifacts/section_X/bd-XXX/verification_evidence.json
- **Verification command**: python3 scripts/check_compatibility.py --json
- **Last verified**: 2025-XX-XXTXX:XX:XX+00:00
- **Status**: pending
-->
