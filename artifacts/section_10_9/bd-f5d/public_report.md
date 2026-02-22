# Public Benchmark Campaign Report

| Workload | p95 Latency Delta % (franken_node) | Throughput Delta % (franken_node) |
|---|---:|---:|
| child_process_spawning | -3.2 | 2.941 |
| cold_start | -3.953 | 4.774 |
| compatibility_shim_overhead | -6.522 | 3.835 |
| crypto_operations | -7.018 | 2.758 |
| file_io | -4.403 | 4.626 |
| http_server_throughput | -3.053 | 3.495 |
| json_processing | -2.817 | 2.652 |
| module_loading | -3.483 | 6.338 |
| stream_throughput | -3.96 | 2.809 |
| url_parsing | -5.882 | 1.499 |

## Category-Defining Targets
- Compatibility >=95%: PASS
- Migration velocity >=3x: PASS
- Compromise reduction >=10x: PASS
