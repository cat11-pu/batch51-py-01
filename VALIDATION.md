# Validation Record

Environment: Python 3.14.4. The system interpreter does not have pytest
installed, so the official suite was run with pytest 9.2.0 supplied by `uv`.

## Official tests

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest python3 -m pytest -q tests
```

Result:

```text
...............                                                          [100%]
15 passed in 0.01s
```

The existing files under `tests/` were not modified.

## Extended local scenarios

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 verify_dns_tcp_pipeline.py
```

Result:

```text
out_of_order: ok [(2, 'b.example'), (1, 'a.example')]
case_insensitive: ok Delivery(conn_id='c1', qid=3, qname='MiXeD.Example', qtype=1, status='delivered')
compression_pointer: ok Delivery(conn_id='c1', qid=4, qname='compressed.example', qtype=1, status='delivered')
timeout_id_reuse: ok unmatched delivered
half_close_partial: ok pending=3, no bogus delivery
snapshot_restore: ok Delivery(conn_id='c1', qid=12, qname='snap.example', qtype=1, status='delivered') {'queries': 1, 'delivered': 1, 'duplicates': 0, 'unmatched': 0, 'timeouts': 0, 'idle_closed': 0, 'frame_errors': 0}
concurrent_duplicate: ok ['delivered', 'duplicate']
concurrent_feed_close: ok (100 iterations)
all_extended_scenarios: ok
```

An additional local boundary check covered exact query/idle deadlines, all
frame failure classes, reused IDs, close-time servfail delivery, malformed
snapshot atomicity, and 200 `feed`/`close_connection` races.

## Change summary

- Added strict two-byte framing for `accept_response` and a byte-bounded stream
  parser for `feed`; oversize, zero-length, and mismatched frames close the
  connection and increment `frame_errors`.
- Matched responses by `(qid, lower(qname), qtype)`, including compressed DNS
  question names, rather than by arrival order.
- Kept per-connection in-flight and last-delivery state so duplicates are
  reported once, while timeout-released IDs can be reused without accepting a
  late response for the new query.
- Added lock-protected feed, response, close, expiration, and snapshot paths;
  half-close drains complete frames while retaining an incomplete tail.
- Versioned, detached snapshots preserve configuration, connections, pending
  bytes, in-flight IDs, delivery state, ticket sequence, and exact counters.
  Restore validates before assignment, making invalid restores atomic.
