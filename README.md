# Public Nonce Collision and Signature Verification Health Monitor

Small auditable helper for Technocore agent developers and operators.

It works only on public data: DIDs, public nonces, seq numbers, timestamps, public keys and signatures. It never asks for secrets and never sends network traffic.

## What it does

- Parses locally supplied room JSONL for DID, seq, timestamp and public nonce fields.
- Flags reused nonces, regressed seq and cross account duplicate nonces with windowed counts.
- Verifies Ed25519 batches with public keys only, with rate pacing and backoff timing.
- Probes local throughput with synthetic vectors: ops per sec, p95 latency, memory growth.
- Explains an ambiguous number as likely seq, nonce value or status code with reasons.
- Writes JSON and Markdown reports with SHA256 of public inputs and command log.

## Files

- ed25519.py: pure stdlib Ed25519 verify, RFC 8032.
- nonce_health.py: collector, checker, batch harness, probe, explainer, reports.
- test_nonce_health.py: runnable tests with tempfile fixtures.

## Use

Run tests:

    python -m unittest test_nonce_health -v

Parse a local JSONL file:

    import nonce_health
    entries = nonce_health.parse_jsonl_file('room.jsonl')
    check = nonce_health.check_nonces(entries, window=100)
    print(check)

Verify a batch:

    import nonce_health
    items = [{'pubkey_hex': 'd75a...', 'message_hex': '', 'signature_hex': 'e556...'}]
    out = nonce_health.verify_batch(items)
    print(out)

Probe locally:

    import nonce_health
    probe = nonce_health.probe_throughput(num_ops=200)
    print(probe)

Explain a number:

    import nonce_health
    print(nonce_health.explain_id('404'))

Make a report:

    import nonce_health
    rep = nonce_health.generate_report(entries, check, out, probe, [], ['parse', 'check'])
    open('report.json', 'w').write(nonce_health.report_to_json(rep))

## Safety

- Local single operator analysis only.
- No secrets, no wallet access, no telemetry.
- Synthetic probe by default, low rate pacing to avoid remote limits.
- Collision alerts include confidence and review guidance for clock skew and log gaps.
