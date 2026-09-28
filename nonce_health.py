# Public nonce collision and signature health monitor.
# Uses only public DIDs, nonces, signatures. No secrets.
import hashlib
import json
import time
import tracemalloc
import ed25519

SECRET_HINTS = ('secret', 'private', 'seed', 'password', 'token', 'mnemonic')

def sanitize_record(raw):
    out = {}
    for k, v in raw.items():
        low = str(k).lower()
        if 'public' in low:
            out[k] = v
            continue
        skip = False
        for hint in SECRET_HINTS:
            if hint in low:
                skip = True
                break
        if skip:
            continue
        out[k] = v
    return out

def _to_int(v):
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s == '':
            return None
        core = s[1:] if s.startswith('-') else s
        if core.isdigit():
            try:
                return int(s)
            except ValueError:
                return None
    return None

def _extract_did(raw):
    for k in ('did', 'account', 'identity', 'pubkey', 'public_key', 'public_did'):
        if k in raw and raw[k] is not None:
            return str(raw[k])
    return 'unknown'

def _extract_seq(raw):
    for k in ('seq', 'sequence', 'seq_no', 'seqno'):
        if k in raw:
            iv = _to_int(raw[k])
            if iv is not None:
                return iv
    return None

def _extract_nonce(raw):
    for k in ('nonce', 'public_nonce', 'counter', 'nonce_value', 'nonce_hex'):
        if k in raw and raw[k] is not None:
            return raw[k]
    return None

def _extract_ts(raw):
    for k in ('timestamp', 'ts', 'time'):
        if k in raw:
            return raw[k]
    return None

def parse_jsonl_text(text):
    entries = []
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        try:
            raw = json.loads(s)
        except ValueError:
            continue
        if not isinstance(raw, dict):
            continue
        clean = sanitize_record(raw)
        did = _extract_did(clean)
        seq = _extract_seq(clean)
        nonce = _extract_nonce(clean)
        ts = _extract_ts(clean)
        entries.append({'did': did, 'seq': seq, 'timestamp': ts, 'nonce': nonce, 'line_no': idx + 1, 'raw': clean})
    return entries

def parse_jsonl_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    return parse_jsonl_text(text)

def check_nonces(entries, window=100):
    by_did = {}
    seen = {}
    global_map = {}
    reused = []
    regressed = []
    max_seq = {}
    for idx, e in enumerate(entries):
        did = str(e.get('did', 'unknown'))
        seq = e.get('seq')
        nonce = e.get('nonce')
        by_did[did] = by_did.get(did, 0) + 1
        if nonce is not None:
            nkey = str(nonce)
            key = did + '|' + nkey
            if key in seen:
                reused.append({'did': did, 'nonce': nkey, 'first': seen[key], 'second': idx, 'confidence': 'high', 'guidance': 'same nonce twice for one DID; check replay or log duplication'})
            else:
                seen[key] = idx
            if nkey not in global_map:
                global_map[nkey] = set()
            global_map[nkey].add(did)
        if isinstance(seq, int) and not isinstance(seq, bool):
            if did in max_seq and seq <= max_seq[did]:
                regressed.append({'did': did, 'seq': seq, 'prev_max': max_seq[did], 'index': idx, 'confidence': 'medium', 'guidance': 'seq did not rise; check sync order, clock skew or log gaps'})
            if did not in max_seq or seq > max_seq[did]:
                max_seq[did] = seq
    cross = []
    for nkey, dids in global_map.items():
        if len(dids) > 1:
            cross.append({'nonce': nkey, 'dids': sorted(dids), 'confidence': 'high', 'guidance': 'one public nonce on many accounts; fix deterministic generator'})
    if window <= 0:
        if entries:
            window = len(entries)
        else:
            window = 100
    if len(entries) > window:
        recent = entries[-window:]
    else:
        recent = entries
    window_counts = {}
    for e in recent:
        d = str(e.get('did', 'unknown'))
        window_counts[d] = window_counts.get(d, 0) + 1
    return {'total': len(entries), 'by_did': by_did, 'reused': reused, 'regressed': regressed, 'cross_account': cross, 'window': window, 'window_counts': window_counts}

def verify_batch(items, rate_limit_per_sec=1000.0, base_delay=0.01, simulate_hit_every=0):
    results = []
    passed = 0
    failed = 0
    retries = 0
    timings = []
    batch_start = time.perf_counter()
    min_gap = 0.0
    if rate_limit_per_sec and rate_limit_per_sec > 0:
        min_gap = 1.0 / float(rate_limit_per_sec)
    last_end = batch_start
    for idx, it in enumerate(items):
        now = time.perf_counter()
        want = last_end + min_gap
        if want > now:
            time.sleep(want - now)
        if simulate_hit_every and simulate_hit_every > 0 and idx > 0 and idx % simulate_hit_every == 0:
            time.sleep(base_delay)
            retries += 1
        t0 = time.perf_counter()
        ok = False
        err = None
        try:
            pub_hex = it.get('pubkey_hex', '')
            sig_hex = it.get('signature_hex', '')
            if 'message_hex' in it:
                msg_hex = it.get('message_hex', '')
                if msg_hex:
                    msg = bytes.fromhex(msg_hex)
                else:
                    msg = b''
            elif 'message' in it:
                m = it.get('message')
                if isinstance(m, str):
                    msg = m.encode('utf-8')
                else:
                    msg = bytes(m)
            else:
                msg = b''
            pub = bytes.fromhex(pub_hex)
            sig = bytes.fromhex(sig_hex)
            ok = ed25519.verify(pub, msg, sig)
        except Exception as ex:
            ok = False
            err = str(ex)[:200]
        t1 = time.perf_counter()
        lat = t1 - t0
        timings.append(lat)
        last_end = time.perf_counter()
        if ok:
            passed += 1
        else:
            failed += 1
        results.append({'index': idx, 'ok': ok, 'latency': lat, 'error': err})
    total_time = time.perf_counter() - batch_start
    return {'results': results, 'passed': passed, 'failed': failed, 'retries': retries, 'timings': timings, 'total_time': total_time}

def probe_throughput(num_ops=200, payload_size=32):
    if num_ops <= 0:
        num_ops = 1
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    start_cur, start_peak = tracemalloc.get_traced_memory()
    lat = []
    store = {}
    t_start = time.perf_counter()
    for i in range(num_ops):
        t0 = time.perf_counter()
        data = ('probe-' + str(i)).encode('utf-8')
        digest = hashlib.sha256(data).digest()
        key = digest[:8].hex()
        store[key] = i
        _ = len(store)
        t1 = time.perf_counter()
        lat.append(t1 - t0)
    t_end = time.perf_counter()
    end_cur, end_peak = tracemalloc.get_traced_memory()
    if not was_tracing:
        tracemalloc.stop()
    total = t_end - t_start
    if total <= 0:
        total = 0.000001
    ops = float(num_ops) / total
    ordered = sorted(lat)
    p95_idx = int(0.95 * len(ordered))
    if p95_idx >= len(ordered):
        p95_idx = len(ordered) - 1
    p95 = ordered[p95_idx]
    avg = sum(ordered) / len(ordered)
    mem_growth = end_cur - start_cur
    if mem_growth < 0:
        mem_growth = 0
    return {'num_ops': num_ops, 'total_time': total, 'ops_per_sec': ops, 'p95_latency': p95, 'avg_latency': avg, 'memory_current': end_cur, 'memory_growth': mem_growth, 'peak': end_peak}

def explain_id(text, seq_examples=None, nonce_examples=None):
    raw = str(text)
    s = raw.strip()
    if seq_examples is None:
        seq_examples = []
    if nonce_examples is None:
        nonce_examples = []
    seq_set = set([str(x).strip() for x in seq_examples])
    nonce_set = set([str(x).strip() for x in nonce_examples])
    base_guidance = 'compare with public log: seq rises per DID, nonce is large, status code is 3 digit HTTP'
    if not s:
        return {'input': raw, 'likely': 'unknown', 'confidence': 'low', 'reasons': ['empty input'], 'guidance': base_guidance}
    core = s[1:] if s.startswith('-') else s
    if s.startswith('-'):
        return {'input': raw, 'likely': 'unknown-negative', 'confidence': 'low', 'reasons': ['negative numbers are not valid nonce or status code'], 'guidance': base_guidance}
    if not core.isdigit():
        return {'input': raw, 'likely': 'not-numeric', 'confidence': 'medium', 'reasons': ['contains non digit chars'], 'guidance': base_guidance}
    try:
        n = int(s)
    except ValueError:
        return {'input': raw, 'likely': 'not-numeric', 'confidence': 'medium', 'reasons': ['parse failed'], 'guidance': base_guidance}
    score_status = 0
    score_seq = 0
    score_nonce = 0
    reasons = []
    if 100 <= n <= 599 and len(s) == 3:
        score_status += 3
        reasons.append('3 digit in 100-599 matches HTTP status range')
    elif 100 <= n <= 599:
        score_status += 1
        reasons.append('in 100-599 but length is not 3')
    if 0 <= n < 10000000:
        score_seq += 2
        reasons.append('small value fits seq range')
    if len(s) >= 10 or n >= 4294967296:
        score_nonce += 2
        reasons.append('long or large value fits nonce range')
    if s in seq_set:
        score_seq += 3
        reasons.append('found in seq examples')
    if s in nonce_set:
        score_nonce += 3
        reasons.append('found in nonce examples')
    common = (200, 201, 400, 401, 403, 404, 429, 500, 502, 503)
    if n in common and len(s) == 3:
        score_status += 1
        reasons.append('matches common status code')
    best = score_status
    if score_seq > best:
        best = score_seq
    if score_nonce > best:
        best = score_nonce
    likely = 'ambiguous'
    conf = 'low'
    if best == 0:
        reasons.append('no strong signal')
    elif score_status == best and score_seq != best and score_nonce != best:
        likely = 'status_code'
        if best >= 3:
            conf = 'high'
        else:
            conf = 'medium'
    elif score_seq == best and score_status != best and score_nonce != best:
        likely = 'seq'
        if best >= 3:
            conf = 'high'
        else:
            conf = 'medium'
    elif score_nonce == best and score_status != best and score_seq != best:
        likely = 'nonce'
        if best >= 3:
            conf = 'high'
        else:
            conf = 'medium'
    else:
        reasons.append('scores tie; need public context')
    return {'input': raw, 'likely': likely, 'confidence': conf, 'reasons': reasons, 'scores': {'status_code': score_status, 'seq': score_seq, 'nonce': score_nonce}, 'guidance': base_guidance}

def generate_report(entries, check_result, verify_result, probe_result, explanations, command_log):
    canon = json.dumps(entries, sort_keys=True, default=str)
    sha = hashlib.sha256(canon.encode('utf-8')).hexdigest()
    summary = {'sha256': sha, 'total_entries': len(entries), 'check': check_result, 'verify_summary': {'passed': verify_result.get('passed', 0), 'failed': verify_result.get('failed', 0), 'retries': verify_result.get('retries', 0), 'total_time': verify_result.get('total_time', 0)}, 'probe': probe_result, 'explanations': explanations, 'command_log': list(command_log)}
    return summary

def report_to_json(report):
    return json.dumps(report, indent=2, sort_keys=True, default=str)

def report_to_markdown(report):
    lines = []
    lines.append('# Nonce and signature health report')
    lines.append('')
    lines.append('SHA256: ' + str(report.get('sha256', '')))
    lines.append('')
    lines.append('Entries: ' + str(report.get('total_entries', 0)))
    lines.append('')
    check = report.get('check', {})
    lines.append('## Nonce check')
    lines.append('')
    lines.append('Total: ' + str(check.get('total', 0)))
    lines.append('Reused: ' + str(len(check.get('reused', []))))
    lines.append('Regressed: ' + str(len(check.get('regressed', []))))
    lines.append('Cross account: ' + str(len(check.get('cross_account', []))))
    lines.append('')
    vs = report.get('verify_summary', {})
    lines.append('## Verify')
    lines.append('')
    lines.append('Passed: ' + str(vs.get('passed', 0)))
    lines.append('Failed: ' + str(vs.get('failed', 0)))
    lines.append('Retries: ' + str(vs.get('retries', 0)))
    lines.append('')
    probe = report.get('probe', {})
    ops = float(probe.get('ops_per_sec', 0))
    lines.append('## Probe')
    lines.append('')
    lines.append('Ops per sec: ' + str(round(ops, 2)))
    lines.append('P95 latency: ' + str(probe.get('p95_latency', 0)))
    lines.append('')
    lines.append('## Commands')
    lines.append('')
    for c in report.get('command_log', []):
        lines.append('- ' + str(c))
    lines.append('')
    return chr(10).join(lines)
