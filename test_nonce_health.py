# Tests for nonce health monitor, uses only tempfile fixtures.
import hashlib
import json
import tempfile
import unittest
import ed25519
import nonce_health

PUB1 = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
SIG1 = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555ed652f0737895d3d424b6822b8873c20262b0bd4d27b4a92c7f3de0d4f'
MSG1_HEX = ''

PUB3 = '3d4017c3e843895a92b70a74d1b7e7c9c582ccf744ab5f3c6452b4d4934c0b'
MSG3_HEX = 'af82'
SIG3 = '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'

class TestParseCheck(unittest.TestCase):
    def test_parse_and_reused(self):
        a1 = {'did': 'did:ex:alice', 'seq': 1, 'nonce': '111', 'timestamp': 100}
        a2 = {'did': 'did:ex:alice', 'seq': 2, 'nonce': '111', 'timestamp': 101}
        b1 = {'did': 'did:ex:bob', 'seq': 1, 'nonce': '999', 'timestamp': 102}
        text = json.dumps(a1) + chr(10) + json.dumps(a2) + chr(10) + json.dumps(b1)
        entries = nonce_health.parse_jsonl_text(text)
        self.assertEqual(len(entries), 3)
        res = nonce_health.check_nonces(entries, window=10)
        self.assertEqual(len(res['reused']), 1)
        self.assertEqual(res['reused'][0]['did'], 'did:ex:alice')
        self.assertEqual(res['by_did']['did:ex:alice'], 2)

    def test_regressed_and_cross(self):
        a1 = {'did': 'did:ex:alice', 'seq': 5, 'nonce': 'aaa'}
        a2 = {'did': 'did:ex:alice', 'seq': 3, 'nonce': 'bbb'}
        b1 = {'did': 'did:ex:bob', 'seq': 1, 'nonce': 'aaa'}
        text = json.dumps(a1) + chr(10) + json.dumps(a2) + chr(10) + json.dumps(b1)
        entries = nonce_health.parse_jsonl_text(text)
        res = nonce_health.check_nonces(entries, window=2)
        self.assertEqual(len(res['regressed']), 1)
        self.assertEqual(len(res['cross_account']), 1)
        self.assertEqual(res['cross_account'][0]['nonce'], 'aaa')

    def test_sanitize_drops_secrets(self):
        raw = {'did': 'did:ex:alice', 'nonce': '123', 'secret_seed': 'zzz', 'private_key': 'yyy'}
        clean = nonce_health.sanitize_record(raw)
        self.assertIn('did', clean)
        self.assertNotIn('secret_seed', clean)
        self.assertNotIn('private_key', clean)

class TestVerify(unittest.TestCase):
    def test_rfc_empty(self):
        pub = bytes.fromhex(PUB1)
        sig = bytes.fromhex(SIG1)
        self.assertTrue(ed25519.verify(pub, b'', sig))

    def test_rfc_af82(self):
        pub = bytes.fromhex(PUB3)
        msg = bytes.fromhex(MSG3_HEX)
        sig = bytes.fromhex(SIG3)
        self.assertTrue(ed25519.verify(pub, msg, sig))

    def test_tampered_fails(self):
        pub = bytes.fromhex(PUB1)
        sig = bytearray(bytes.fromhex(SIG1))
        sig[0] = (sig[0] + 1) % 256
        self.assertFalse(ed25519.verify(pub, b'', bytes(sig)))

    def test_batch_harness(self):
        items = [{'pubkey_hex': PUB1, 'message_hex': MSG1_HEX, 'signature_hex': SIG1}, {'pubkey_hex': PUB1, 'message_hex': '00', 'signature_hex': SIG1}]
        out = nonce_health.verify_batch(items, rate_limit_per_sec=5000.0, base_delay=0.001, simulate_hit_every=0)
        self.assertEqual(out['passed'], 1)
        self.assertEqual(out['failed'], 1)
        self.assertEqual(len(out['results']), 2)

class TestProbeExplain(unittest.TestCase):
    def test_probe(self):
        res = nonce_health.probe_throughput(num_ops=20, payload_size=32)
        self.assertGreater(res['ops_per_sec'], 0)
        self.assertIn('p95_latency', res)
        self.assertGreaterEqual(res['p95_latency'], 0)

    def test_explain_status(self):
        r = nonce_health.explain_id('404')
        self.assertEqual(r['likely'], 'status_code')

    def test_explain_seq(self):
        r = nonce_health.explain_id('42')
        self.assertEqual(r['likely'], 'seq')

    def test_explain_nonce(self):
        r = nonce_health.explain_id('18446744073709551615')
        self.assertEqual(r['likely'], 'nonce')

    def test_explain_with_context(self):
        r = nonce_health.explain_id('7', seq_examples=['7'], nonce_examples=['9999999999'])
        self.assertEqual(r['likely'], 'seq')

class TestReportFile(unittest.TestCase):
    def test_report_and_tempfile(self):
        a1 = {'did': 'did:ex:alice', 'seq': 1, 'nonce': 'n1'}
        b1 = {'did': 'did:ex:bob', 'seq': 1, 'nonce': 'n2'}
        text = json.dumps(a1) + chr(10) + json.dumps(b1)
        with tempfile.TemporaryDirectory() as td:
            p = td + '/input.jsonl'
            with open(p, 'w', encoding='utf-8') as f:
                f.write(text)
            entries = nonce_health.parse_jsonl_file(p)
            self.assertEqual(len(entries), 2)
            check = nonce_health.check_nonces(entries)
            items = [{'pubkey_hex': PUB1, 'message_hex': MSG1_HEX, 'signature_hex': SIG1}]
            vres = nonce_health.verify_batch(items, rate_limit_per_sec=5000.0)
            probe = nonce_health.probe_throughput(num_ops=10)
            exps = [nonce_health.explain_id('200')]
            rep = nonce_health.generate_report(entries, check, vres, probe, exps, ['check', 'verify'])
            self.assertIn('sha256', rep)
            j = nonce_health.report_to_json(rep)
            m = nonce_health.report_to_markdown(rep)
            self.assertIn('sha256', j)
            self.assertIn('Nonce', m)
            outp = td + '/report.json'
            with open(outp, 'w', encoding='utf-8') as f:
                f.write(j)
            with open(outp, 'r', encoding='utf-8') as f:
                back = f.read()
            self.assertEqual(back, j)

if __name__ == '__main__':
    unittest.main()
