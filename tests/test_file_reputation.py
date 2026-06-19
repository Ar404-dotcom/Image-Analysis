import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from file_reputation import (
    DEMO_CLEAN_SHA256,
    build_reputation_report,
    calculate_hashes,
    demo_reputation_report,
    query_virustotal_hash,
    shannon_entropy,
    verdict_from_reputation,
)


class FileReputationTests(unittest.TestCase):
    def test_calculate_hashes_returns_common_hashes(self):
        hashes = calculate_hashes(b"abc")

        self.assertEqual(hashes["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(hashes["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(hashes["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_entropy_is_zero_for_empty_or_repeated_bytes(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"\x00" * 16), 0.0)

    def test_missing_api_key_does_not_query_virustotal(self):
        result = query_virustotal_hash("0" * 64, api_key="")

        self.assertFalse(result["queried"])
        self.assertIn("No API key", result["error"])

    def test_verdict_marks_many_malicious_hits_as_known_malicious(self):
        hashes = {"sha256": "0" * 64}
        signature = {"status": "UNKNOWN"}
        online = {"stats": {"malicious": 7, "suspicious": 0}}

        verdict = verdict_from_reputation(hashes, signature, online)

        self.assertEqual(verdict["label"], "Known malicious")
        self.assertEqual(verdict["severity"], "CRITICAL")

    def test_demo_reputation_report_is_clean_and_uses_demo_hash(self):
        report = demo_reputation_report()

        self.assertEqual(report["hashes"]["sha256"], DEMO_CLEAN_SHA256)
        self.assertEqual(report["verdict"]["label"], "Demo authentic")
        self.assertEqual(report["verdict"]["severity"], "CLEAN")

    def test_build_report_without_online_lookup_is_unknown_for_arbitrary_unsigned_data(self):
        report = build_reputation_report(b"not signed", "sample.bin", query_online=False)

        self.assertEqual(report["online_reputation"]["queried"], False)
        self.assertEqual(report["verdict"]["severity"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
