import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malware_scanner import MalwareScanner
from tests.corpus_manifest import SAFE_IMAGE_CORPUS, SUSPICIOUS_IMAGE_CORPUS, TEXT_CORPUS


class CorpusRegressionTests(unittest.TestCase):
    def setUp(self):
        self.scanner = MalwareScanner()

    def scan_path(self, path):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = self.scanner.scan_file(str(path))
        return result

    def test_safe_image_corpus_is_clean(self):
        for image_path in SAFE_IMAGE_CORPUS:
            with self.subTest(image=image_path.name):
                result = self.scan_path(image_path)
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["risk_level"], "CLEAN - NO SIGNIFICANT THREATS")

    def test_suspicious_image_corpus_retains_structural_findings(self):
        for sample in SUSPICIOUS_IMAGE_CORPUS:
            with self.subTest(image=sample["path"].name):
                result = self.scan_path(sample["path"])
                finding_types = {finding["type"] for finding in result["findings"]}

                self.assertTrue(sample["required_types"] & finding_types)
                self.assertGreater(result["risk_score"], 0)
                self.assertGreater(result["evidence_summary"]["validated binary structure"], 0)

    def test_text_corpus_expectations_hold(self):
        for sample in TEXT_CORPUS:
            with self.subTest(text=sample["path"].name):
                result = self.scan_path(sample["path"])
                finding_types = {finding["type"] for finding in result["findings"]}

                if not sample["required_types"]:
                    self.assertEqual(result["findings"], [])
                else:
                    self.assertTrue(sample["required_types"] & finding_types)

                if "expected_risk" in sample:
                    self.assertEqual(result["risk_level"], sample["expected_risk"])
                if "expected_risk_not" in sample:
                    self.assertNotEqual(result["risk_level"], sample["expected_risk_not"])

    def test_png_with_benign_trailing_bytes_is_treated_as_clean(self):
        base = (ROOT / "assets" / "Screenshot (508).png").read_bytes()
        benign = b"benign trailing notes"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(base + benign)
            path = Path(tmp.name)

        try:
            result = self.scan_path(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
