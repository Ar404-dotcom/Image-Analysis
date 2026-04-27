import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malware_scanner import MalwareScanner


class PixelAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.scanner = MalwareScanner()

    def scan_path(self, path):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            return self.scanner.scan_file(str(path))

    def test_preprocess_content_falls_back_to_latin1_for_binary_images(self):
        pixel_bytes = bytes(range(16))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bmp") as tmp:
            path = Path(tmp.name)

        try:
            image = Image.frombytes("L", (4, 4), pixel_bytes)
            image.save(path)
            content = MalwareScanner.preprocess_content(str(path))
        finally:
            path.unlink(missing_ok=True)

        self.assertTrue(content)
        self.assertIn("BM", content[:8])

    def test_scan_file_merges_pixel_findings_for_grayscale_dataset_samples(self):
        pixel_bytes = bytes(range(256))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bmp") as tmp:
            path = Path(tmp.name)

        try:
            image = Image.frombytes("L", (16, 16), pixel_bytes)
            image.save(path)
            result = self.scan_path(path)
        finally:
            path.unlink(missing_ok=True)

        finding_types = {finding["type"] for finding in result["findings"]}

        self.assertIn("PIXEL_HIGH_ENTROPY", finding_types)
        self.assertIn("PIXEL_HIGH_VARIANCE", finding_types)
        self.assertGreater(result["risk_score"], 0)
        self.assertAlmostEqual(result["pixel_features"]["pixel_entropy"], 8.0, places=1)


if __name__ == "__main__":
    unittest.main()
