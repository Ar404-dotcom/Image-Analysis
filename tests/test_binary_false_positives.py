import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malware_scanner import BinaryExtractor, MalwareScanner


class BinaryFalsePositiveTests(unittest.TestCase):
    def test_extract_appended_data_uses_final_png_eof(self):
        ihdr_data = (
            b"\x00\x00\x00\x01"  # width
            b"\x00\x00\x00\x01"  # height
            b"\x08\x02\x00\x00\x00"
        )
        fake_png = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\x0dIHDR"
            + ihdr_data
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x10tEXt"
            + BinaryExtractor.PNG_IEND
            + b"FAKE"
            + b"\x00\x00\x00\x00"
            + BinaryExtractor.PNG_IEND
            + b"PAYLOAD"
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(fake_png)
            path = tmp.name

        try:
            appended = BinaryExtractor.extract_appended_data(path)
        finally:
            Path(path).unlink(missing_ok=True)

        self.assertEqual(appended, b"PAYLOAD")

    def test_binary_opcode_signatures_are_not_reported_for_plain_file_body(self):
        scanner = MalwareScanner()
        raw = b"A" * 2048 + b"\xcd\x80" + b"B" * 2048 + b"\x0f\x05"

        findings = scanner.detect_binary_payloads(raw_bytes=raw, appended_bytes=None)
        finding_types = {finding["type"] for finding in findings}

        self.assertNotIn("BINARY_INT80", finding_types)
        self.assertNotIn("BINARY_SYSCALL", finding_types)
        self.assertNotIn("NON_PRINTABLE_BLOB", finding_types)

    def test_xmp_metadata_is_not_treated_as_script_indicator(self):
        scanner = MalwareScanner()
        raw = b"\x89PNG\r\n\x1a\nrandom xmp metadata block"

        findings = scanner.detect_binary_payloads(raw_bytes=raw, appended_bytes=None)
        finding_types = {finding["type"] for finding in findings}

        self.assertNotIn("SUSPICIOUS_METADATA_SCRIPT", finding_types)

    def test_embedded_pe_requires_real_pe_structure(self):
        scanner = MalwareScanner()
        appended = b"A" * 4096 + b"MZ" + b"B" * 8192

        findings = scanner.detect_binary_payloads(raw_bytes=b"\x89PNG\r\n\x1a\n", appended_bytes=appended)
        finding_types = {finding["type"] for finding in findings}

        self.assertNotIn("EMBEDDED_PE", finding_types)


if __name__ == "__main__":
    unittest.main()
