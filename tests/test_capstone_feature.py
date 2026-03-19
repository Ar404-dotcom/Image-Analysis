import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malware_scanner import BinaryExtractor, CAPSTONE_AVAILABLE, MalwareScanner


class CapstoneFeatureTests(unittest.TestCase):
    def setUp(self):
        self.scanner = MalwareScanner()
        self.assertTrue(CAPSTONE_AVAILABLE, 'Capstone must be installed for this test suite')

    def test_extract_hex_sequences_handles_tabs_and_masm_hex(self):
        content = """payload db 48h,	C7h, C0h, 3Bh, 00h, 00h, 00h
	db 48h, 31h, FFh, 0Fh, 05h
"""

        sequences = BinaryExtractor.extract_hex_byte_sequences(content)

        self.assertEqual(len(sequences), 1)
        self.assertEqual(
            sequences[0]['bytes'],
            bytes.fromhex('48 c7 c0 3b 00 00 00 48 31 ff 0f 05')
        )

    def test_capstone_detects_execve_from_hex_blob_that_regex_misses(self):
        content = """shellcode bytes:
	db 48h, C7h, C0h, 3Bh, 00h, 00h, 00h
	db 48h, 31h, FFh, 0Fh, 05h
"""

        regex_findings = self.scanner.detect_suspicious_syscalls(content)
        self.assertFalse(any(f['type'] == 'DANGEROUS_SYSCALL' for f in regex_findings))

        sequences = BinaryExtractor.extract_hex_byte_sequences(content)
        capstone_findings = self.scanner.capstone.analyze_sequences(sequences, self.scanner)

        self.assertTrue(any(f['type'] == 'CAPSTONE_DANGEROUS_SYSCALL' for f in capstone_findings))
        self.assertTrue(any('sys_execve' in f['message'] for f in capstone_findings))

    def test_scan_file_reports_capstone_findings_for_backslash_x_shellcode(self):
        content = 'shellcode = "\\x48\\xc7\\xc0\\x3b\\x00\\x00\\x00\\x48\\x31\\xff\\x0f\\x05"\n'
        sample = ROOT / 'output' / 'capstone_sample_test.asm'

        try:
            sample.write_text(content, encoding='utf-8')
            result = self.scanner.scan_file(str(sample))
        finally:
            if sample.exists():
                sample.unlink()

        finding_types = {finding['type'] for finding in result['findings']}
        self.assertIn('CAPSTONE_DANGEROUS_SYSCALL', finding_types)
        self.assertIn('CAPSTONE_DISASSEMBLY', finding_types)


if __name__ == '__main__':
    unittest.main()
