from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SAFE_IMAGE_CORPUS = [
    ROOT / "assets" / "Screenshot (508).png",
    ROOT / "assets" / "Screenshot_20251015-223409.Reddit.png",
    ROOT / "assets" / "table image'.jpeg",
]
SAFE_IMAGE_CORPUS = [path for path in SAFE_IMAGE_CORPUS if path.exists()]

SUSPICIOUS_IMAGE_CORPUS = [
    {
        "path": ROOT / "assets" / "embedded" / "generated_polyglot_zip.png",
        "required_types": {"JPEG_ZIP_POLYGLOT", "EMBEDDED_ZIP"},
    },
    {
        "path": ROOT / "assets" / "embedded" / "generated_embedded_pe.png",
        "required_types": {"EMBEDDED_PE"},
    },
    {
        "path": ROOT / "assets" / "embedded" / "polyglot_zip.jpg",
        "required_types": {"JPEG_ZIP_POLYGLOT"},
    },
]

TEXT_CORPUS = [
    {
        "path": ROOT / "test_samples" / "clean_hello.asm",
        "required_types": set(),
        "expected_risk": "CLEAN - NO SIGNIFICANT THREATS",
    },
    {
        "path": ROOT / "test_samples" / "simulated_malware.asm",
        "required_types": {"DANGEROUS_SYSCALL", "WINDOWS_API", "NETWORK_SETUP", "SOCKET_CREATION"},
        "expected_risk_not": "CLEAN - NO SIGNIFICANT THREATS",
    },
]
