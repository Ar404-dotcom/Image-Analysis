from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import subprocess
import urllib.error
import urllib.request
from pathlib import Path


VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
DEMO_CLEAN_BYTES = b"Image Analysis Workbench clean reputation demo file\n"
DEMO_CLEAN_SHA256 = hashlib.sha256(DEMO_CLEAN_BYTES).hexdigest()


def calculate_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return round(entropy, 3)


def signature_status_for_path(path: str | Path) -> dict[str, str]:
    if platform.system() != "Windows":
        return {
            "status": "UNSUPPORTED",
            "subject": "",
            "message": "Authenticode signature checks are available on Windows only.",
        }

    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "$s = Get-AuthenticodeSignature -LiteralPath $args[0]; "
        "@{Status=$s.Status.ToString(); "
        "Subject=if ($s.SignerCertificate) {$s.SignerCertificate.Subject} else {''}; "
        "StatusMessage=$s.StatusMessage} | ConvertTo-Json -Compress",
        str(path),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        payload = (completed.stdout or "").strip().splitlines()[-1] if completed.stdout.strip() else "{}"
        parsed = json.loads(payload)
        return {
            "status": str(parsed.get("Status") or "UNKNOWN").upper(),
            "subject": str(parsed.get("Subject") or "").replace("\r", " ").replace("\n", " "),
            "message": str(parsed.get("StatusMessage") or ""),
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, IndexError) as exc:
        return {"status": "UNKNOWN", "subject": "", "message": f"Signature check failed: {exc}"}


def query_virustotal_hash(sha256: str, api_key: str | None = None, timeout: float = 8.0) -> dict:
    api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {
            "service": "VirusTotal",
            "queried": False,
            "found": False,
            "error": "No API key configured. Set VIRUSTOTAL_API_KEY or paste a key in the UI.",
        }

    request = urllib.request.Request(
        VT_FILE_REPORT_URL.format(sha256=sha256),
        headers={"x-apikey": api_key, "accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "service": "VirusTotal",
                "queried": True,
                "found": False,
                "error": "",
                "stats": {},
            }
        return {
            "service": "VirusTotal",
            "queried": True,
            "found": False,
            "error": f"HTTP {exc.code}: {exc.reason}",
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {
            "service": "VirusTotal",
            "queried": True,
            "found": False,
            "error": str(exc),
        }

    attributes = payload.get("data", {}).get("attributes", {})
    return {
        "service": "VirusTotal",
        "queried": True,
        "found": True,
        "error": "",
        "stats": attributes.get("last_analysis_stats", {}),
        "reputation": attributes.get("reputation", 0),
        "meaningful_name": attributes.get("meaningful_name", ""),
        "last_analysis_date": attributes.get("last_analysis_date", 0),
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def verdict_from_reputation(
    hashes: dict[str, str],
    signature: dict[str, str],
    online: dict | None = None,
) -> dict[str, str | int]:
    online = online or {}
    stats = online.get("stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    signature_status = (signature.get("status") or "").upper()

    if malicious >= 5:
        return {
            "label": "Known malicious",
            "severity": "CRITICAL",
            "score": 100,
            "message": f"{malicious} engines marked this hash as malicious.",
        }
    if malicious > 0 or suspicious >= 3:
        return {
            "label": "Suspicious reputation",
            "severity": "HIGH",
            "score": 70,
            "message": f"Detections found: malicious={malicious}, suspicious={suspicious}.",
        }
    if hashes["sha256"] == DEMO_CLEAN_SHA256:
        return {
            "label": "Demo authentic",
            "severity": "CLEAN",
            "score": 0,
            "message": "This matches the built-in clean demo file hash.",
        }
    if signature_status == "VALID" and malicious == 0 and suspicious == 0:
        return {
            "label": "Likely authentic",
            "severity": "CLEAN",
            "score": 0,
            "message": "The file has a valid Windows Authenticode signature and no malicious reputation hits.",
        }
    if online.get("queried") and online.get("found") and harmless > 0 and malicious == 0 and suspicious == 0:
        return {
            "label": "No known malicious reputation",
            "severity": "LOW",
            "score": 10,
            "message": "The hash is known to the reputation service with no malicious detections.",
        }
    if online.get("queried") and not online.get("found") and not online.get("error"):
        return {
            "label": "Unknown hash",
            "severity": "LOW",
            "score": 10,
            "message": "The hash was not found by the reputation service.",
        }
    return {
        "label": "Unknown",
        "severity": "UNKNOWN",
        "score": 0,
        "message": "No online reputation verdict is available. Use a signed file or configure a reputation API key.",
    }


def build_reputation_report(
    data: bytes,
    filename: str,
    *,
    signature_path: str | Path | None = None,
    query_online: bool = False,
    api_key: str | None = None,
) -> dict:
    hashes = calculate_hashes(data)
    signature = signature_status_for_path(signature_path) if signature_path else {
        "status": "NOT_CHECKED",
        "subject": "",
        "message": "No local path was available for signature checking.",
    }
    online = query_virustotal_hash(hashes["sha256"], api_key=api_key) if query_online else {
        "service": "VirusTotal",
        "queried": False,
        "found": False,
        "error": "Online lookup was not requested.",
    }
    verdict = verdict_from_reputation(hashes, signature, online)

    return {
        "filename": filename,
        "file_size": len(data),
        "hashes": hashes,
        "entropy": shannon_entropy(data),
        "signature": signature,
        "online_reputation": online,
        "verdict": verdict,
        "privacy_note": "Only the SHA-256 hash is sent for online reputation lookup; file bytes are not uploaded.",
    }


def demo_reputation_report() -> dict:
    return build_reputation_report(
        DEMO_CLEAN_BYTES,
        "clean_reputation_demo.txt",
        query_online=False,
    )
