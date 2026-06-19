from __future__ import annotations

import contextlib
import io
import json
import os
import platform
import tempfile
from collections import Counter
from pathlib import Path

import streamlit as st
from PIL import Image, UnidentifiedImageError

from converter import image_to_asm, image_to_base64, image_to_binary_string
from file_reputation import build_reputation_report, demo_reputation_report
from live_monitor import (
    DEFAULT_TARGET_FILE,
    MonitorConfig,
    WindowsBehaviorMonitor,
    arm_target_file_monitor,
    contain_target_file_threat,
    launch_target_file_simulator,
    target_file_report,
)
from malware_scanner import MalwareScanner


st.set_page_config(
    page_title="Image Analysis Workbench",
    layout="wide",
    initial_sidebar_state="expanded",
)


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --bg: #0c1016;
            --panel: rgba(18, 24, 34, 0.88);
            --panel-strong: rgba(24, 31, 43, 0.96);
            --line: rgba(152, 174, 210, 0.16);
            --ink: #edf3ff;
            --muted: #9caec9;
            --accent: #ff7a2f;
            --accent-soft: rgba(255, 122, 47, 0.14);
            --warn: #ff5f56;
            --safe: #3ddc97;
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(255, 122, 47, 0.16), transparent 26%),
                radial-gradient(circle at 85% 18%, rgba(65, 129, 255, 0.12), transparent 22%),
                linear-gradient(180deg, #111722 0%, var(--bg) 100%);
            color: var(--ink);
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #121926 0%, #0b1119 100%);
        }

        [data-testid="stSidebar"] * {
            color: #edf3ff !important;
        }

        .hero {
            padding: 1.6rem 1.8rem;
            border: 1px solid var(--line);
            border-radius: 24px;
            background:
                linear-gradient(135deg, rgba(25, 33, 45, 0.98), rgba(18, 24, 34, 0.94)),
                var(--panel);
            box-shadow: 0 24px 70px rgba(0, 0, 0, 0.38);
            margin-bottom: 1rem;
        }

        .hero h1 {
            margin: 0;
            font-size: 3rem;
            line-height: 1;
            letter-spacing: -0.04em;
        }

        .hero p {
            margin: 0.8rem 0 0;
            max-width: 52rem;
            color: var(--muted);
            font-size: 1.02rem;
        }

        .panel {
            padding: 1rem 1.1rem;
            border-radius: 20px;
            border: 1px solid var(--line);
            background: var(--panel);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
        }

        .pill-row {
            display: flex;
            gap: 0.6rem;
            flex-wrap: wrap;
            margin: 1rem 0 0;
        }

        .pill {
            border-radius: 999px;
            padding: 0.45rem 0.8rem;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--line);
            color: var(--ink);
            font-size: 0.92rem;
        }

        .risk-card {
            padding: 1rem 1.1rem;
            border-radius: 20px;
            border: 1px solid var(--line);
            background: var(--panel-strong);
            min-height: 130px;
        }

        .status-card {
            padding: 0.95rem 1rem;
            border-radius: 18px;
            border: 1px solid var(--line);
            background: rgba(255,255,255,0.035);
        }

        .risk-card h3, .metric-card h3 {
            margin: 0;
            font-size: 0.95rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .status-card h3 {
            margin: 0;
            font-size: 0.85rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .risk-value, .metric-value {
            margin-top: 0.65rem;
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: -0.04em;
        }

        .status-value {
            margin-top: 0.55rem;
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.03em;
        }

        .metric-card {
            padding: 1rem 1.1rem;
            border-radius: 18px;
            border: 1px solid var(--line);
            background: rgba(255,255,255,0.04);
        }

        .section-label {
            margin-top: 0.4rem;
            color: var(--muted);
            font-size: 0.95rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def risk_band(score: int) -> tuple[str, str]:
    if score >= 100:
        return "Critical", "#8a2d1d"
    if score >= 60:
        return "High", "#b64d1f"
    if score >= 30:
        return "Medium", "#bd7c16"
    if score >= 10:
        return "Low", "#567a12"
    return "Clean", "#256245"


def behavior_risk_band(summary: dict) -> tuple[str, str]:
    score = int(summary.get("risk_score", 0))
    severities = summary.get("severity_counts", {})
    if severities.get("CRITICAL", 0) or score >= 100:
        return "Critical", "#8a2d1d"
    if severities.get("HIGH", 0) or score >= 35:
        return "High", "#b64d1f"
    if severities.get("MEDIUM", 0) or score >= 20:
        return "Medium", "#bd7c16"
    if severities.get("LOW", 0) or score > 0:
        return "Low", "#567a12"
    return "Clean", "#256245"


def reputation_band(verdict: dict) -> tuple[str, str]:
    severity = str(verdict.get("severity", "UNKNOWN")).upper()
    if severity == "CRITICAL":
        return "Critical", "#8a2d1d"
    if severity == "HIGH":
        return "High", "#b64d1f"
    if severity == "MEDIUM":
        return "Medium", "#bd7c16"
    if severity == "LOW":
        return "Low", "#567a12"
    if severity == "CLEAN":
        return "Clean", "#256245"
    return "Unknown", "#7b8798"


def port_exposure_band(summary: dict) -> tuple[str, str]:
    severities = summary.get("severity_counts", {})
    categories = summary.get("category_counts", {})
    if severities.get("CRITICAL", 0):
        return "Critical", "#8a2d1d"
    if severities.get("HIGH", 0):
        return "High", "#b64d1f"
    if categories.get("public_remote_control_or_file_port", 0):
        return "Medium", "#bd7c16"
    if categories.get("network_listener_all_interfaces", 0) or categories.get("network_listener_reachable_interface", 0):
        return "Low", "#567a12"
    return "Clean", "#256245"


def open_uploaded_image(uploaded_file) -> Image.Image | None:
    try:
        image = Image.open(io.BytesIO(uploaded_file.getvalue()))
        image.load()
        return image
    except UnidentifiedImageError:
        return None


def is_known_image_upload(uploaded_file) -> bool:
    return Path(uploaded_file.name).suffix.lower() in {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"
    }


def convert_image_outputs(image: Image.Image, width: int | None) -> dict[str, str]:
    working = image.copy()
    if width and width > 0 and width != working.size[0]:
        ratio = width / float(working.size[0])
        resized_height = max(1, int(working.size[1] * ratio))
        working = working.resize((width, resized_height), Image.Resampling.LANCZOS)

    return {
        "ASM": image_to_asm(working),
        "Binary": image_to_binary_string(working),
        "Base64": image_to_base64(working),
    }


def scan_uploaded_file(uploaded_file) -> tuple[dict | None, str]:
    suffix = Path(uploaded_file.name).suffix or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded_file.getvalue())
        temp_path = tmp.name

    scanner = MalwareScanner()
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            result = scanner.scan_file(temp_path)
    finally:
        Path(temp_path).unlink(missing_ok=True)

    return result, buffer.getvalue()


def scan_local_file(path: Path) -> tuple[dict | None, str]:
    scanner = MalwareScanner()
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = scanner.scan_file(str(path))
    return result, buffer.getvalue()


def ensure_true_positive_image_sample() -> Path:
    output_path = Path("output") / "true_positive_embedded_pe.png"
    output_path.parent.mkdir(exist_ok=True)

    image = Image.new("RGB", (64, 64), color=(42, 90, 140))
    image.save(output_path)

    pe_stub = bytearray(256)
    pe_stub[0:2] = b"MZ"
    pe_stub[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe_stub[0x80:0x84] = b"PE\x00\x00"
    with output_path.open("ab") as handle:
        handle.write(pe_stub)

    return output_path


def render_hero() -> None:
    st.markdown(
        """
        <div class="hero">
            <h1>Image Analysis Workbench</h1>
            <p>
                A focused frontend for converting images into low-level representations
                triaging suspicious image, ASM, and polyglot files, and running bounded
                Windows behavior monitoring sessions.
            </p>
            <div class="pill-row">
                <div class="pill">Image preview</div>
                <div class="pill">ASM / Binary / Base64 export</div>
                <div class="pill">Malware risk scoring</div>
                <div class="pill">File reputation</div>
                <div class="pill">Live monitoring</div>
                <div class="pill">Finding breakdowns</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_converter_tab() -> None:
    st.markdown("### Convert Images")
    st.caption("Turn uploaded images into ASM byte arrays, binary strings, and base64 with an immediate preview.")

    uploaded = st.file_uploader(
        "Upload an image",
        type=["png", "jpg", "jpeg", "gif", "bmp", "webp"],
        key="converter_uploader",
    )

    if not uploaded:
        st.info("Add an image to start generating low-level outputs.")
        return

    image = open_uploaded_image(uploaded)
    if image is None:
        st.error("This file could not be opened as an image.")
        return

    left, right = st.columns([1.15, 1], gap="large")

    with left:
        st.image(image, caption=f"{uploaded.name} | {image.size[0]}x{image.size[1]}", use_container_width=True)

    with right:
        width = st.number_input(
            "Resize width before conversion",
            min_value=1,
            value=image.size[0],
            step=1,
            help="Aspect ratio is preserved automatically.",
        )
        include_asm = st.checkbox("Generate ASM output", value=True)
        include_binary = st.checkbox("Generate binary output", value=True)
        include_base64 = st.checkbox("Generate base64 output", value=True)

        if not any([include_asm, include_binary, include_base64]):
            st.warning("Select at least one output format.")
            return

        outputs = convert_image_outputs(image, int(width) if width else None)

        metrics = st.columns(3)
        for column, (label, content) in zip(metrics, outputs.items()):
            with column:
                st.markdown(
                    f"""
                    <div class="metric-card">
                        <h3>{label}</h3>
                        <div class="metric-value">{len(content):,}</div>
                        <div class="section-label">characters</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    render_map = {
        "ASM": include_asm,
        "Binary": include_binary,
        "Base64": include_base64,
    }

    for label, enabled in render_map.items():
        if not enabled:
            continue
        content = outputs[label]
        ext = {"ASM": "asm", "Binary": "bin.txt", "Base64": "b64.txt"}[label]
        st.markdown(f"#### {label} Output")
        st.code(content[:12000], language="text")
        if len(content) > 12000:
            st.caption("Preview truncated in the UI. Use download to access the full output.")
        st.download_button(
            label=f"Download {label}",
            data=content,
            file_name=f"{uploaded.name}.{ext}",
            mime="text/plain",
            use_container_width=False,
        )


def render_scanner_tab() -> None:
    st.markdown("### Scan Files")
    st.caption("Analyze images, ASM, or extracted text blobs and inspect the risk breakdown instead of reading raw terminal output.")

    test_col, upload_col = st.columns([0.75, 1.25], gap="large")
    with test_col:
        if st.button("Run true-positive image self-test", use_container_width=True):
            sample_path = ensure_true_positive_image_sample()
            with st.spinner("Scanning controlled PE-in-PNG sample..."):
                result, console_output = scan_local_file(sample_path)
            st.session_state["scanner_self_test"] = {
                "path": str(sample_path),
                "result": result,
                "console_output": console_output,
            }

    self_test = st.session_state.get("scanner_self_test")
    if self_test:
        sample_name = Path(self_test["path"]).name
        st.info(f"Showing self-test report for {sample_name}. Upload a file below to run a normal scan.")
        render_scan_result(
            result=self_test["result"],
            console_output=self_test["console_output"],
            report_name=f"{Path(sample_name).stem}_scan_report.json",
        )
        st.divider()

    uploaded = st.file_uploader(
        "Upload a file to scan",
        type=["asm", "txt", "bin", "png", "jpg", "jpeg", "gif", "bmp", "webp"],
        key="scanner_uploader",
    )

    if not uploaded:
        st.info("Upload an image, ASM file, or suspicious payload sample to run the scanner.")
        return

    image = open_uploaded_image(uploaded)
    if image is not None:
        st.image(image, caption=f"Preview: {uploaded.name}", use_container_width=True)

    with st.spinner("Running scanner modules and correlating findings..."):
        result, console_output = scan_uploaded_file(uploaded)

    if result is None:
        st.error("The scan did not return a result.")
        if console_output.strip():
            st.code(console_output, language="text")
        return

    render_scan_result(
        result=result,
        console_output=console_output,
        report_name=f"{Path(uploaded.name).stem}_scan_report.json",
        uploaded_file=uploaded,
    )


def render_scan_result(result: dict | None, console_output: str, report_name: str, uploaded_file=None) -> None:
    if result is None:
        st.error("The scan did not return a result.")
        if console_output.strip():
            st.code(console_output, language="text")
        return

    score = int(result.get("risk_score", 0))
    findings = result.get("findings", [])
    evidence_summary = result.get("evidence_summary", {})
    level, color = risk_band(score)
    severity_counts = Counter(f["severity"] for f in findings)

    top_a, top_b, top_c = st.columns(3, gap="large")
    with top_a:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>Risk Level</h3>
                <div class="risk-value" style="color:{color};">{level}</div>
                <div class="section-label">Score {score}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_b:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>Total Findings</h3>
                <div class="risk-value">{len(findings)}</div>
                <div class="section-label">Signals surfaced</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_c:
        appended = "Yes" if uploaded_file is not None and is_known_image_upload(uploaded_file) else "Sample"
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>Image Signature</h3>
                <div class="risk-value">{appended}</div>
                <div class="section-label">Recognized as image by extension check</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    sev_cols = st.columns(4)
    for column, severity in zip(sev_cols, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
        with column:
            st.metric(severity.title(), severity_counts.get(severity, 0))

    st.markdown("#### Evidence Sources")
    source_cols = st.columns(4)
    source_labels = [
        ("Validated structure", "validated binary structure"),
        ("Appended payload", "appended payload"),
        ("Low-confidence", "low-confidence heuristic"),
        ("Text heuristics", "heuristic text analysis"),
    ]
    for column, (label, key) in zip(source_cols, source_labels):
        with column:
            st.markdown(
                f"""
                <div class="status-card">
                    <h3>{label}</h3>
                    <div class="status-value">{evidence_summary.get(key, 0)}</div>
                    <div class="section-label">{key}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    if findings:
        st.markdown("#### Findings")
        table_rows = [
            {
                "Severity": finding["severity"],
                "Type": finding["type"],
                "Evidence": finding.get("evidence_source", "heuristic text analysis"),
                "Confidence": finding.get("confidence", "medium"),
                "Line": finding["line"] if finding["line"] else "-",
                "Score": finding["score"],
                "Message": finding["message"],
            }
            for finding in findings
        ]
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

        st.markdown("#### Findings JSON")
        st.code(json.dumps(findings, indent=2), language="json")
    else:
        st.success("No suspicious patterns were detected for this upload.")

    with st.expander("Scanner console output"):
        st.code(console_output or "No console output was captured.", language="text")

    st.download_button(
        label="Download scan report",
        data=json.dumps(result, indent=2),
        file_name=report_name,
        mime="application/json",
    )


def render_reputation_tab() -> None:
    st.markdown("### File Reputation Checker")
    st.caption(
        "Upload any file to calculate hashes, check Windows signature status, and optionally query an online reputation service by SHA-256 hash."
    )

    left, right = st.columns([1.1, 0.9], gap="large")
    with left:
        uploaded = st.file_uploader(
            "Choose a file to verify",
            key="reputation_uploader",
        )
    with right:
        query_online = st.checkbox("Query VirusTotal by hash", value=False)
        configured_key = bool(os.getenv("VIRUSTOTAL_API_KEY"))
        api_key = st.text_input(
            "VirusTotal API key",
            type="password",
            value="",
            placeholder="Using VIRUSTOTAL_API_KEY" if configured_key else "Optional",
            help="Only the SHA-256 hash is sent. The file contents are not uploaded.",
            disabled=not query_online,
        )
        run_demo = st.button("Run clean demo check", use_container_width=True)

    st.markdown(
        """
        <div class="panel">
            Reputation checks are strongest when the hash is already known by an online service
            or when the file has a valid Windows Authenticode signature. Unknown does not mean
            malicious; it means the checker cannot prove authenticity from available signals.
        </div>
        """,
        unsafe_allow_html=True,
    )

    if run_demo:
        st.session_state["file_reputation_report"] = demo_reputation_report()

    if uploaded:
        suffix = Path(uploaded.name).suffix or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(uploaded.getvalue())
            temp_path = tmp.name

        try:
            with st.spinner("Checking file identity and reputation..."):
                st.session_state["file_reputation_report"] = build_reputation_report(
                    uploaded.getvalue(),
                    uploaded.name,
                    signature_path=temp_path,
                    query_online=query_online,
                    api_key=api_key or None,
                )
        finally:
            Path(temp_path).unlink(missing_ok=True)

    report = st.session_state.get("file_reputation_report")
    if not report:
        st.info("Upload a file or run the demo to start a reputation check.")
        return

    render_reputation_report(report)


def render_reputation_report(report: dict) -> None:
    verdict = report.get("verdict", {})
    hashes = report.get("hashes", {})
    signature = report.get("signature", {})
    online = report.get("online_reputation", {})
    level, color = reputation_band(verdict)

    top_a, top_b, top_c = st.columns(3, gap="large")
    with top_a:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>Reputation Verdict</h3>
                <div class="risk-value" style="color:{color};">{level}</div>
                <div class="section-label">{verdict.get("label", "Unknown")}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_b:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>File Size</h3>
                <div class="risk-value">{int(report.get("file_size", 0)):,}</div>
                <div class="section-label">bytes</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_c:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>Entropy</h3>
                <div class="risk-value">{float(report.get("entropy", 0.0)):.3f}</div>
                <div class="section-label">0 to 8 byte distribution</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.info(verdict.get("message", "No reputation message is available."))
    st.caption(report.get("privacy_note", "Only file hashes are used for online lookup."))

    st.markdown("#### File Hashes")
    st.dataframe(
        [{"Algorithm": key.upper(), "Hash": value} for key, value in hashes.items()],
        use_container_width=True,
        hide_index=True,
    )

    detail_cols = st.columns(2, gap="large")
    with detail_cols[0]:
        st.markdown("#### Signature")
        st.dataframe(
            [
                {"Field": "Status", "Value": signature.get("status", "")},
                {"Field": "Subject", "Value": signature.get("subject", "")},
                {"Field": "Message", "Value": signature.get("message", "")},
            ],
            use_container_width=True,
            hide_index=True,
        )
    with detail_cols[1]:
        st.markdown("#### Online Reputation")
        stats = online.get("stats") or {}
        st.dataframe(
            [
                {"Field": "Service", "Value": online.get("service", "VirusTotal")},
                {"Field": "Queried", "Value": online.get("queried", False)},
                {"Field": "Found", "Value": online.get("found", False)},
                {"Field": "Malicious", "Value": stats.get("malicious", 0)},
                {"Field": "Suspicious", "Value": stats.get("suspicious", 0)},
                {"Field": "Harmless", "Value": stats.get("harmless", 0)},
                {"Field": "Error", "Value": online.get("error", "")},
            ],
            use_container_width=True,
            hide_index=True,
        )
        if online.get("link"):
            st.markdown(f"[Open reputation details]({online['link']})")

    with st.expander("Reputation report JSON"):
        st.code(json.dumps(report, indent=2), language="json")

    st.download_button(
        label="Download reputation report",
        data=json.dumps(report, indent=2),
        file_name=f"{Path(report.get('filename', 'file')).stem}_reputation_report.json",
        mime="application/json",
    )


def render_live_monitoring_tab() -> None:
    st.markdown("### Live Monitoring")
    st.caption(
        "Run a bounded Windows behavior-monitoring session, or launch a local-only demo that collects low-sensitivity host facts and detects the follow-on sleep pattern."
    )

    is_windows = platform.system() == "Windows"
    if not is_windows:
        st.warning("Live monitoring is Windows-only. This tab can be configured here, but sessions run only on Windows hosts.")

    left, right = st.columns([1, 1], gap="large")
    with left:
        duration = st.slider("Session duration", min_value=5, max_value=120, value=20, step=5)
        interval = st.slider("Polling interval", min_value=0.5, max_value=5.0, value=1.0, step=0.5)
        max_processes = st.slider("Memory scan budget", min_value=10, max_value=200, value=80, step=10)
        memory_growth_threshold = st.slider("Memory growth threshold (%)", min_value=25, max_value=400, value=80, step=5)
        memory_growth_min_mb = st.slider("Minimum memory jump (MB)", min_value=5, max_value=256, value=25, step=5)

    with right:
        inspect_threads = st.checkbox("Inspect new thread start addresses", value=True)
        inspect_memory = st.checkbox("Inspect private executable memory", value=True)
        inspect_transitions = st.checkbox("Detect sleep-obfuscation page transitions", value=True)
        include_process_starts = st.checkbox("Evaluate new process starts", value=True)
        inspect_network_ports = st.checkbox("Check live network ports", value=True)
        inspect_memory_growth = st.checkbox("Track sudden memory growth", value=True)

    st.markdown(
        """
        <div class="panel">
            The monitor runs in user mode and focuses on behavior: suspicious process chains,
            thread starts inside private executable memory, process masquerading, and newly
            observed executable private regions in sensitive processes. Page-transition tracking
            watches those regions for sleep-obfuscation style flips to non-executable protections.
            Port checking lists live listeners and active connections to help verify possible
            screen-share, remote-control, or file-transfer paths.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("#### Controlled Target File Simulator")
    st.caption(
        f"Arms a Windows directory watcher for `{DEFAULT_TARGET_FILE}`, detects the rename to a `_LOCKED` name, records previous/current names in `output/readme.txt`, then lets containment restore it."
    )
    sim_col_a, sim_col_b, sim_col_c, sim_col_d = st.columns([1, 1, 1, 1], gap="large")
    with sim_col_a:
        prepare_simulator = st.button("Start demo monitor", use_container_width=True)
    with sim_col_b:
        start_simulator = st.button("Start threat simulator", use_container_width=True)
    with sim_col_c:
        refresh_simulator = st.button("Refresh simulator status", use_container_width=True)
    with sim_col_d:
        contain_simulator = st.button("Contain threat", type="primary", use_container_width=True)

    action_col, port_col, self_test_col, demo_col = st.columns([1, 1, 1, 1], gap="large")
    with action_col:
        start = st.button("Start live monitoring session", type="primary", disabled=not is_windows, use_container_width=True)
    with port_col:
        check_ports = st.button("Check live ports now", use_container_width=True)
    with self_test_col:
        run_self_test = st.button("Run synthetic rule self-test", use_container_width=True)
    with demo_col:
        run_demo = st.button("Run telemetry sleep demo", use_container_width=True)

    if prepare_simulator:
        arm_target_file_monitor()
        st.session_state["live_monitor_report"] = target_file_report()

    if start_simulator:
        with st.spinner("Launching controlled target-file simulator..."):
            st.session_state["live_monitor_report"] = launch_target_file_simulator()

    if refresh_simulator:
        st.session_state["live_monitor_report"] = target_file_report()

    if contain_simulator:
        with st.spinner("Containing controlled simulator and restoring the target file name..."):
            st.session_state["live_monitor_report"] = contain_target_file_threat()

    if start:
        config = MonitorConfig(
            duration_seconds=int(duration),
            interval_seconds=float(interval),
            inspect_thread_starts=inspect_threads,
            inspect_memory_regions=inspect_memory,
            inspect_page_transitions=inspect_transitions,
            transition_watch_seconds=max(10, int(duration)),
            max_processes_per_cycle=int(max_processes),
            include_process_starts=include_process_starts,
            inspect_network_ports=inspect_network_ports,
            inspect_memory_growth=inspect_memory_growth,
            memory_growth_percent_threshold=float(memory_growth_threshold),
            memory_growth_min_mb=int(memory_growth_min_mb),
        )
        monitor = WindowsBehaviorMonitor(config)
        progress = st.progress(0.0)
        status = st.empty()

        def update_progress(value: float) -> None:
            progress.progress(value)
            status.caption(f"Monitoring session progress: {int(value * 100)}%")

        with st.spinner("Monitoring Windows process and memory behavior..."):
            st.session_state["live_monitor_report"] = monitor.run(update_progress)

    if check_ports:
        config = MonitorConfig(
            duration_seconds=int(duration),
            interval_seconds=float(interval),
            inspect_thread_starts=inspect_threads,
            inspect_memory_regions=inspect_memory,
            inspect_page_transitions=inspect_transitions,
            transition_watch_seconds=max(10, int(duration)),
            max_processes_per_cycle=int(max_processes),
            include_process_starts=include_process_starts,
            inspect_network_ports=inspect_network_ports,
            inspect_memory_growth=inspect_memory_growth,
            memory_growth_percent_threshold=float(memory_growth_threshold),
            memory_growth_min_mb=int(memory_growth_min_mb),
        )
        with st.spinner("Checking live TCP and UDP ports..."):
            st.session_state["live_monitor_report"] = WindowsBehaviorMonitor(config).port_check_report()

    if run_self_test:
        config = MonitorConfig(
            duration_seconds=int(duration),
            interval_seconds=float(interval),
            inspect_thread_starts=inspect_threads,
            inspect_memory_regions=inspect_memory,
            inspect_page_transitions=inspect_transitions,
            transition_watch_seconds=max(10, int(duration)),
            max_processes_per_cycle=int(max_processes),
            include_process_starts=include_process_starts,
            inspect_network_ports=inspect_network_ports,
            inspect_memory_growth=inspect_memory_growth,
            memory_growth_percent_threshold=float(memory_growth_threshold),
            memory_growth_min_mb=int(memory_growth_min_mb),
        )
        st.session_state["live_monitor_report"] = WindowsBehaviorMonitor(config).self_test_report()

    if run_demo:
        config = MonitorConfig(
            duration_seconds=int(duration),
            interval_seconds=float(interval),
            inspect_thread_starts=inspect_threads,
            inspect_memory_regions=inspect_memory,
            inspect_page_transitions=inspect_transitions,
            transition_watch_seconds=max(10, int(duration)),
            max_processes_per_cycle=int(max_processes),
            include_process_starts=include_process_starts,
            inspect_network_ports=inspect_network_ports,
            inspect_memory_growth=inspect_memory_growth,
            memory_growth_percent_threshold=float(memory_growth_threshold),
            memory_growth_min_mb=int(memory_growth_min_mb),
        )
        progress = st.progress(0.0)
        status = st.empty()

        def update_demo_progress(value: float) -> None:
            progress.progress(value)
            status.caption(f"Demo progress: {int(value * 100)}%")

        with st.spinner("Collecting local demo telemetry and entering sleep interval..."):
            st.session_state["live_monitor_report"] = WindowsBehaviorMonitor(config).demo_recon_sleep_report(
                sleep_seconds=3.0,
                progress_callback=update_demo_progress,
            )

    report = st.session_state.get("live_monitor_report")
    if not report:
        st.info("Start a session to collect live behavior events.")
        return

    if not report.get("supported", False):
        st.error(report.get("message", "Live monitoring is not supported on this host."))
        return

    summary = report.get("summary", {})
    network_summary = report.get("network_summary") or summary.get("network", {})
    memory_surge_summary = report.get("memory_surge_summary", {})
    configuration = report.get("configuration", {})
    events = report.get("events", [])
    score = int(summary.get("risk_score", 0))
    is_port_check = bool(report.get("port_check"))
    level, color = port_exposure_band(summary) if is_port_check else behavior_risk_band(summary)
    risk_label = "Port Exposure" if is_port_check else "Behavior Risk"
    score_label = "Max exposure score" if is_port_check else "Score"
    is_threat_simulator = bool(report.get("threat_simulator"))
    session_duration = int(configuration.get("duration_seconds", duration))

    top_a, top_b, top_c = st.columns(3, gap="large")
    with top_a:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>{risk_label}</h3>
                <div class="risk-value" style="color:{color};">{level}</div>
                <div class="section-label">{score_label} {score}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_b:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>Events</h3>
                <div class="risk-value">{len(events)}</div>
                <div class="section-label">Behavior signals</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_c:
        if is_threat_simulator:
            top_c.markdown(
                f"""
                <div class="risk-card">
                    <h3>Simulator Status</h3>
                    <div class="risk-value">{report.get("threat_status", "Ready")}</div>
                    <div class="section-label">{report.get("message", "")}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            top_c.markdown(
                f"""
                <div class="risk-card">
                    <h3>Session Window</h3>
                    <div class="risk-value">{session_duration}s</div>
                    <div class="section-label">{report.get("started_at", "")} UTC</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    severity_counts = summary.get("severity_counts", {})
    sev_cols = st.columns(4)
    for column, severity in zip(sev_cols, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
        with column:
            st.metric(severity.title(), severity_counts.get(severity, 0))

    demo_state = report.get("demo_state")
    if demo_state:
        st.markdown("#### Controlled Demo State")
        if demo_state.get("target_file_demo"):
            state_rows = [
                {"Field": "Device", "Value": demo_state.get("device_name", "")},
                {"Field": "Original path", "Value": demo_state.get("original_path", "")},
                {"Field": "Locked path", "Value": demo_state.get("locked_path", "")},
                {"Field": "Previous name", "Value": demo_state.get("previous_name", "")},
                {"Field": "Current name", "Value": demo_state.get("current_name", "")},
                {"Field": "Original exists", "Value": demo_state.get("original_exists", False)},
                {"Field": "Locked exists", "Value": demo_state.get("locked", False)},
                {"Field": "Log created", "Value": demo_state.get("readme_created", False)},
                {"Field": "Log path", "Value": demo_state.get("readme_path", "")},
                {"Field": "Simulator PID", "Value": demo_state.get("simulator_pid", 0)},
                {"Field": "Simulator running", "Value": demo_state.get("simulator_running", False)},
                {"Field": "Monitor armed", "Value": demo_state.get("monitor_armed", False)},
                {"Field": "Detection method", "Value": demo_state.get("detection_method", "")},
                {"Field": "Process terminated", "Value": demo_state.get("terminated_process", "")},
                {"Field": "Restored", "Value": demo_state.get("restored", "")},
            ]
        else:
            state_rows = [
                {"Field": "Device", "Value": demo_state.get("device_name", "")},
                {"Field": "Demo root", "Value": demo_state.get("demo_root", "")},
                {"Field": "DemoData exists", "Value": demo_state.get("demo_data_exists", False)},
                {"Field": "DemoData_LOCKED exists", "Value": demo_state.get("locked", False)},
                {"Field": "READ_ME.txt created", "Value": demo_state.get("readme_created", False)},
                {"Field": "Simulator PID", "Value": demo_state.get("simulator_pid", 0)},
                {"Field": "Simulator running", "Value": demo_state.get("simulator_running", False)},
                {"Field": "Process terminated", "Value": demo_state.get("terminated_process", "")},
            ]
        st.dataframe(state_rows, use_container_width=True, hide_index=True)

    network_ports = report.get("network_ports", [])
    memory_surges = report.get("memory_surges", [])
    st.markdown("#### Memory Surge Dashboard")
    st.caption("Processes are ranked by percentage growth from the previous sample, then tracked even if they later become quiet or sleep-like.")
    surge_cols = st.columns(4)
    surge_metrics = [
        ("Tracked surges", "tracked_processes"),
        ("Peak growth %", "max_growth_percent"),
        ("Alive after surge", "alive_after_surge"),
        ("Sleeping after surge", "sleeping_after_surge"),
    ]
    for column, (label, key) in zip(surge_cols, surge_metrics):
        with column:
            st.metric(label, memory_surge_summary.get(key, 0))

    if memory_surges:
        st.dataframe(
            [
                {
                    "Process": surge["process_name"],
                    "PID": surge["pid"],
                    "Status": surge["status"],
                    "Alive": surge["alive"],
                    "Sleeping After Surge": surge["sleeping_after_surge"],
                    "Peak Growth %": surge["peak_growth_percent"],
                    "Baseline RSS MB": surge["baseline_rss_mb"],
                    "Peak RSS MB": surge["peak_rss_mb"],
                    "Latest RSS MB": surge["latest_rss_mb"],
                    "Peak Memory %": surge["peak_memory_percent"],
                    "Persistence Cycles": surge["persistence_cycles"],
                }
                for surge in memory_surges
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No sudden memory-growth processes have been observed in the current report yet. Start a live monitoring session and let it run long enough to sample a surge.")

    if network_ports:
        st.markdown("#### Live Network Ports")
        st.caption("This shows current listeners and connections. It can reveal possible transfer paths, but port state alone does not prove that files or screen data were sent.")
        net_cols = st.columns(4)
        network_metrics = [
            ("Total ports", "total_ports"),
            ("Listeners", "listeners"),
            ("Public connections", "established_public_connections"),
            ("Exposed listeners", "exposed_listeners"),
        ]
        for column, (label, key) in zip(net_cols, network_metrics):
            with column:
                st.metric(label, network_summary.get(key, 0))

        st.dataframe(
            [
                {
                    "Protocol": port["protocol"],
                    "Local": f"{port['local_address']}:{port['local_port']}",
                    "Remote": f"{port['remote_address']}:{port['remote_port']}" if port.get("remote_address") else "",
                    "Remote Scope": port.get("remote_scope", ""),
                    "Status": port.get("status", ""),
                    "Exposure": port.get("listener_exposure", ""),
                    "Process": port.get("process_name", ""),
                    "PID": port.get("pid", 0),
                }
                for port in network_ports
            ],
            use_container_width=True,
            hide_index=True,
        )

    demo_telemetry = report.get("demo_telemetry")
    if demo_telemetry:
        st.markdown("#### Local Demo Telemetry")
        st.caption("Shown from local Streamlit session state. The demo checks whether the Desktop folder exists but does not read desktop files.")
        st.dataframe(
            [{"Field": key, "Value": value} for key, value in demo_telemetry.items()],
            use_container_width=True,
            hide_index=True,
        )

    if events:
        st.markdown("#### Live Events")
        rows = [
            {
                "Time": event["timestamp"],
                "Severity": event["severity"],
                "Category": event["category"],
                "Process": event["process_name"],
                "PID": event["pid"],
                "Parent": event.get("parent_name", ""),
                "Score": event["score"],
                "Message": event["message"],
            }
            for event in events
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

        with st.expander("Event evidence JSON"):
            st.code(json.dumps(events, indent=2), language="json")
    else:
        st.success("No suspicious live behavior was observed during this session.")

    st.download_button(
        label="Download monitoring report",
        data=json.dumps(report, indent=2),
        file_name="live_monitoring_report.json",
        mime="application/json",
    )


def main() -> None:
    inject_styles()

    with st.sidebar:
        st.title("Workbench")
        st.write("A small frontend for image conversion, static triage, and bounded Windows behavior monitoring.")
        st.markdown(
            """
            - Convert images into `ASM`, `binary`, and `base64`
            - Preview images before processing
            - Scan uploaded files and inspect finding severity
            - Check file hashes, signatures, and reputation
            - Run Windows live monitoring sessions
            - Export structured JSON reports
            """
        )

    render_hero()
    convert_tab, scan_tab, reputation_tab, monitor_tab = st.tabs(
        ["Converter", "Scanner", "File Reputation", "Live Monitoring"]
    )

    with convert_tab:
        render_converter_tab()

    with scan_tab:
        render_scanner_tab()

    with reputation_tab:
        render_reputation_tab()

    with monitor_tab:
        render_live_monitoring_tab()


if __name__ == "__main__":
    main()
