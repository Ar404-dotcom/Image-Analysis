from __future__ import annotations

import contextlib
import io
import json
import platform
import tempfile
from collections import Counter
from pathlib import Path

import streamlit as st
from PIL import Image, UnidentifiedImageError

from converter import image_to_asm, image_to_base64, image_to_binary_string
from live_monitor import MonitorConfig, WindowsBehaviorMonitor
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


def render_live_monitoring_tab() -> None:
    st.markdown("### Live Monitoring")
    st.caption("Run a bounded Windows behavior-monitoring session for process, thread, private executable-memory, and page-transition signals.")

    is_windows = platform.system() == "Windows"
    if not is_windows:
        st.warning("Live monitoring is Windows-only. This tab can be configured here, but sessions run only on Windows hosts.")

    left, right = st.columns([1, 1], gap="large")
    with left:
        duration = st.slider("Session duration", min_value=5, max_value=120, value=20, step=5)
        interval = st.slider("Polling interval", min_value=0.5, max_value=5.0, value=1.0, step=0.5)
        max_processes = st.slider("Memory scan budget", min_value=10, max_value=200, value=80, step=10)

    with right:
        inspect_threads = st.checkbox("Inspect new thread start addresses", value=True)
        inspect_memory = st.checkbox("Inspect private executable memory", value=True)
        inspect_transitions = st.checkbox("Detect sleep-obfuscation page transitions", value=True)
        include_process_starts = st.checkbox("Evaluate new process starts", value=True)

    st.markdown(
        """
        <div class="panel">
            The monitor runs in user mode and focuses on behavior: suspicious process chains,
            thread starts inside private executable memory, process masquerading, and newly
            observed executable private regions in sensitive processes. Page-transition tracking
            watches those regions for sleep-obfuscation style flips to non-executable protections.
        </div>
        """,
        unsafe_allow_html=True,
    )

    action_col, test_col = st.columns([1, 1], gap="large")
    with action_col:
        start = st.button("Start live monitoring session", type="primary", disabled=not is_windows, use_container_width=True)
    with test_col:
        run_self_test = st.button("Run detection self-test", use_container_width=True)

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
        )
        monitor = WindowsBehaviorMonitor(config)
        progress = st.progress(0.0)
        status = st.empty()

        def update_progress(value: float) -> None:
            progress.progress(value)
            status.caption(f"Monitoring session progress: {int(value * 100)}%")

        with st.spinner("Monitoring Windows process and memory behavior..."):
            st.session_state["live_monitor_report"] = monitor.run(update_progress)

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
        )
        st.session_state["live_monitor_report"] = WindowsBehaviorMonitor(config).self_test_report()

    report = st.session_state.get("live_monitor_report")
    if not report:
        st.info("Start a session to collect live behavior events.")
        return

    if not report.get("supported", False):
        st.error(report.get("message", "Live monitoring is not supported on this host."))
        return

    summary = report.get("summary", {})
    configuration = report.get("configuration", {})
    events = report.get("events", [])
    score = int(summary.get("risk_score", 0))
    level, color = behavior_risk_band(summary)
    session_duration = int(configuration.get("duration_seconds", duration))

    top_a, top_b, top_c = st.columns(3, gap="large")
    with top_a:
        st.markdown(
            f"""
            <div class="risk-card">
                <h3>Behavior Risk</h3>
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
                <h3>Events</h3>
                <div class="risk-value">{len(events)}</div>
                <div class="section-label">Behavior signals</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_c:
        st.markdown(
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
            - Run Windows live monitoring sessions
            - Export structured JSON reports
            """
        )

    render_hero()
    convert_tab, scan_tab, monitor_tab = st.tabs(["Converter", "Scanner", "Live Monitoring"])

    with convert_tab:
        render_converter_tab()

    with scan_tab:
        render_scanner_tab()

    with monitor_tab:
        render_live_monitoring_tab()


if __name__ == "__main__":
    main()
