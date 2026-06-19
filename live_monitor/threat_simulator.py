from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover - exercised when optional dependency is absent.
    psutil = None


DEMO_ROOT = Path("output") / "threat_simulator_demo"
DEMO_DATA_NAME = "DemoData"
LOCKED_DATA_NAME = "DemoData_LOCKED"
README_NAME = "READ_ME.txt"
PID_FILE_NAME = "simulator.pid"
DEFAULT_TARGET_FILE = Path(r"C:\Users\HP\Downloads\Resume updated June.pdf")
TARGET_PID_FILE = Path("output") / "target_file_simulator.pid"
ACTION_LOG_FILE = Path("output") / "readme.txt"
_RUNNING_SIMULATORS: list[subprocess.Popen] = []


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_demo_root(root: str | Path | None = None) -> Path:
    return Path(root or DEMO_ROOT).resolve()


def prepare_demo_workspace(root: str | Path | None = None) -> dict:
    demo_root = resolve_demo_root(root)
    demo_root.mkdir(parents=True, exist_ok=True)
    data_dir = demo_root / DEMO_DATA_NAME
    locked_dir = demo_root / LOCKED_DATA_NAME

    if locked_dir.exists() and not data_dir.exists():
        locked_dir.rename(data_dir)

    data_dir.mkdir(exist_ok=True)
    (data_dir / "family_notes.txt").write_text(
        "Controlled demo data. This file is safe to rename during the simulator demo.\n",
        encoding="utf-8",
    )
    (data_dir / "sample_invoice.txt").write_text(
        "Invoice demo content for Image Analysis Workbench threat simulation.\n",
        encoding="utf-8",
    )

    for readme in (data_dir / README_NAME, locked_dir / README_NAME, demo_root / README_NAME):
        if readme.exists():
            readme.unlink()

    pid_file = demo_root / PID_FILE_NAME
    if pid_file.exists() and not _pid_running(_read_pid(pid_file)):
        pid_file.unlink()

    return inspect_demo_state(demo_root)


def launch_threat_simulator(root: str | Path | None = None, hold_seconds: float = 300.0) -> dict:
    demo_root = resolve_demo_root(root)
    prepare_demo_workspace(demo_root)

    command = [
        sys.executable,
        "-m",
        "live_monitor.threat_simulator",
        "--root",
        str(demo_root),
        "--hold-seconds",
        str(max(1.0, float(hold_seconds))),
    ]
    creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
    process = subprocess.Popen(
        command,
        cwd=str(Path(__file__).resolve().parents[1]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    _RUNNING_SIMULATORS.append(process)
    (demo_root / PID_FILE_NAME).write_text(str(process.pid), encoding="utf-8")

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        state = inspect_demo_state(demo_root)
        if state["locked"]:
            return monitor_demo_report(demo_root)
        time.sleep(0.1)

    return monitor_demo_report(demo_root)


def launch_target_file_simulator(
    target_path: str | Path | None = None,
    hold_seconds: float = 300.0,
) -> dict:
    target = resolve_target_file(target_path)
    locked = locked_target_file(target)
    if not target.exists() and not locked.exists():
        return target_file_report(
            target,
            status="Target Missing",
            message=f"Target file was not found: {target}",
        )

    command = [
        sys.executable,
        "-m",
        "live_monitor.threat_simulator",
        "--target-file",
        str(target),
        "--hold-seconds",
        str(max(1.0, float(hold_seconds))),
    ]
    creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
    process = subprocess.Popen(
        command,
        cwd=str(Path(__file__).resolve().parents[1]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    _RUNNING_SIMULATORS.append(process)
    TARGET_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    TARGET_PID_FILE.write_text(str(process.pid), encoding="utf-8")

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        state = inspect_target_file_state(target)
        if state["locked"]:
            return target_file_report(target)
        time.sleep(0.1)

    return target_file_report(target)


def contain_threat(root: str | Path | None = None) -> dict:
    demo_root = resolve_demo_root(root)
    pid_file = demo_root / PID_FILE_NAME
    pid = _read_pid(pid_file)
    terminated = _terminate_pid(pid)

    locked_dir = demo_root / LOCKED_DATA_NAME
    data_dir = demo_root / DEMO_DATA_NAME
    if locked_dir.exists():
        if data_dir.exists():
            for child in locked_dir.iterdir():
                target = data_dir / child.name
                if not target.exists():
                    child.rename(target)
            locked_dir.rmdir()
        else:
            locked_dir.rename(data_dir)

    for readme in (data_dir / README_NAME, demo_root / README_NAME):
        if readme.exists():
            readme.unlink()
    if pid_file.exists():
        pid_file.unlink()

    state = inspect_demo_state(demo_root)
    return {
        "supported": True,
        "threat_simulator": True,
        "threat_status": "Threat Contained",
        "started_at": utc_now(),
        "ended_at": utc_now(),
        "events": [],
        "summary": _summary([]),
        "demo_state": {**state, "terminated_process": terminated},
        "message": "Controlled simulator was contained and DemoData was restored.",
    }


def contain_target_file_threat(target_path: str | Path | None = None) -> dict:
    target = resolve_target_file(target_path)
    locked = locked_target_file(target)
    pid = _read_pid(TARGET_PID_FILE)
    terminated = _terminate_pid(pid)

    restored = False
    if locked.exists() and not target.exists():
        locked.rename(target)
        restored = True
        write_action_log(
            action="restore",
            previous_path=locked,
            current_path=target,
            pid=pid,
            note="Containment restored the original file name.",
        )

    if TARGET_PID_FILE.exists():
        TARGET_PID_FILE.unlink()

    state = inspect_target_file_state(target)
    return {
        "supported": True,
        "threat_simulator": True,
        "target_file_simulator": True,
        "threat_status": "Threat Contained",
        "started_at": utc_now(),
        "ended_at": utc_now(),
        "events": [],
        "summary": _summary([]),
        "demo_state": {**state, "terminated_process": terminated, "restored": restored},
        "message": "Controlled target-file simulator was contained and the file name was restored.",
    }


def monitor_demo_report(root: str | Path | None = None) -> dict:
    demo_root = resolve_demo_root(root)
    state = inspect_demo_state(demo_root)
    events = [_threat_event(state)] if state["locked"] else []
    status = "Threat Active" if events else "Ready"
    return {
        "supported": True,
        "threat_simulator": True,
        "threat_status": status,
        "started_at": utc_now(),
        "ended_at": utc_now(),
        "events": events,
        "summary": _summary(events),
        "demo_state": state,
        "message": "Controlled simulator state was checked.",
    }


def target_file_report(
    target_path: str | Path | None = None,
    status: str | None = None,
    message: str | None = None,
) -> dict:
    target = resolve_target_file(target_path)
    state = inspect_target_file_state(target)
    events = [_target_file_event(state)] if state["locked"] else []
    threat_status = status or ("Threat Active" if events else "Ready")
    return {
        "supported": True,
        "threat_simulator": True,
        "target_file_simulator": True,
        "threat_status": threat_status,
        "started_at": utc_now(),
        "ended_at": utc_now(),
        "events": events,
        "summary": _summary(events),
        "demo_state": state,
        "message": message or "Controlled target-file simulator state was checked.",
    }


def inspect_demo_state(root: str | Path | None = None) -> dict:
    demo_root = resolve_demo_root(root)
    data_dir = demo_root / DEMO_DATA_NAME
    locked_dir = demo_root / LOCKED_DATA_NAME
    pid_file = demo_root / PID_FILE_NAME
    pid = _read_pid(pid_file)
    readme_path = locked_dir / README_NAME
    return {
        "demo_root": str(demo_root),
        "device_name": platform.node() or "unknown",
        "demo_data_path": str(data_dir),
        "locked_data_path": str(locked_dir),
        "demo_data_exists": data_dir.exists(),
        "locked": locked_dir.exists(),
        "readme_created": readme_path.exists(),
        "readme_path": str(readme_path),
        "simulator_pid": pid,
        "simulator_running": _pid_running(pid),
    }


def inspect_target_file_state(target_path: str | Path | None = None) -> dict:
    target = resolve_target_file(target_path)
    locked = locked_target_file(target)
    pid = _read_pid(TARGET_PID_FILE)
    return {
        "device_name": platform.node() or "unknown",
        "target_file_demo": True,
        "original_path": str(target),
        "locked_path": str(locked),
        "previous_name": target.name,
        "current_name": locked.name if locked.exists() else target.name,
        "original_exists": target.exists(),
        "locked": locked.exists(),
        "readme_created": ACTION_LOG_FILE.exists(),
        "readme_path": str(ACTION_LOG_FILE.resolve()),
        "simulator_pid": pid,
        "simulator_running": _pid_running(pid),
    }


def run_simulator(root: str | Path | None = None, hold_seconds: float = 300.0) -> None:
    demo_root = resolve_demo_root(root)
    demo_root.mkdir(parents=True, exist_ok=True)
    data_dir = demo_root / DEMO_DATA_NAME
    locked_dir = demo_root / LOCKED_DATA_NAME
    if not data_dir.exists() and not locked_dir.exists():
        data_dir.mkdir()
        (data_dir / "sample_invoice.txt").write_text("Demo content.\n", encoding="utf-8")
    if data_dir.exists() and not locked_dir.exists():
        data_dir.rename(locked_dir)

    locked_dir.mkdir(exist_ok=True)
    (locked_dir / README_NAME).write_text(
        "CONTROLLED DEMO ONLY\n"
        f"Device: {platform.node() or 'unknown'}\n"
        "DemoData was renamed to DemoData_LOCKED so the monitor can show containment.\n",
        encoding="utf-8",
    )
    (demo_root / PID_FILE_NAME).write_text(str(os.getpid()), encoding="utf-8")

    end = time.monotonic() + max(1.0, float(hold_seconds))
    while time.monotonic() < end:
        time.sleep(0.5)


def run_target_file_simulator(
    target_path: str | Path | None = None,
    hold_seconds: float = 300.0,
) -> None:
    target = resolve_target_file(target_path)
    locked = locked_target_file(target)
    if target.exists() and not locked.exists():
        target.rename(locked)
        write_action_log(
            action="rename",
            previous_path=target,
            current_path=locked,
            pid=os.getpid(),
            note="Controlled target-file simulator renamed the requested file.",
        )
    TARGET_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    TARGET_PID_FILE.write_text(str(os.getpid()), encoding="utf-8")

    end = time.monotonic() + max(1.0, float(hold_seconds))
    while time.monotonic() < end:
        time.sleep(0.5)


def resolve_target_file(target_path: str | Path | None = None) -> Path:
    return Path(target_path or DEFAULT_TARGET_FILE).resolve()


def locked_target_file(target_path: str | Path) -> Path:
    target = Path(target_path)
    return target.with_name(f"{target.stem}_LOCKED{target.suffix}")


def write_action_log(
    action: str,
    previous_path: str | Path,
    current_path: str | Path,
    pid: int,
    note: str,
) -> None:
    previous = Path(previous_path)
    current = Path(current_path)
    ACTION_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = "\n".join(
        [
            "CONTROLLED TARGET FILE SIMULATOR",
            f"timestamp: {utc_now()}",
            f"device_name: {platform.node() or 'unknown'}",
            f"action: {action}",
            f"simulator_pid: {pid}",
            f"previous_name: {previous.name}",
            f"current_name: {current.name}",
            f"previous_path: {previous}",
            f"current_path: {current}",
            f"note: {note}",
            "",
        ]
    )
    with ACTION_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(entry)


def _threat_event(state: dict) -> dict:
    return {
        "timestamp": utc_now(),
        "severity": "HIGH",
        "category": "controlled_file_lock_simulation",
        "pid": state.get("simulator_pid") or 0,
        "process_name": "controlled_threat_simulator",
        "process_path": __file__,
        "parent_pid": None,
        "parent_name": "",
        "thread_id": None,
        "score": 90,
        "message": "Controlled simulator renamed DemoData and created READ_ME.txt",
        "evidence": {
            "device_name": state.get("device_name", "unknown"),
            "demo_root": state.get("demo_root", ""),
            "locked_data_path": state.get("locked_data_path", ""),
            "readme_path": state.get("readme_path", ""),
            "scope": "project-owned demo folder only",
        },
    }


def _target_file_event(state: dict) -> dict:
    return {
        "timestamp": utc_now(),
        "severity": "HIGH",
        "category": "controlled_target_file_rename",
        "pid": state.get("simulator_pid") or 0,
        "process_name": "controlled_target_file_simulator",
        "process_path": __file__,
        "parent_pid": None,
        "parent_name": "",
        "thread_id": None,
        "score": 90,
        "message": "Controlled simulator renamed the requested PDF and wrote output/readme.txt",
        "evidence": {
            "device_name": state.get("device_name", "unknown"),
            "previous_name": state.get("previous_name", ""),
            "current_name": state.get("current_name", ""),
            "original_path": state.get("original_path", ""),
            "locked_path": state.get("locked_path", ""),
            "readme_path": state.get("readme_path", ""),
            "scope": "single user-provided target file",
        },
    }


def _summary(events: list[dict]) -> dict:
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_counts: dict[str, int] = {}
    risk_score = 0
    for event in events:
        severity = str(event.get("severity", "LOW"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category = str(event.get("category", "unknown"))
        category_counts[category] = category_counts.get(category, 0) + 1
        risk_score += int(event.get("score", 0))
    return {
        "risk_score": risk_score,
        "event_count": len(events),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
    }


def _read_pid(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def _pid_running(pid: int) -> bool:
    if not pid:
        return False
    if psutil is not None:
        return psutil.pid_exists(pid)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _terminate_pid(pid: int) -> bool:
    if not pid:
        return False
    for process in list(_RUNNING_SIMULATORS):
        if process.pid == pid:
            try:
                process.terminate()
                process.wait(timeout=3)
                _RUNNING_SIMULATORS.remove(process)
                return True
            except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
                break
    if psutil is not None:
        try:
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            return False
    if platform.system() == "Windows":
        completed = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return completed.returncode == 0
    try:
        os.kill(pid, 15)
        return True
    except OSError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the controlled file-lock threat simulator.")
    parser.add_argument("--root", default=str(DEMO_ROOT))
    parser.add_argument("--target-file", default="")
    parser.add_argument("--hold-seconds", type=float, default=300.0)
    args = parser.parse_args()
    if args.target_file:
        run_target_file_simulator(args.target_file, args.hold_seconds)
    else:
        run_simulator(args.root, args.hold_seconds)


if __name__ == "__main__":
    main()
