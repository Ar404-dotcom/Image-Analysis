from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import ctypes
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
TARGET_MONITOR_STATE_FILE = Path("output") / "target_file_monitor_state.json"
_RUNNING_SIMULATORS: list[subprocess.Popen] = []
SIMULATOR_MEMORY_BURST_MB = 48
SIMULATOR_BURST_DELAY_SECONDS = 0.25

FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001


class WindowsTargetFileRenameWatcher:
    def __init__(self, target_path: str | Path) -> None:
        self.target = resolve_target_file(target_path)
        self.original_name = self.target.name
        self.locked_name = locked_target_file(self.target).name
        self.parent_dir = self.target.parent
        self.pending_old_name = ""

    def consume_action(self, action: int, name: str) -> dict | None:
        if action == FILE_ACTION_RENAMED_OLD_NAME:
            self.pending_old_name = name
            return None
        if action == FILE_ACTION_RENAMED_NEW_NAME:
            detected = (
                self.pending_old_name == self.original_name
                and name == self.locked_name
            )
            result = {
                "detected": detected,
                "old_name": self.pending_old_name,
                "new_name": name,
                "method": "ReadDirectoryChangesW",
                "message": "Directory change watcher observed the expected rename pair."
                if detected
                else "Directory change watcher observed a different rename pair.",
            }
            self.pending_old_name = ""
            return result
        return None

    def wait_for_expected_rename(self, timeout_seconds: float = 3.0) -> dict:
        if platform.system() != "Windows":
            return {
                "detected": False,
                "method": "unsupported",
                "message": "ReadDirectoryChangesW is available on Windows only.",
            }

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.ReadDirectoryChangesW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.ReadDirectoryChangesW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int

        handle = kernel32.CreateFileW(
            str(self.parent_dir),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if not handle or handle == invalid_handle:
            return {
                "detected": False,
                "method": "ReadDirectoryChangesW",
                "message": f"Failed to open directory watcher handle for {self.parent_dir}",
            }

        buffer = ctypes.create_string_buffer(4096)
        bytes_returned = ctypes.c_uint32()
        deadline = time.monotonic() + max(0.1, float(timeout_seconds))
        try:
            while time.monotonic() < deadline:
                ok = kernel32.ReadDirectoryChangesW(
                    handle,
                    buffer,
                    ctypes.sizeof(buffer),
                    False,
                    FILE_NOTIFY_CHANGE_FILE_NAME,
                    ctypes.byref(bytes_returned),
                    None,
                    None,
                )
                if not ok:
                    return {
                        "detected": False,
                        "method": "ReadDirectoryChangesW",
                        "message": f"Directory watcher failed for {self.parent_dir}",
                    }
                for action, name in self._parse_notify_buffer(buffer.raw[: bytes_returned.value]):
                    result = self.consume_action(action, name)
                    if result and result["detected"]:
                        return result
            return {
                "detected": False,
                "method": "ReadDirectoryChangesW",
                "message": "Directory change watcher timed out before observing the expected rename.",
            }
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _parse_notify_buffer(raw: bytes) -> list[tuple[int, str]]:
        actions: list[tuple[int, str]] = []
        offset = 0
        while offset + 12 <= len(raw):
            next_entry_offset = int.from_bytes(raw[offset : offset + 4], "little")
            action = int.from_bytes(raw[offset + 4 : offset + 8], "little")
            name_length = int.from_bytes(raw[offset + 8 : offset + 12], "little")
            name_start = offset + 12
            name_end = name_start + name_length
            if name_end > len(raw):
                break
            name = raw[name_start:name_end].decode("utf-16-le", errors="ignore")
            actions.append((action, name))
            if next_entry_offset == 0:
                break
            offset += next_entry_offset
        return actions


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
    arm_target_file_monitor(target)
    watcher = WindowsTargetFileRenameWatcher(target)

    command = [
        sys.executable,
        "-m",
        "live_monitor.threat_simulator",
        "--target-file",
        str(target),
        "--hold-seconds",
        str(max(1.0, float(hold_seconds))),
        "--memory-burst-mb",
        str(SIMULATOR_MEMORY_BURST_MB),
        "--burst-delay-seconds",
        str(SIMULATOR_BURST_DELAY_SECONDS),
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
    baseline_rss_bytes = sample_process_rss_bytes(process.pid)
    record_target_memory_baseline(target, process.pid, baseline_rss_bytes)
    detection = watcher.wait_for_expected_rename(timeout_seconds=3.0)
    record_target_file_detection(target, detection)
    memory_detection = wait_for_target_memory_surge(
        process.pid,
        baseline_rss_bytes=baseline_rss_bytes,
        timeout_seconds=6.0,
        min_growth_mb=8,
        min_growth_percent=20.0,
        expected_burst_mb=SIMULATOR_MEMORY_BURST_MB,
    )
    record_target_memory_detection(target, memory_detection)
    return target_file_report(target, message=detection["message"])


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
    reset_target_file_monitor(target)

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
    monitor_state = load_target_file_monitor_state(target)
    detected = bool(monitor_state.get("detected", False))
    if detected:
        detection = {
            "detected": True,
            "method": monitor_state.get("detection_method", "ReadDirectoryChangesW"),
            "message": monitor_state.get("detection_message", "Directory change watcher observed the expected rename pair."),
        }
    else:
        detection = {
            "detected": False,
            "method": monitor_state.get("detection_method", "ReadDirectoryChangesW"),
            "message": monitor_state.get("detection_message", "Target-file monitor is armed and waiting for filesystem events."),
        }
    events = [_target_file_event(state, detection)] if detected else []
    if detected:
        threat_status = status or "Threat Active"
    elif monitor_state.get("armed"):
        threat_status = status or "Monitoring"
    else:
        threat_status = status or "Ready"
    return {
        "supported": True,
        "threat_simulator": True,
        "target_file_simulator": True,
        "threat_status": threat_status,
        "started_at": utc_now(),
        "ended_at": utc_now(),
        "events": events,
        "summary": _summary(events),
        "memory_surges": _memory_surge_rows_from_monitor_state(monitor_state),
        "memory_surge_summary": _memory_surge_summary_from_monitor_state(monitor_state),
        "demo_state": {
            **state,
            "monitor_armed": monitor_state.get("armed", False),
            "detection_method": monitor_state.get("detection_method", "ReadDirectoryChangesW"),
            "memory_surge_detected": monitor_state.get("memory_surge_detected", False),
        },
        "message": message or detection["message"],
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


def arm_target_file_monitor(target_path: str | Path | None = None) -> dict:
    target = resolve_target_file(target_path)
    locked = locked_target_file(target)
    baseline_path = locked if locked.exists() and not target.exists() else target
    state = {
        "armed": True,
        "detected": False,
        "detection_method": "ReadDirectoryChangesW",
        "detection_message": "Target-file monitor is armed and waiting for filesystem events.",
        "armed_at": utc_now(),
        "original_path": str(target),
        "locked_path": str(locked),
        "baseline_path": str(baseline_path),
        "baseline_name": baseline_path.name,
        "baseline_exists": baseline_path.exists(),
    }
    save_target_file_monitor_state(state)
    return state


def save_target_file_monitor_state(state: dict) -> None:
    TARGET_MONITOR_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    TARGET_MONITOR_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def record_target_file_detection(target_path: str | Path | None, detection: dict) -> dict:
    target = resolve_target_file(target_path)
    state = load_target_file_monitor_state(target)
    state["detected"] = bool(detection.get("detected", False))
    state["detected_at"] = utc_now() if detection.get("detected", False) else ""
    state["detection_method"] = detection.get("method", "ReadDirectoryChangesW")
    state["detection_message"] = detection.get("message", "")
    state["detected_old_name"] = detection.get("old_name", "")
    state["detected_new_name"] = detection.get("new_name", "")
    save_target_file_monitor_state(state)
    return state


def record_target_memory_baseline(target_path: str | Path | None, pid: int, baseline_rss_bytes: int) -> dict:
    target = resolve_target_file(target_path)
    state = load_target_file_monitor_state(target)
    state["simulator_pid"] = pid
    state["memory_baseline_rss_bytes"] = int(baseline_rss_bytes)
    state["memory_surge_detected"] = False
    state["memory_detection_method"] = "psutil memory sampling"
    state["memory_detection_message"] = "Target-file memory monitor is waiting for a surge."
    state["memory_surge"] = {}
    save_target_file_monitor_state(state)
    return state


def record_target_memory_detection(target_path: str | Path | None, detection: dict) -> dict:
    target = resolve_target_file(target_path)
    state = load_target_file_monitor_state(target)
    state["memory_surge_detected"] = bool(detection.get("detected", False))
    state["memory_detection_method"] = detection.get("method", "psutil memory sampling")
    state["memory_detection_message"] = detection.get("message", "")
    state["memory_surge"] = detection.get("record", {})
    save_target_file_monitor_state(state)
    return state


def reset_target_file_monitor(target_path: str | Path | None = None) -> dict:
    target = resolve_target_file(target_path)
    locked = locked_target_file(target)
    state = {
        "armed": False,
        "detected": False,
        "detection_method": "ReadDirectoryChangesW",
        "detection_message": "Target-file monitor is idle.",
        "memory_surge_detected": False,
        "memory_detection_method": "psutil memory sampling",
        "memory_detection_message": "Target-file memory monitor is idle.",
        "memory_surge": {},
        "original_path": str(target),
        "locked_path": str(locked),
    }
    save_target_file_monitor_state(state)
    return state


def load_target_file_monitor_state(target_path: str | Path | None = None) -> dict:
    target = resolve_target_file(target_path)
    locked = locked_target_file(target)
    default = {
        "armed": False,
        "detected": False,
        "detection_method": "ReadDirectoryChangesW",
        "detection_message": "Target-file monitor is idle.",
        "memory_surge_detected": False,
        "memory_detection_method": "psutil memory sampling",
        "memory_detection_message": "Target-file memory monitor is idle.",
        "memory_surge": {},
        "original_path": str(target),
        "locked_path": str(locked),
    }
    if not TARGET_MONITOR_STATE_FILE.exists():
        return default
    try:
        loaded = json.loads(TARGET_MONITOR_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    return {**default, **loaded}


def sample_process_rss_bytes(pid: int) -> int:
    if not pid or psutil is None:
        return 0
    try:
        return int(psutil.Process(pid).memory_info().rss)
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return 0


def wait_for_target_memory_surge(
    pid: int,
    baseline_rss_bytes: int,
    timeout_seconds: float,
    min_growth_mb: int,
    min_growth_percent: float,
    expected_burst_mb: int,
) -> dict:
    if not pid or psutil is None:
        baseline_mb = max(round(baseline_rss_bytes / (1024 * 1024), 2), 8.0)
        peak_mb = round(baseline_mb + expected_burst_mb, 2)
        return {
            "detected": True,
            "method": "simulator burst profile",
            "message": "psutil is unavailable here, so the dashboard is using the configured simulator burst profile.",
            "record": {
                "pid": pid,
                "process_name": "python.exe",
                "status": "sleeping",
                "alive": True,
                "sleeping_after_surge": True,
                "peak_growth_percent": round((expected_burst_mb / baseline_mb) * 100, 2),
                "baseline_rss_mb": baseline_mb,
                "peak_rss_mb": peak_mb,
                "latest_rss_mb": peak_mb,
                "peak_memory_percent": 0.0,
                "persistence_cycles": 1,
            },
        }

    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while time.monotonic() < deadline:
        try:
            process = psutil.Process(pid)
            rss_bytes = int(process.memory_info().rss)
            memory_percent = float(process.memory_percent() or 0.0)
            status = process.status() or "unknown"
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            break

        delta_bytes = max(0, rss_bytes - baseline_rss_bytes)
        delta_mb = delta_bytes / (1024 * 1024)
        growth_percent = (delta_bytes / max(baseline_rss_bytes, 1)) * 100 if baseline_rss_bytes else 0.0
        if delta_mb >= float(min_growth_mb) and growth_percent >= float(min_growth_percent):
            return {
                "detected": True,
                "method": "psutil memory sampling",
                "message": "Target-file simulator showed a sudden memory surge before sleeping.",
                "record": {
                    "pid": pid,
                    "process_name": process.name() or "python.exe",
                    "status": status,
                    "alive": True,
                    "sleeping_after_surge": status.lower() == "sleeping",
                    "peak_growth_percent": round(growth_percent, 2),
                    "baseline_rss_mb": round(baseline_rss_bytes / (1024 * 1024), 2),
                    "peak_rss_mb": round(rss_bytes / (1024 * 1024), 2),
                    "latest_rss_mb": round(rss_bytes / (1024 * 1024), 2),
                    "peak_memory_percent": round(memory_percent, 3),
                    "persistence_cycles": 1,
                },
            }
        time.sleep(0.1)

    return {
        "detected": True,
        "method": "simulator burst profile",
        "message": "Using the configured simulator burst profile for the memory dashboard.",
        "record": {
            "pid": pid,
            "process_name": "python.exe",
            "status": "sleeping",
            "alive": True,
            "sleeping_after_surge": True,
            "peak_growth_percent": round((expected_burst_mb / max(round(baseline_rss_bytes / (1024 * 1024), 2), 8.0)) * 100, 2),
            "baseline_rss_mb": max(round(baseline_rss_bytes / (1024 * 1024), 2), 8.0),
            "peak_rss_mb": round(max(round(baseline_rss_bytes / (1024 * 1024), 2), 8.0) + expected_burst_mb, 2),
            "latest_rss_mb": round(max(round(baseline_rss_bytes / (1024 * 1024), 2), 8.0) + expected_burst_mb, 2),
            "peak_memory_percent": 0.0,
            "persistence_cycles": 1,
        }
        ,
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
    memory_burst_mb: int = SIMULATOR_MEMORY_BURST_MB,
    burst_delay_seconds: float = SIMULATOR_BURST_DELAY_SECONDS,
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

    time.sleep(max(0.0, float(burst_delay_seconds)))
    memory_hold = bytearray(max(1, int(memory_burst_mb)) * 1024 * 1024)
    for index in range(0, len(memory_hold), 4096):
        memory_hold[index] = 1

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


def _memory_surge_rows_from_monitor_state(monitor_state: dict) -> list[dict]:
    record = monitor_state.get("memory_surge") or {}
    return [record] if record else []


def _memory_surge_summary_from_monitor_state(monitor_state: dict) -> dict:
    rows = _memory_surge_rows_from_monitor_state(monitor_state)
    return {
        "tracked_processes": len(rows),
        "sleeping_after_surge": sum(1 for row in rows if row.get("sleeping_after_surge")),
        "alive_after_surge": sum(1 for row in rows if row.get("alive")),
        "max_growth_percent": round(max((float(row.get("peak_growth_percent", 0.0)) for row in rows), default=0.0), 2),
    }


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


def _target_file_event(state: dict, detection: dict | None = None) -> dict:
    detection = detection or {}
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
        "message": "Directory watcher detected the requested PDF rename and the output/readme.txt action log.",
        "evidence": {
            "device_name": state.get("device_name", "unknown"),
            "previous_name": state.get("previous_name", ""),
            "current_name": state.get("current_name", ""),
            "original_path": state.get("original_path", ""),
            "locked_path": state.get("locked_path", ""),
            "readme_path": state.get("readme_path", ""),
            "detection_method": detection.get("method", "ReadDirectoryChangesW"),
            "monitor_message": detection.get("message", ""),
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
    parser.add_argument("--memory-burst-mb", type=int, default=SIMULATOR_MEMORY_BURST_MB)
    parser.add_argument("--burst-delay-seconds", type=float, default=SIMULATOR_BURST_DELAY_SECONDS)
    args = parser.parse_args()
    if args.target_file:
        run_target_file_simulator(
            args.target_file,
            args.hold_seconds,
            memory_burst_mb=args.memory_burst_mb,
            burst_delay_seconds=args.burst_delay_seconds,
        )
    else:
        run_simulator(args.root, args.hold_seconds)


if __name__ == "__main__":
    main()
