from __future__ import annotations

import argparse
import base64
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path


if platform.system() != "Windows":
    raise SystemExit("This simulator is Windows-only.")


def downloads_dir() -> Path:
    return Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Downloads"


def launch_benign_user_process() -> subprocess.Popen:
    print("Launching benign user process: notepad.exe")
    return subprocess.Popen(["notepad.exe"])


def launch_encoded_powershell() -> subprocess.Popen:
    command = "Start-Sleep -Seconds 12"
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    print("Launching suspicious PowerShell with -EncodedCommand and hidden window.")
    return subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            encoded,
        ],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def launch_downloads_script() -> subprocess.Popen:
    target_dir = downloads_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    script_path = target_dir / "live_monitor_probe.ps1"
    script_path.write_text("Start-Sleep -Seconds 12\n", encoding="utf-8")
    print(f"Launching PowerShell script from user-writable path: {script_path}")
    return subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ]
    )


def launch_scheduled_task() -> subprocess.Popen:
    task_name = r"\LiveMonitorProbe"
    command = "Start-Sleep -Seconds 15"
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    run_time = (datetime.now() + timedelta(minutes=1)).strftime("%H:%M")
    task_command = f'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {encoded}'

    print("Launching PowerShell through Windows Task Scheduler.")
    subprocess.run(
        [
            "schtasks.exe",
            "/Create",
            "/TN",
            task_name,
            "/TR",
            task_command,
            "/SC",
            "ONCE",
            "/ST",
            run_time,
            "/F",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    subprocess.run(["schtasks.exe", "/Run", "/TN", task_name], check=False, capture_output=True, text=True)
    time.sleep(3)
    subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], check=False, capture_output=True, text=True)
    return subprocess.Popen(["cmd.exe", "/c", "timeout", "/t", "15", "/nobreak"], creationflags=subprocess.CREATE_NO_WINDOW)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate process-origin events for the live monitor.")
    parser.add_argument(
        "scenario",
        choices=["benign-user", "encoded-powershell", "downloads-script", "scheduled-task", "all"],
        help="Process launch scenario to run.",
    )
    args = parser.parse_args()

    scenarios = {
        "benign-user": [launch_benign_user_process],
        "encoded-powershell": [launch_encoded_powershell],
        "downloads-script": [launch_downloads_script],
        "scheduled-task": [launch_scheduled_task],
        "all": [launch_benign_user_process, launch_encoded_powershell, launch_downloads_script, launch_scheduled_task],
    }

    processes = []
    for launch in scenarios[args.scenario]:
        processes.append(launch())
        time.sleep(2)

    print("Keeping simulator alive for 15 seconds so the monitor can observe child processes.")
    time.sleep(15)

    for process in processes:
        if process.poll() is None and process.args == ["notepad.exe"]:
            process.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
