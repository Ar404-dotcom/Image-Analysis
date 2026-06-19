"""Windows live monitoring package.

This package is intentionally independent from the image converter and static
malware scanner modules. It provides a bounded, user-mode behavioral monitor
for process and memory telemetry on Windows.
"""

from .threat_simulator import (
    DEFAULT_TARGET_FILE,
    contain_target_file_threat,
    contain_threat,
    launch_target_file_simulator,
    launch_threat_simulator,
    monitor_demo_report,
    prepare_demo_workspace,
    target_file_report,
)
from .windows_monitor import MonitorConfig, MonitorEvent, NetworkPortInfo, WindowsBehaviorMonitor

__all__ = [
    "MonitorConfig",
    "MonitorEvent",
    "NetworkPortInfo",
    "WindowsBehaviorMonitor",
    "DEFAULT_TARGET_FILE",
    "contain_target_file_threat",
    "contain_threat",
    "launch_target_file_simulator",
    "launch_threat_simulator",
    "monitor_demo_report",
    "prepare_demo_workspace",
    "target_file_report",
]
