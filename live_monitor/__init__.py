"""Windows live monitoring package.

This package is intentionally independent from the image converter and static
malware scanner modules. It provides a bounded, user-mode behavioral monitor
for process and memory telemetry on Windows.
"""

from .windows_monitor import MonitorConfig, MonitorEvent, WindowsBehaviorMonitor

__all__ = ["MonitorConfig", "MonitorEvent", "WindowsBehaviorMonitor"]
