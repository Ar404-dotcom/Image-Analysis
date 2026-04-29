import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from live_monitor.windows_monitor import (
    BehaviorRuleEngine,
    MemoryRegion,
    MonitorConfig,
    ProcessInfo,
    ThreadInfo,
    WindowsBehaviorMonitor,
    WindowsApiProbe,
)


class LiveMonitorRuleTests(unittest.TestCase):
    def setUp(self):
        self.rules = BehaviorRuleEngine()

    def test_exploit_prone_parent_spawning_lolbin_is_high_severity(self):
        parent = ProcessInfo(pid=100, parent_pid=4, name="WINWORD.EXE", path=r"C:\Program Files\Office\WINWORD.EXE")
        child = ProcessInfo(pid=101, parent_pid=100, name="powershell.exe", path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")

        events = self.rules.process_start_events(child, parent)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "HIGH")
        self.assertEqual(events[0].category, "suspicious_process_tree")

    def test_thread_start_in_private_executable_memory_is_critical_for_sensitive_process(self):
        owner = ProcessInfo(pid=500, parent_pid=4, name="lsass.exe", path=r"C:\Windows\System32\lsass.exe")
        region = MemoryRegion(
            base_address=0x100000,
            size=4096,
            protection=0x40,
            region_type=WindowsApiProbe.MEM_PRIVATE,
            state=WindowsApiProbe.MEM_COMMIT,
        )
        thread = ThreadInfo(tid=900, owner_pid=500, start_address=0x100100, start_region=region)

        events = self.rules.thread_start_events(thread, owner)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "CRITICAL")
        self.assertEqual(events[0].category, "private_executable_thread_start")

    def test_private_executable_memory_alerts_are_limited_to_non_jit_sensitive_targets(self):
        sensitive = ProcessInfo(pid=10, parent_pid=4, name="lsass.exe", path=r"C:\Windows\System32\lsass.exe")
        ordinary = ProcessInfo(pid=11, parent_pid=4, name="notepad.exe", path=r"C:\Windows\System32\notepad.exe")
        browser = ProcessInfo(pid=12, parent_pid=4, name="chrome.exe", path=r"C:\Program Files\Chrome\chrome.exe")
        region = MemoryRegion(
            base_address=0x200000,
            size=8192,
            protection=0x20,
            region_type=WindowsApiProbe.MEM_PRIVATE,
            state=WindowsApiProbe.MEM_COMMIT,
        )

        self.assertEqual(len(self.rules.memory_region_events(sensitive, region)), 1)
        self.assertEqual(self.rules.memory_region_events(ordinary, region), [])
        self.assertEqual(self.rules.memory_region_events(browser, region), [])

    def test_jit_heavy_browsers_are_not_memory_scanned_for_region_only_alerts(self):
        browser = ProcessInfo(pid=20, parent_pid=4, name="chrome.exe", path=r"C:\Program Files\Chrome\chrome.exe")

        self.assertFalse(self.rules.should_memory_scan(browser, is_new_process=True))

    def test_self_test_report_contains_true_positive_behavior_events(self):
        report = WindowsBehaviorMonitor(MonitorConfig(duration_seconds=5)).self_test_report()
        categories = {event["category"] for event in report["events"]}

        self.assertTrue(report["self_test"])
        self.assertIn("suspicious_process_tree", categories)
        self.assertIn("private_executable_thread_start", categories)
        self.assertGreater(report["summary"]["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
