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
        chain_events = [event for event in events if event.category == "suspicious_process_tree"]

        self.assertEqual(len(chain_events), 1)
        self.assertEqual(chain_events[0].severity, "HIGH")

    def test_suspicious_command_line_flags_encoded_powershell(self):
        parent = ProcessInfo(pid=100, parent_pid=4, name="explorer.exe", path=r"C:\Windows\explorer.exe")
        child = ProcessInfo(
            pid=101,
            parent_pid=100,
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA",
        )

        events = self.rules.process_start_events(child, parent)
        categories = {event.category for event in events}

        self.assertIn("suspicious_command_line", categories)

    def test_lolbin_referencing_downloads_script_is_flagged(self):
        parent = ProcessInfo(pid=100, parent_pid=4, name="explorer.exe", path=r"C:\Windows\explorer.exe")
        child = ProcessInfo(
            pid=101,
            parent_pid=100,
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r'powershell.exe -File "C:\Users\Alice\Downloads\live_monitor_probe.ps1"',
        )

        events = self.rules.process_start_events(child, parent)

        self.assertIn("user_writable_script_argument", {event.category for event in events})

    def test_background_lolbin_parent_is_distinguished_from_interactive_parent(self):
        background_parent = ProcessInfo(pid=200, parent_pid=4, name="services.exe", path=r"C:\Windows\System32\services.exe")
        interactive_parent = ProcessInfo(pid=201, parent_pid=4, name="explorer.exe", path=r"C:\Windows\explorer.exe")
        child = ProcessInfo(
            pid=202,
            parent_pid=200,
            name="cmd.exe",
            path=r"C:\Windows\System32\cmd.exe",
            command_line=r"cmd.exe /c whoami",
        )

        background_events = self.rules.process_start_events(child, background_parent)
        interactive_events = self.rules.process_start_events(child, interactive_parent)

        self.assertIn("background_lolbin_launch", {event.category for event in background_events})
        self.assertNotIn("background_lolbin_launch", {event.category for event in interactive_events})

    def test_untrusted_user_writable_process_is_high_severity(self):
        process = ProcessInfo(
            pid=300,
            parent_pid=100,
            name="invoice_viewer.exe",
            path=r"C:\Users\Alice\Downloads\invoice_viewer.exe",
            signer_status="NOTSIGNED",
        )

        events = self.rules.process_start_events(process, None)
        categories = {event.category for event in events}

        self.assertIn("unsigned_user_writable_process", categories)

    def test_unknown_signature_user_writable_process_path_alone_is_not_reported(self):
        parent = ProcessInfo(pid=100, parent_pid=4, name="explorer.exe", path=r"C:\Windows\explorer.exe")
        process = ProcessInfo(
            pid=300,
            parent_pid=100,
            name="setup.exe",
            path=r"C:\Users\Alice\Downloads\setup.exe",
            signer_status="UNKNOWN",
        )

        events = self.rules.process_start_events(process, parent)

        self.assertNotIn("user_writable_process_path", {event.category for event in events})

    def test_vscode_user_updater_temp_process_is_suppressed(self):
        parent = ProcessInfo(
            pid=19144,
            parent_pid=100,
            name="Code.exe",
            path=r"C:\Users\HP\AppData\Local\Programs\Microsoft VS Code\Code.exe",
            signer_status="UNKNOWN",
        )
        process = ProcessInfo(
            pid=9744,
            parent_pid=19144,
            name="CodeSetup-stable-974500e64f0d1cfdf7c9821a2a51c2cb3bf0e561.exe",
            path=r"C:\Users\HP\AppData\Local\Temp\vscode-stable-user-x64\CodeSetup-stable-974500e64f0d1cfdf7c9821a2a51c2cb3bf0e561.exe",
            signer_status="UNKNOWN",
        )

        events = self.rules.process_start_events(process, parent)

        self.assertEqual([], events)

    def test_vscode_inner_temp_updater_process_is_suppressed(self):
        parent = ProcessInfo(
            pid=9744,
            parent_pid=19144,
            name="CodeSetup-stable-974500e64f0d1cfdf7c9821a2a51c2cb3bf0e561.exe",
            path=r"C:\Users\HP\AppData\Local\Temp\vscode-stable-user-x64\CodeSetup-stable-974500e64f0d1cfdf7c9821a2a51c2cb3bf0e561.exe",
            signer_status="UNKNOWN",
        )
        process = ProcessInfo(
            pid=10752,
            parent_pid=9744,
            name="CodeSetup-stable-974500e64f0d1cfdf7c9821a2a51c2cb3bf0e561.tmp",
            path=r"C:\Users\HP\AppData\Local\Temp\is-O9GHF.tmp\CodeSetup-stable-974500e64f0d1cfdf7c9821a2a51c2cb3bf0e561.tmp",
            signer_status="UNKNOWN",
        )

        events = self.rules.process_start_events(process, parent)

        self.assertEqual([], events)

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

    def test_executable_to_noaccess_transition_flags_sleep_obfuscation(self):
        owner = ProcessInfo(pid=500, parent_pid=4, name="lsass.exe", path=r"C:\Windows\System32\lsass.exe")
        watched = self._watched_region(previous_protection=0x40)
        current = MemoryRegion(
            base_address=0x200000,
            size=8192,
            protection=WindowsApiProbe.PAGE_NOACCESS,
            region_type=WindowsApiProbe.MEM_PRIVATE,
            state=WindowsApiProbe.MEM_COMMIT,
        )

        events = self.rules.page_transition_events(owner, watched, current)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "CRITICAL")
        self.assertEqual(events[0].category, "sleep_obfuscation_page_transition")

    def test_non_executable_transition_does_not_trigger_sleep_obfuscation(self):
        owner = ProcessInfo(pid=500, parent_pid=4, name="lsass.exe", path=r"C:\Windows\System32\lsass.exe")
        watched = self._watched_region(previous_protection=0x04)
        current = MemoryRegion(
            base_address=0x200000,
            size=8192,
            protection=WindowsApiProbe.PAGE_NOACCESS,
            region_type=WindowsApiProbe.MEM_PRIVATE,
            state=WindowsApiProbe.MEM_COMMIT,
        )

        self.assertEqual(self.rules.page_transition_events(owner, watched, current), [])

    def test_jit_heavy_browsers_are_not_memory_scanned_for_region_only_alerts(self):
        browser = ProcessInfo(pid=20, parent_pid=4, name="chrome.exe", path=r"C:\Program Files\Chrome\chrome.exe")

        self.assertFalse(self.rules.should_memory_scan(browser, is_new_process=True))

    def test_self_test_report_contains_true_positive_behavior_events(self):
        report = WindowsBehaviorMonitor(MonitorConfig(duration_seconds=5)).self_test_report()
        categories = {event["category"] for event in report["events"]}

        self.assertTrue(report["self_test"])
        self.assertIn("suspicious_process_tree", categories)
        self.assertIn("private_executable_thread_start", categories)
        self.assertIn("sleep_obfuscation_page_transition", categories)
        self.assertGreater(report["summary"]["risk_score"], 0)

    @staticmethod
    def _watched_region(previous_protection: int):
        from live_monitor.windows_monitor import WatchedRegion

        return WatchedRegion(
            pid=500,
            base_address=0x200000,
            size=8192,
            previous_protection=previous_protection,
            first_seen=0.0,
            last_seen=0.0,
            source="unit test",
            thread_id=123,
        )


if __name__ == "__main__":
    unittest.main()
