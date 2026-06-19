import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from live_monitor.windows_monitor import (
    BehaviorRuleEngine,
    MemorySurgeRecord,
    MemoryRegion,
    MonitorConfig,
    NetworkPortInfo,
    ProcessInfo,
    ProcessMemorySample,
    ThreadInfo,
    WindowsBehaviorMonitor,
    WindowsApiProbe,
    collect_demo_system_telemetry,
    listener_exposure,
    network_address_scope,
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

    def test_demo_telemetry_is_low_sensitivity_and_local_only(self):
        telemetry = collect_demo_system_telemetry()

        self.assertIn("device_name", telemetry)
        self.assertIn("os_version", telemetry)
        self.assertEqual(telemetry["destination"], "local Streamlit session state")
        self.assertEqual(telemetry["desktop_probe_scope"], "existence check only; no desktop files are read")

    def test_demo_recon_sleep_report_contains_detection_event_and_telemetry(self):
        report = WindowsBehaviorMonitor(MonitorConfig(duration_seconds=5)).demo_recon_sleep_report(sleep_seconds=0)
        categories = {event["category"] for event in report["events"]}

        self.assertTrue(report["self_test"])
        self.assertEqual(report["demo_type"], "local_reconnaissance_sleep")
        self.assertIn("demo_reconnaissance_then_sleep", categories)
        self.assertIn("demo_telemetry", report)
        self.assertGreater(report["summary"]["risk_score"], 0)
        self.assertEqual(report["configuration"]["demo_sleep_seconds"], 0.0)

    def test_network_address_scope_classifies_public_and_local_addresses(self):
        self.assertEqual(network_address_scope("8.8.8.8"), "public")
        self.assertEqual(network_address_scope("127.0.0.1"), "loopback")
        self.assertEqual(network_address_scope("0.0.0.0"), "all_interfaces")
        self.assertEqual(listener_exposure("0.0.0.0", "LISTEN"), "all_interfaces")

    def test_all_interface_listener_is_reported_as_low_risk(self):
        port = NetworkPortInfo(
            protocol="TCP",
            local_address="0.0.0.0",
            local_port=8080,
            status="LISTEN",
            pid=1234,
            process_name="sharing.exe",
            process_path=r"C:\Tools\sharing.exe",
        )

        events = self.rules.network_port_events(port)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "LOW")
        self.assertEqual(events[0].category, "network_listener_all_interfaces")

    def test_public_remote_control_or_file_port_is_reported(self):
        port = NetworkPortInfo(
            protocol="TCP",
            local_address="192.168.1.20",
            local_port=51555,
            remote_address="8.8.8.8",
            remote_port=3389,
            status="ESTABLISHED",
            pid=1234,
            process_name="remote.exe",
        )

        events = self.rules.network_port_events(port)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, "public_remote_control_or_file_port")

    def test_network_summary_counts_live_ports(self):
        ports = [
            NetworkPortInfo(protocol="TCP", local_address="0.0.0.0", local_port=8080, status="LISTEN"),
            NetworkPortInfo(
                protocol="TCP",
                local_address="192.168.1.20",
                local_port=51555,
                remote_address="8.8.8.8",
                remote_port=3389,
                status="ESTABLISHED",
            ),
        ]

        summary = WindowsBehaviorMonitor._network_summary(ports)

        self.assertEqual(summary["total_ports"], 2)
        self.assertEqual(summary["listeners"], 1)
        self.assertEqual(summary["established_public_connections"], 1)
        self.assertEqual(summary["exposed_listeners"], 1)

    def test_memory_growth_event_uses_percentage_increase(self):
        process = ProcessInfo(pid=700, parent_pid=4, name="allocator.exe", path=r"C:\Temp\allocator.exe")
        previous = ProcessMemorySample(pid=700, rss_bytes=20 * 1024 * 1024, memory_percent=0.5, status="running")
        current = ProcessMemorySample(pid=700, rss_bytes=80 * 1024 * 1024, memory_percent=2.5, status="running")

        events = self.rules.memory_growth_events(process, previous, current)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, "sudden_memory_growth")
        self.assertEqual(events[0].severity, "HIGH")
        self.assertGreater(events[0].evidence["growth_percent"], 200)

    def test_memory_surge_sleep_event_flags_sleep_like_status(self):
        process = ProcessInfo(pid=701, parent_pid=4, name="sleeper.exe", path=r"C:\Temp\sleeper.exe")
        record = MemorySurgeRecord(
            pid=701,
            process_name="sleeper.exe",
            process_path=r"C:\Temp\sleeper.exe",
            first_seen="2026-01-01T00:00:00+00:00",
            last_seen="2026-01-01T00:00:05+00:00",
            baseline_rss_bytes=10 * 1024 * 1024,
            peak_rss_bytes=120 * 1024 * 1024,
            latest_rss_bytes=120 * 1024 * 1024,
            peak_growth_percent=1100.0,
            latest_growth_percent=0.0,
            peak_memory_percent=4.2,
            latest_memory_percent=4.2,
            status="sleeping",
            persistence_cycles=3,
            sleeping_after_surge=True,
        )

        events = self.rules.memory_surge_sleep_events(process, record)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, "memory_surge_then_sleep")
        self.assertEqual(events[0].severity, "MEDIUM")

    def test_memory_surge_summary_counts_sleeping_and_alive_processes(self):
        records = {
            1: MemorySurgeRecord(
                pid=1,
                process_name="a.exe",
                process_path="",
                first_seen="x",
                last_seen="x",
                baseline_rss_bytes=1,
                peak_rss_bytes=2,
                latest_rss_bytes=2,
                peak_growth_percent=150.0,
                latest_growth_percent=10.0,
                peak_memory_percent=1.0,
                latest_memory_percent=1.0,
                status="sleeping",
                persistence_cycles=2,
                sleeping_after_surge=True,
                alive=True,
            ),
            2: MemorySurgeRecord(
                pid=2,
                process_name="b.exe",
                process_path="",
                first_seen="x",
                last_seen="x",
                baseline_rss_bytes=1,
                peak_rss_bytes=2,
                latest_rss_bytes=2,
                peak_growth_percent=90.0,
                latest_growth_percent=0.0,
                peak_memory_percent=0.5,
                latest_memory_percent=0.4,
                status="running",
                persistence_cycles=1,
                sleeping_after_surge=False,
                alive=False,
            ),
        }

        summary = WindowsBehaviorMonitor._memory_surge_summary(records)

        self.assertEqual(summary["tracked_processes"], 2)
        self.assertEqual(summary["sleeping_after_surge"], 1)
        self.assertEqual(summary["alive_after_surge"], 1)
        self.assertEqual(summary["max_growth_percent"], 150.0)

    def test_port_check_summary_uses_max_single_exposure_score(self):
        ports = [
            NetworkPortInfo(protocol="TCP", local_address="0.0.0.0", local_port=8000, status="LISTEN"),
            NetworkPortInfo(protocol="TCP", local_address="0.0.0.0", local_port=8001, status="LISTEN"),
        ]
        events = []
        for port in ports:
            events.extend(self.rules.network_port_events(port))

        summary = WindowsBehaviorMonitor._port_check_summary(events, ports)

        self.assertEqual(summary["risk_score"], 10)
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["score_model"], "max_single_port_exposure")

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
