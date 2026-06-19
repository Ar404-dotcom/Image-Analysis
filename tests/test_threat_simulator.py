import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from live_monitor.threat_simulator import (
    FILE_ACTION_RENAMED_NEW_NAME,
    FILE_ACTION_RENAMED_OLD_NAME,
    WindowsTargetFileRenameWatcher,
    DEMO_DATA_NAME,
    LOCKED_DATA_NAME,
    README_NAME,
    arm_target_file_monitor,
    contain_target_file_threat,
    contain_threat,
    launch_target_file_simulator,
    load_target_file_monitor_state,
    monitor_demo_report,
    prepare_demo_workspace,
    target_file_report,
)


class ThreatSimulatorTests(unittest.TestCase):
    def test_prepare_demo_workspace_creates_demo_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = prepare_demo_workspace(tmp)

            self.assertTrue(Path(state["demo_data_path"]).exists())
            self.assertFalse(state["locked"])
            self.assertFalse(state["readme_created"])

    def test_locked_demo_state_reports_high_risk_score_90(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locked = root / LOCKED_DATA_NAME
            locked.mkdir()
            (locked / README_NAME).write_text("controlled demo", encoding="utf-8")

            report = monitor_demo_report(root)

            self.assertEqual(report["threat_status"], "Threat Active")
            self.assertEqual(report["summary"]["risk_score"], 90)
            self.assertEqual(report["events"][0]["severity"], "HIGH")
            self.assertEqual(report["events"][0]["category"], "controlled_file_lock_simulation")

    def test_containment_restores_folder_and_resets_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locked = root / LOCKED_DATA_NAME
            locked.mkdir()
            (locked / README_NAME).write_text("controlled demo", encoding="utf-8")

            report = contain_threat(root)

            self.assertTrue((root / DEMO_DATA_NAME).exists())
            self.assertFalse((root / LOCKED_DATA_NAME).exists())
            self.assertFalse((root / DEMO_DATA_NAME / README_NAME).exists())
            self.assertEqual(report["threat_status"], "Threat Contained")
            self.assertEqual(report["summary"]["risk_score"], 0)
            self.assertEqual(report["events"], [])

    def test_target_file_simulator_logs_previous_and_current_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Resume updated June.pdf"
            locked = Path(tmp) / "Resume updated June_LOCKED.pdf"
            target.write_bytes(b"%PDF-1.4 controlled test")

            try:
                report = launch_target_file_simulator(target, hold_seconds=10)

                self.assertEqual(report["threat_status"], "Threat Active")
                self.assertEqual(report["summary"]["risk_score"], 90)
                self.assertFalse(target.exists())
                self.assertTrue(locked.exists())
                readme = Path("output") / "readme.txt"
                contents = readme.read_text(encoding="utf-8")
                self.assertIn("previous_name: Resume updated June.pdf", contents)
                self.assertIn("current_name: Resume updated June_LOCKED.pdf", contents)
                self.assertGreaterEqual(report["memory_surge_summary"]["tracked_processes"], 1)
                self.assertTrue(report["memory_surges"])
            finally:
                contained = contain_target_file_threat(target)

            self.assertTrue(target.exists())
            self.assertFalse(locked.exists())
            self.assertEqual(contained["summary"]["risk_score"], 0)

    def test_directory_change_watcher_matches_expected_rename_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Resume updated June.pdf"
            watcher = WindowsTargetFileRenameWatcher(target)

            self.assertIsNone(watcher.consume_action(FILE_ACTION_RENAMED_OLD_NAME, "Resume updated June.pdf"))
            result = watcher.consume_action(FILE_ACTION_RENAMED_NEW_NAME, "Resume updated June_LOCKED.pdf")

            self.assertIsNotNone(result)
            self.assertTrue(result["detected"])
            self.assertEqual(result["method"], "ReadDirectoryChangesW")

    def test_target_report_is_monitoring_before_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Resume updated June.pdf"
            target.write_bytes(b"%PDF-1.4 controlled test")

            arm_target_file_monitor(target)
            state = load_target_file_monitor_state(target)
            report = target_file_report(target)

            self.assertTrue(state["armed"])
            self.assertEqual(report["threat_status"], "Monitoring")
            self.assertEqual(report["events"], [])

    def test_target_file_report_uses_recorded_watcher_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Resume updated June.pdf"
            locked = Path(tmp) / "Resume updated June_LOCKED.pdf"
            target.write_bytes(b"%PDF-1.4 controlled test")
            arm_target_file_monitor(target)
            target.rename(locked)

            watcher = WindowsTargetFileRenameWatcher(target)
            watcher.consume_action(FILE_ACTION_RENAMED_OLD_NAME, "Resume updated June.pdf")
            detection = watcher.consume_action(FILE_ACTION_RENAMED_NEW_NAME, "Resume updated June_LOCKED.pdf")
            from live_monitor.threat_simulator import record_target_file_detection

            record_target_file_detection(target, detection)
            report = target_file_report(target)

            self.assertEqual(report["threat_status"], "Threat Active")
            self.assertEqual(report["summary"]["risk_score"], 90)
            self.assertEqual(report["events"][0]["evidence"]["detection_method"], "ReadDirectoryChangesW")
            contain_target_file_threat(target)


if __name__ == "__main__":
    unittest.main()
