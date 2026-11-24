import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import keylogger_detector as detector


class ScriptDetectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.ctx = detector.ScanContext(check_signatures=False)

    def write(self, source, filename="sample.py", encoding="utf-8"):
        path = self.root / filename
        path.write_text(source, encoding=encoding)
        return path

    def test_script_patterns(self):
        cases = [
            ("__import__('pyn' + 'put')", 'pynput'),
            ("importlib.import_module(''.join(('pyn', 'put.keyboard')))", 'pynput.keyboard'),
            ("getattr(obj, 'GetAsync' 'KeyState')", 'GetAsyncKeyState'),
            ("__import__('pyn' + 'put')\nraise RuntimeError()", 'pynput'),
            ("from pynput import keyboard", 'pynput'),
            ("label = 'pyn' + 'put'", None),
            ("__import__('pyn' + unknown)", None),
            ("__import__('path' + 'lib')", None),
            ("similar_getattr(obj, 'GetAsync' + 'KeyState')", None),
            ("__import__('pyn' + 'put')\ninvalid +", None),
            ("getattr(obj, ''.join(chr(i ^ 256) for i in [1, 2]))", None),
        ]
        for index, (source, expected) in enumerate(cases):
            with self.subTest(source=source):
                path = self.write(source, f"sample{index}.py")
                score, reasons = detector.scan_script_file(str(path), self.ctx)
                if expected:
                    self.assertGreaterEqual(score, detector.FLAG_THRESHOLD)
                    self.assertIn(expected, " ".join(reasons))
                else:
                    self.assertEqual((score, reasons), (0, []))

    def test_xor_variants(self):
        encoded = bytes(ord(char) ^ 73 for char in "GetAsyncKeyState")
        for index, data in enumerate((encoded, list(encoded), tuple(encoded))):
            with self.subTest(data_type=type(data).__name__):
                source = f"getattr(obj, ''.join(chr(73 ^ item) for item in {data!r}))"
                path = self.write(source, f"xor{index}.pyw", encoding="utf-16")
                score, reasons = detector.scan_script_file(str(path), self.ctx)
                self.assertEqual(score, 40)
                self.assertIn("GetAsyncKeyState", reasons[0])

    def test_xor_binding_and_unrelated_xor(self):
        encoded = [ord(char) ^ 73 for char in "GetAsyncKeyState"]
        decode = f"name = ''.join(chr(item ^ 73) for item in {encoded!r})"
        path = self.write(decode + "\napi = getattr(obj, name)")
        score, reasons = detector.scan_script_file(str(path), self.ctx)
        self.assertGreaterEqual(score, detector.FLAG_THRESHOLD)
        self.assertTrue(any("XOR" in reason and "GetAsyncKeyState" in reason for reason in reasons))
        other = self.write(decode + "\nname = 'unrelated'\ngetattr(obj, name)", "other.py")
        self.assertEqual(detector.scan_script_file(str(other), self.ctx), (0, []))

    def test_process_scan_reports_only_suspicious_fixture(self):
        suspicious = self.write("__import__('pyn' + 'put')", "sample path.py")
        benign = self.write("label = 'pyn' + 'put'", "benign.py")
        snapshot = [
            dict(pid=pid, name="python.exe", exe=sys.executable,
                 cmdline=f'python.exe "{file}"', has_network=False, ppid=0)
            for pid, file in ((41001, suspicious), (41002, benign))
        ]
        for is_windows in (False, True):
            with self.subTest(windows_command_line_parsing=is_windows):
                with patch.object(detector, "get_processes_snapshot", return_value=snapshot):
                    with patch.object(detector, "IS_WINDOWS", is_windows):
                        count, findings = detector.scan_processes(self.ctx)
                self.assertEqual(count, 2)
                self.assertEqual([finding.pid for finding in findings], [41001])
                self.assertIn("pynput", " ".join(findings[0].reasons))
                self.assertEqual(findings[0].file_name, suspicious.name)
                self.assertEqual(findings[0].file_path, str(suspicious))
                self.assertEqual(findings[0].exe_path, sys.executable)

    def test_explorer_selects_file_with_spaces(self):
        path = r"C:\Example Folder\sample script.py"
        with patch.object(detector.subprocess, "Popen") as popen:
            detector.select_file_in_explorer(path)
        popen.assert_called_once_with(f'explorer.exe /select,"{path}"')


    def test_behavior_trace_scan(self):
        base = 1_700_000_000
        now = base + 60
        polls = [
            dict(pid=41001, process_start=base, timestamp=now - 2 + index / 100,
                 api="GetAsyncKeyState")
            for index in range(100)
        ]
        hook = dict(pid=41002, process_start=base, timestamp=now - 1,
                    api="SetWindowsHookExW", hook_id=13, thread_id=0, success=True)
        events = polls + [hook, dict(hook, pid=41003, hook_id=14),
                          dict(hook, pid=41004, timestamp=now - 31),
                          dict(hook, pid=41005, success=False),
                          dict(hook, pid=41006, thread_id=1),
                          dict(hook, pid=41007, process_start=base - 1)]
        events += [dict(polls[0], pid=41008)] * 100
        self.ctx.behavior_trace = self.write(
            "malformed\n" + "\n".join(map(json.dumps, events)), "trace.jsonl"
        )
        filetime = detector.FILETIME_UNIX_EPOCH + base * 10_000_000
        snapshot = [
            dict(pid=pid, name="sample.exe", exe="", cmdline="", ppid=0,
                 start=filetime if pid == 41002 else base, has_network=pid == 41001)
            for pid in range(41001, 41009)
        ]
        with patch.object(detector, "get_processes_snapshot", return_value=snapshot):
            with patch.object(detector.time, "time", return_value=now):
                count, findings = detector.scan_processes(self.ctx)
        self.assertEqual(count, 8)
        self.assertEqual([finding.pid for finding in findings], [41001, 41002])
        self.assertIn("100 keyboard state polls", findings[0].reasons[0])
        self.assertTrue(any("network connection" in reason for reason in findings[0].reasons))
        self.assertIn("global Windows keyboard hook", findings[1].reasons[0])

    def test_live_process_scan(self):
        encoded = [ord(char) ^ 73 for char in "GetAsyncKeyState"]
        fixtures = {
            "xor sample.py": (
                f"    name = ''.join(chr(item ^ 73) for item in {encoded!r})\n"
                "    getattr(object(), name)\n"
            ),
            "benign sample.py": "    result = 1 ^ 3\n",
        }
        processes = {}
        for filename, body in fixtures.items():
            script = self.write("import time\nif False:\n" + body + "time.sleep(240)\n", filename)
            child = subprocess.Popen([sys.executable, str(script)])
            self.addCleanup(self.stop_process, child)
            processes[filename] = child

        # Windows has a native fallback. Other platforms need psutil.
        if not detector.IS_WINDOWS and not detector.HAS_PSUTIL:
            self.skipTest("Live scanning on this platform requires psutil.")

        modes = [("default", [])]
        if detector.IS_WINDOWS and detector.HAS_PSUTIL:
            modes.append(("Windows native", ["-S"]))
        for mode, flags in modes:
            with self.subTest(mode=mode):
                log = self.root / f"{mode}.jsonl"
                result = subprocess.run(
                    [sys.executable, *flags, str(detector.SCRIPT_PATH), "--scan",
                     "--no-signature-check", "--whitelist", str(self.root / "empty.json"),
                     "--log", str(log)],
                    capture_output=True, text=True, timeout=80,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for child in processes.values():
                    self.assertIsNone(child.poll(), "Fixture process exited before scan completed")
                self.assertTrue(log.exists(), result.stdout + result.stderr)
                alerts = {item["pid"]: item for item in
                          map(json.loads, log.read_text(encoding="utf-8").splitlines())}
                self.assertNotIn(processes["benign sample.py"].pid, alerts)
                match = alerts.get(processes["xor sample.py"].pid)
                self.assertIsNotNone(match, result.stdout + result.stderr)
                self.assertTrue(
                    any("XOR" in reason and "GetAsyncKeyState" in reason for reason in match["reasons"]),
                    match["reasons"],
                )

    @staticmethod
    def stop_process(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)

    def test_register_and_remove_windows_sign_in(self):
        registry = MagicMock()
        key = registry.CreateKey.return_value.__enter__.return_value
        self.write("", "pythonw.exe")
        exe = str(self.root / "python.exe")
        with (patch.dict(sys.modules, {"winreg": registry}), patch.object(detector, "IS_WINDOWS", True),
              patch.object(sys, "executable", exe)):
            with patch.object(detector, "default_data_dir", return_value=self.root / "App Data"):
                command = detector.sign_in_command()
                detector.configure_sign_in(True)
                self.assertIn(' --monitor --log "', command)
                self.assertIn("pythonw.exe", command)
                self.assertIn(str(detector.SCRIPT_PATH), command)
                registry.SetValueEx.assert_called_once_with(
                    key, detector.SIGN_IN_VALUE, 0, registry.REG_SZ, command
                )
                detector.configure_sign_in(False)
        registry.DeleteValue.assert_called_once_with(
            registry.OpenKey.return_value.__enter__.return_value, detector.SIGN_IN_VALUE
        )

    def test_alert_viewer_receives_the_same_two_findings(self):
        findings = [
            detector.ProcessFinding(
                pid=pid, name="python.exe", exe_path="python.exe", cmdline="", score=score,
                severity=severity, script_path=filename,
            )
            for pid, score, severity, filename in (
                (123, 70, "CRITICAL", "first sample.py"),
                (456, 50, "HIGH", "second sample.py"),
            )
        ]
        with patch.object(detector, "IS_WINDOWS", True), patch.object(detector, "launch_alert_window") as launch:
            detector.notify_new_findings(findings)
        mode, payload = launch.call_args.args
        self.assertEqual(mode, "--alert-popup")
        self.assertIn("first sample.py", payload["groups"][0][1])
        self.assertIn("second sample.py", payload["groups"][0][1])
        from io import StringIO
        with (patch.object(sys, "argv", ["keylogger_detector.py", "--alert-viewer"]),
              patch.object(sys, "stdin", StringIO(json.dumps(payload))),
              patch.object(detector, "default_data_dir", return_value=self.root),
              patch.object(detector, "launch_gui") as gui):
            detector.main()
        self.assertFalse(gui.call_args.kwargs["auto_monitor"])
        self.assertEqual(gui.call_args.kwargs["alert_findings"], findings)

    def test_rescan_after_file_changes(self):
        path = self.write("__import__('pyn' + 'put')")
        self.assertGreater(detector.scan_script_file(str(path), self.ctx)[0], 0)
        path.write_text("pass", encoding="utf-8")
        self.assertEqual(detector.scan_script_file(str(path), self.ctx), (0, []))


if __name__ == "__main__":
    unittest.main()
