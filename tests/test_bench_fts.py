"""Independent benchmark validation without executing unknown Python code."""

import json
import contextlib
from importlib.util import module_from_spec, spec_from_file_location
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "tools" / "bench_fts.py"


class BenchmarkTests(unittest.TestCase):
    def test_sorted_per_round_p95_and_global_gate_reject_hidden_tail(self):
        spec = spec_from_file_location("fts_rank_regression", BENCH)
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        out = io.StringIO()
        scrambled = [900.0, 1.0, 5.0, 3.0, 8.0, 7.0, 6.0, 2.0, 4.0, 0.0]
        with mock.patch.object(module, "bench_once", return_value=(0.01, scrambled)), \
                mock.patch.object(sys, "argv", ["bench_fts", "--records", "10",
                                                "--queries", "10", "--runs", "5"]), \
                contextlib.redirect_stdout(out):
            module.main()
        result = json.loads(out.getvalue())
        self.assertEqual(result["independent_runs"], 5)
        self.assertEqual([row["query_p95_ms"] for row in result["runs"]], [8.0] * 5)
        self.assertEqual(result["query_p95_ms"], 900.0)
        self.assertEqual(result["fts_p95_status"], "FAIL",
                         "the global p95 gate must not hide a heavy-tailed regression")

    def test_five_independent_sqlite_runs_have_all_evidence_fields(self):
        proc = subprocess.run(
            [sys.executable, str(BENCH), "--records", "100", "--queries", "10", "--runs", "5"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        report = json.loads(proc.stdout)
        self.assertEqual(report["independent_runs"], 5)
        self.assertEqual(report["total_query_measurements"], 50)
        self.assertEqual([row["run"] for row in report["runs"]], [1, 2, 3, 4, 5])
        self.assertGreaterEqual(report["query_max_ms"], report["query_p95_ms"])
        self.assertGreaterEqual(report["query_p95_ms"], 0)
        self.assertEqual(report["scope"], "SQLite FTS5 only; Rust repair pipeline not measured")
        self.assertEqual(report["fts_p95_threshold_ms"], 50.0)
        self.assertGreater(report["peak_rss_kib"], 0)
        if sys.platform == "win32":
            self.assertEqual(report["peak_rss_basis"], "windows_peak_working_set_process_high_water")
        elif sys.platform == "linux":
            self.assertEqual(report["peak_rss_basis"], "linux_ru_maxrss_process_high_water")
        self.assertIn(report["fts_p95_status"], ("PASS", "FAIL"))

    def test_less_than_five_runs_is_rejected(self):
        proc = subprocess.run(
            [sys.executable, str(BENCH), "--records", "10", "--queries", "5", "--runs", "4"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("runs 5..20", proc.stderr)


if __name__ == "__main__":
    unittest.main()
