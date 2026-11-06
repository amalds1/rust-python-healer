"""Release-to-release metrics: self-reports never become behavioral proof."""

import copy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("release_quality", ROOT / "python" / "release_quality.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def observation(version="0.17.0", *, fpositives=0, regressions=0,
                successes=80, completed=1000, elapsed=1000,
                durations=None, coverage=None, checked=1000):
    row = {
        "version": version,
        "run_id": "RUN-" + version,
        "source_sha256": hashlib.sha256((version + "source").encode()).hexdigest(),
        "binary_sha256": hashlib.sha256((version + "binary").encode()).hexdigest(),
        "python_minors": coverage if coverage is not None else
                         ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"],
        "oracle_checked": checked,
        "reported_false_positives": fpositives,
        "regression_failures": regressions,
        "repair_candidates": 100,
        "reported_repair_successes": successes,
        "jobs_completed": completed,
        "elapsed_ms": elapsed,
        "durations_ms": durations if durations is not None else [10.0] * 10,
    }
    row["record_sha256"] = module.digest(row)
    return row


def resign(row):
    row["record_sha256"] = module.digest({key: value for key, value in row.items()
                                          if key != "record_sha256"})
    return row


class ReleaseQualityTests(unittest.TestCase):
    def test_one_release_is_only_a_reported_baseline(self):
        report = module.analyze({"schema_version": 1, "releases": [observation()]})
        self.assertEqual(report["status"], "ANALYZED_UNVERIFIED_RELEASE_MEASUREMENTS")
        self.assertIsNone(report["releases"][0]["baseline"])
        self.assertEqual(report["releases"][0]["benchmark"]["observations"], 10)
        self.assertFalse(report["external_measurements_verified"])
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["source_executed"])
        self.assertEqual(report["behavioral_correctness"], "NOT_VERIFIED")

    def test_more_false_positives_and_regressions_raise_explicit_warnings(self):
        report = module.analyze({"schema_version": 1, "releases": [
            observation("0.17.0"), observation("0.18.0", fpositives=15, regressions=3)]})
        latest = report["releases"][1]
        self.assertEqual(latest["reported_false_positive_percent"], 1.5)
        self.assertEqual(latest["threshold_observations"]["false_positive"],
                         "REPORTED_THRESHOLD_EXCEEDED")
        self.assertEqual(latest["baseline"]["new_regression_failures"], 3)
        self.assertEqual(latest["threshold_observations"]["new_regressions"],
                         "REPORTED_THRESHOLD_EXCEEDED")
        self.assertFalse(latest["release_qualified"])

    def test_deterministic_ten_repeat_nearest_rank_p95_and_median(self):
        durations = [10, 4, 9, 8, 7, 6, 5, 2, 3, 1]
        result = module.analyze({"schema_version": 1, "releases": [
            observation(durations=durations)]})
        metrics = result["releases"][0]["benchmark"]
        self.assertEqual(metrics["median_ms"], 5.5)
        self.assertEqual(metrics["p95_ms"], 10)
        self.assertEqual(metrics["max_ms"], 10)

    def test_less_than_ten_or_too_many_repetitions_are_rejected(self):
        for count in (9, module.MAX_REPEATS + 1):
            with self.subTest(count=count):
                with self.assertRaisesRegex(ValueError,
                                            "insufficient_or_excessive_benchmark_repetitions"):
                    module.analyze({"schema_version": 1, "releases": [
                        observation(durations=[2] * count)]})

    def test_latency_regression_is_compared_using_real_repeated_distribution(self):
        data = {"schema_version": 1, "releases": [
            observation("0.17.0", durations=[10] * 10),
            observation("0.18.0", durations=[12] * 10)]}
        report = module.analyze(data)
        self.assertAlmostEqual(report["releases"][1]["baseline"]["p95_latency_change_percent"], 20)
        self.assertEqual(report["releases"][1]["threshold_observations"]["p95_latency_regression"],
                         "REPORTED_THRESHOLD_EXCEEDED")

    def test_throughput_and_repair_quality_drop_are_reported_separately(self):
        first = observation("0.17.0", successes=90, completed=1000)
        second = observation("0.18.0", successes=70, completed=900)
        report = module.analyze({"schema_version": 1, "releases": [first, second]})
        latest = report["releases"][1]
        self.assertAlmostEqual(latest["baseline"]["throughput_change_percent"], -10)
        self.assertAlmostEqual(latest["baseline"]["repair_quality_change_pp"], -20)
        self.assertEqual(latest["threshold_observations"]["throughput_regression"],
                         "REPORTED_THRESHOLD_EXCEEDED")
        self.assertEqual(latest["threshold_observations"]["repair_quality_regression"],
                         "REPORTED_THRESHOLD_EXCEEDED")

    def test_different_python_coverage_is_not_used_as_same_baseline(self):
        later = observation("0.18.0", coverage=[
            "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15", "3.16"])
        result = module.analyze({"schema_version": 1, "releases": [
            observation("0.17.0"), later]})
        self.assertEqual(result["releases"][1]["baseline"]["comparison_status"],
                         "NOT_COMPARABLE_DIFFERENT_PYTHON_COVERAGE")
        self.assertEqual(result["releases"][1]["threshold_observations"]["throughput_regression"],
                         "NOT_RUN_INCOMPARABLE_COVERAGE")

    def test_too_few_oracle_observations_never_produce_confident_low_fp(self):
        result = module.analyze({"schema_version": 1, "releases": [
            observation(checked=3)]})
        self.assertEqual(result["releases"][0]["threshold_observations"]["false_positive"],
                         "NOT_RUN_TOO_FEW_ORACLE_OBSERVATIONS")

    def test_false_positive_and_reported_successes_cannot_exceed_counts(self):
        for kwargs in ({"fpositives": 1001}, {"successes": 101}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ValueError, "reported_counts_exceed_totals"):
                    module.analyze({"schema_version": 1, "releases": [observation(**kwargs)]})

    def test_negative_nonfinite_and_boolean_numeric_inputs_are_rejected(self):
        for name, invalid in (("elapsed_ms", 0), ("elapsed_ms", float("inf")),
                              ("jobs_completed", True), ("durations_ms", [float("nan")] * 10),
                              ("durations_ms", [-1] * 10)):
            with self.subTest(field=name, invalid=invalid):
                bad = observation()
                bad[name] = invalid
                # Nonfinite JSON is invalid even before signing.
                try:
                    resign(bad)
                except ValueError:
                    continue
                with self.assertRaises(ValueError):
                    module.analyze({"schema_version": 1, "releases": [bad]})

    def test_duplicate_and_unsorted_releases_do_not_count_as_retest(self):
        for releases in ([observation(), observation()],
                         [observation("0.18.0"), observation("0.17.0")]):
            with self.subTest(releases=releases):
                with self.assertRaisesRegex(ValueError,
                                            "releases_must_be_unique_and_strictly_ascending"):
                    module.analyze({"schema_version": 1, "releases": releases})

    def test_tampering_without_new_record_hash_is_detected(self):
        good = observation()
        altered = copy.deepcopy(good)
        altered["reported_false_positives"] = 2
        with self.assertRaisesRegex(ValueError, "release_record_sha256_mismatch"):
            module.analyze({"schema_version": 1, "releases": [altered]})

    def test_invalid_or_unsorted_python_versions_and_hashes_rejected(self):
        for field, value in (("python_minors", ["3.11", "3.9"]),
                             ("python_minors", ["3.9", "3.9"]),
                             ("python_minors", ["python3.12"]),
                             ("source_sha256", "../not-a-hash")):
            with self.subTest(field=field):
                row = observation()
                row[field] = value
                resign(row)
                with self.assertRaises(ValueError):
                    module.analyze({"schema_version": 1, "releases": [row]})

    def test_explicit_run_identifiers_must_be_unique(self):
        first = observation("0.17.0")
        second = observation("0.18.0")
        second["run_id"] = first["run_id"]
        resign(second)
        with self.assertRaisesRegex(ValueError, "duplicate_release_run_id_without_retest"):
            module.analyze({"schema_version": 1, "releases": [first, second]})

    def test_symlink_hardlink_and_oversize_source_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            data = path / "reports.json"
            data.write_text(json.dumps({"schema_version": 1, "releases": [observation()]}))
            link = path / "linked.json"
            link.symlink_to(data)
            with self.assertRaisesRegex(ValueError, "release_evidence_symlink_refused"):
                module.inspect_file(link)
            other = path / "hardlinked.json"
            import os
            os.link(data, other)
            with self.assertRaisesRegex(ValueError, "release_evidence_not_unique_bounded_file"):
                module.inspect_file(data)
            other.unlink()
            data.write_bytes(b"a" * (module.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "release_evidence_not_unique_bounded_file"):
                module.inspect_file(data)

    def test_ambiguous_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "ambiguous.json"
            file.write_text('{"schema_version":1,"schema_version":2,"releases":[]}')
            with self.assertRaisesRegex(ValueError, "duplicate_release_json_key"):
                module.inspect_file(file)

    def test_cli_never_executes_target_and_omits_sensitive_source(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            file = path / "untrusted-report.json"
            marker = path / "must_not_execute.txt"
            payload = {"schema_version": 1, "releases": [observation()]}
            file.write_text(json.dumps(payload))
            run = subprocess.run([sys.executable, "-I", "-S", "-B", "-c",
                                  (ROOT / "python" / "release_quality.py").read_text(),
                                  str(file)], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["releases_examined"], 1)
            self.assertNotIn(str(path), run.stdout)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
