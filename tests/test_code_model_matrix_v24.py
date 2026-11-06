"""Evidence matrix must fail closed on false interpreter/model claims."""

from importlib.util import module_from_spec, spec_from_file_location
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock
import json
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("real_code_model_matrix_v24",
                               ROOT / "tools" / "run_code_model_matrix_v24.py")
matrix = module_from_spec(spec)
spec.loader.exec_module(matrix)


class ActualCodeModelMatrixTests(unittest.TestCase):
    def test_measured_actual_current_minor_and_real_cpython_compile_and_inference(self):
        version = "{}.{}".format(*sys.version_info[:2])
        record = matrix.measure_version(version, Path(sys.executable).resolve())
        self.assertEqual(record["version"], version)
        self.assertEqual(record["actual_train_examples_per_model"], 120)
        self.assertEqual(record["actual_disjoint_holdout_cases_per_model"], 32)
        self.assertEqual(set(record["model_reports"]),
                         {"multinomial_nb", "multiclass_perceptron"})
        self.assertFalse(record["external_audit_claimed"])
        self.assertFalse(record["arbitrary_project_correctness_claimed"])

    def test_wrong_minors_and_missing_python_refuse(self):
        current = "{}.{}".format(*sys.version_info[:2])
        wrong = "3.15" if current != "3.15" else "3.9"
        with self.assertRaisesRegex(ValueError, "unverified_python_minor"):
            matrix.measure_version(wrong, Path(sys.executable).resolve())
        with self.assertRaisesRegex(ValueError, "missing_explicit_python_interpreter"):
            matrix.measure_version(current, Path("/missing-test-python"))

    def test_unsigned_or_incomplete_model_evidence_not_written(self):
        with tempfile.TemporaryDirectory(prefix="rph-model-matrix-reject-") as folder:
            output = Path(folder) / "must-not-exist.json"
            with redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    matrix.main(["--interpreter", "3.9=/missing-python",
                                 "--output", str(output)])
            self.assertFalse(output.exists())

    def test_incomplete_selftest_cannot_pass_quality_and_false_external_claim(self):
        version = "{}.{}".format(*sys.version_info[:2])
        real = matrix.subprocess.run([sys.executable, "-I", "-S", "-B",
                                      str(matrix.ROUTER), "--mode", "selftest"],
                                     capture_output=True, text=True, timeout=30)
        value = json.loads(real.stdout)
        value["external_independent_auditor_attested"] = True
        fake = mock.Mock(returncode=0, stdout=json.dumps(value))
        original = matrix.subprocess.run

        def two_stage(args, **kwargs):
            return original(args, **kwargs) if "-c" in args else fake

        with mock.patch.object(matrix.subprocess, "run", side_effect=two_stage):
            with self.assertRaisesRegex(ValueError, "unqualified_or_misrepresented"):
                matrix.measure_version(version, Path(sys.executable).resolve())


if __name__ == "__main__":
    unittest.main()
