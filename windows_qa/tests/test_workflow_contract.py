"""Static safety gates for the real-host GitHub Actions execution recipe."""

from pathlib import Path
import unittest


WORKFLOW = (Path(__file__).resolve().parents[2] / ".github" / "workflows" /
            "windows-native-matrix.yml")


class WindowsWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_windows_only_real_host_label(self):
        self.assertIn("runs-on: windows-2025", self.source)
        self.assertNotIn("runs-on: ubuntu", self.source)
        self.assertNotIn("runs-on: macos", self.source)

    def test_exact_seven_minor_matrix_not_synthetically_completed(self):
        self.assertIn('python: ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"]',
                      self.source)
        self.assertIn("fail-fast: false", self.source)
        self.assertIn("max-parallel: 2", self.source)

    def test_repository_permissions_minimized(self):
        self.assertIn("contents: read", self.source)
        self.assertIn("persist-credentials: false", self.source)
        self.assertNotIn("secrets.", self.source)

    def test_native_rust_and_real_python_tests_not_skipped(self):
        for snippet in ("cargo test --manifest-path windows_qa/Cargo.toml",
                        "cargo test --locked --all-targets",
                        "cargo build --release --locked",
                        "windows_runtime.py --expected-minor",
                        "qualify_curated.py --expected-minor",
                        "unittest discover -s tests -p"):
            self.assertIn(snippet, self.source)

    def test_primary_repo_missing_fails_closed(self):
        self.assertIn("PRIMARY_RUST_PROJECT_NOT_RESTORED", self.source)
        self.assertIn("PRIMARY_TESTS_NOT_RESTORED", self.source)

    def test_evidence_uploaded_on_failure_without_false_gpu_status(self):
        self.assertIn("if: always()", self.source)
        self.assertIn("actions/upload-artifact@v4", self.source)
        self.assertNotIn("CUDA_PASS", self.source)


if __name__ == "__main__":
    unittest.main()
