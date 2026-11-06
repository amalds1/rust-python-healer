"""Real Python 3.9–3.15 wheel zipimport regression for v27 binary updater.

The first candidate failed on real Python 3.9 because zipimport left the
package context empty; do not allow a green source-tree import to mask this.
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "rph_v27_builder", ROOT / "packaging" / "build_release.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
HELPERS = ("binary_self_update_v27", "binary_recovery_v23",
           "graph_framework_runtime_v27", "macos_universal_wheels_v27",
           "pytorch_runtime_v27", "untrusted_output_guard_v27")


class WheelZipImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rph-v27-wheel-import-")
        cls.path = Path(cls.temp.name)
        version = builder.project_version()
        cls.name, payload, cls.sources = builder.build_wheel(version, builder.collect_helpers())
        cls.wheel = cls.path / cls.name
        cls.wheel.write_bytes(payload)
        cls.hash = hashlib.sha256(payload).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_wheel_deterministic_when_rebuilt_from_same_source(self):
        again, payload, sources = builder.build_wheel(builder.project_version(),
                                                      builder.collect_helpers())
        self.assertEqual(again, self.name)
        self.assertEqual(sources, self.sources)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), self.hash)

    def test_real_interpreter_imports_every_new_helper_from_zip(self):
        source = ("import json,sys; sys.path.insert(0, " + json.dumps(str(self.wheel)) +
                  "); from rust_python_healer_helpers import " + ", ".join(HELPERS) +
                  "; print(json.dumps({'status':'ZIPIMPORT_6_PASS',"
                  "'modules':" + str(len(HELPERS)) + "}))")
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", source],
                                capture_output=True, text=True, check=False, timeout=15)
        self.assertEqual(result.returncode, 0, "zipimport_failed_on_real_interpreter")
        self.assertEqual(json.loads(result.stdout),
                         {"status": "ZIPIMPORT_6_PASS", "modules": len(HELPERS)})

    def test_wheel_contains_real_v27_sources_and_relative_import_dependencies(self):
        with zipfile.ZipFile(self.wheel) as archive:
            for module_name in HELPERS:
                payload = archive.read("rust_python_healer_helpers/" + module_name + ".py")
                self.assertEqual(payload, builder.collect_helpers()[module_name])

    def test_wheel_requires_supported_python_range(self):
        with zipfile.ZipFile(self.wheel) as archive:
            metadata = archive.read("rust_python_healer_helpers-" +
                                    builder.project_version() + ".dist-info/METADATA")
        self.assertIn(b"Requires-Python: >=3.9, <3.16", metadata)


if __name__ == "__main__":
    unittest.main()
