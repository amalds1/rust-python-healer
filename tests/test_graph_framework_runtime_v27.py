"""F254: bounded TensorFlow/JAX metadata + static graph/device observations.

No test here claims to have compiled a graph or run a GPU.  All input source
is syntax only; installed metadata tests never import tensorflow/jax.
"""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "python" / "graph_framework_runtime_v27.py"
SPEC = importlib.util.spec_from_file_location("graph_framework_runtime_v27", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class GraphFrameworkV27Tests(unittest.TestCase):
    def inspect(self, source):
        report = module.inspect_source(source)
        self.assertFalse(report["executed"])
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["graph_compilation_verified"])
        self.assertFalse(report["device_verified"])
        self.assertFalse(report["auto_repair_allowed"])
        self.assertFalse(report["imported_target_packages"])
        return report

    def test_tf_graph_decorator(self):
        report = self.inspect("import tensorflow as tf\n@tf.function\ndef f(x): return x\n")
        self.assertEqual(report["status"], "STATIC_OBSERVATIONS")
        self.assertEqual(report["observations"][0]["rule"], "TF_GRAPH_FUNCTION")
        self.assertEqual(report["observations"][0]["basis"], "AST_DECORATOR")

    def test_tf_graph_jit_true(self):
        source = "import tensorflow as tf\n@tf.function(jit_compile=True)\ndef f(x):return x\n"
        report = self.inspect(source)
        self.assertEqual(report["total_observations"], 1)
        self.assertIs(report["observations"][0]["jit_compile"], True)

    def test_tf_graph_jit_false(self):
        report = self.inspect("from tensorflow import function as compile_it\ncompile_it(jit_compile=False)\n")
        self.assertEqual(report["observations"][0]["jit_compile"], False)

    def test_tf_graph_jit_dynamic_never_invented(self):
        report = self.inspect("import tensorflow as tf\ntf.function(jit_compile=flag)\n")
        self.assertEqual(report["observations"][0]["jit_compile"], "DYNAMIC_UNVERIFIED")

    def test_tf_graph_autograph_false(self):
        report = self.inspect("import tensorflow as tf\ntf.function(autograph=False)\n")
        self.assertEqual(report["observations"][0]["autograph"], False)

    def test_tf_device_context(self):
        report = self.inspect("import tensorflow as tf\nwith tf.device('/CPU:0'):\n    pass\n")
        self.assertEqual(report["observations"][0]["rule"], "TF_DEVICE_CONTEXT")

    def test_tf_devices_metadata_probe(self):
        report = self.inspect("import tensorflow as tf\ntf.config.list_physical_devices('GPU')\n")
        self.assertEqual(report["observations"][0]["rule"], "TF_DEVICE_ENUMERATION")

    def test_tf_legacy_graph_mode(self):
        report = self.inspect("import tensorflow as tf\ntf.compat.v1.disable_eager_execution()\n")
        self.assertEqual(report["observations"][0]["rule"], "TF_LEGACY_GRAPH_MODE_CONTROL")

    def test_tf_model_load_reference_does_not_load(self):
        with mock.patch("os.system", side_effect=AssertionError("executed")):
            report = self.inspect("import tensorflow as tf\ntf.saved_model.load('/sensitive')\n")
        self.assertEqual(report["observations"][0]["rule"], "TF_MODEL_LOAD_REFERENCE")
        self.assertFalse(report["checkpoint_loaded"])
        self.assertNotIn("/sensitive", repr(report))

    def test_jax_jit_function_decorator(self):
        report = self.inspect("import jax\n@jax.jit\ndef f(x):return x\n")
        self.assertEqual(report["observations"][0]["rule"], "JAX_JIT")
        self.assertEqual(report["observations"][0]["basis"], "AST_DECORATOR")

    def test_jax_jit_from_import_alias(self):
        report = self.inspect("from jax import jit as speed\n@speed\ndef f(x):return x\n")
        self.assertEqual(report["observations"][0]["api"], "jax.jit")

    def test_jax_static_argnums(self):
        report = self.inspect("import jax as j\nj.jit(f, static_argnums=(0, 2))\n")
        self.assertEqual(report["observations"][0]["static_argnums"], [0, 2])

    def test_jax_static_argnames(self):
        report = self.inspect("import jax as j\nj.jit(f, static_argnames=('axis',))\n")
        self.assertEqual(report["observations"][0]["static_argnames"], ["axis"])

    def test_jax_static_dynamic_unknown(self):
        report = self.inspect("import jax\njax.jit(f, static_argnums=compute_args())\n")
        self.assertEqual(report["observations"][0]["static_argnums"], "DYNAMIC_UNVERIFIED")

    def test_jax_device_put(self):
        report = self.inspect("import jax\njax.device_put(x)\n")
        self.assertEqual(report["observations"][0]["rule"], "JAX_DEVICE_TRANSFER")

    def test_jax_device_enumeration(self):
        report = self.inspect("import jax\njax.devices()\njax.local_devices()\n")
        self.assertEqual(report["total_observations"], 2)
        self.assertTrue(all(x["rule"] == "JAX_DEVICE_ENUMERATION" for x in report["observations"]))

    def test_jax_default_device(self):
        report = self.inspect("import jax\nwith jax.default_device(device): pass\n")
        self.assertEqual(report["observations"][0]["rule"], "JAX_DEFAULT_DEVICE_CONTEXT")

    def test_dotted_text_and_comments_not_code(self):
        report = self.inspect("# tf.function(jit_compile=True)\nname = 'jax.device_put(x)'\n")
        self.assertEqual(report["observations"], [])

    def test_unknown_names_never_assumed_framework(self):
        report = self.inspect("tf.function()\njax.jit(f)\n")
        self.assertEqual(report["observations"], [])

    def test_shadowed_alias_rejected_conservatively(self):
        report = self.inspect("import tensorflow as tf\ntf = Fake()\ntf.function()\n")
        self.assertEqual(report["observations"], [])

    def test_function_argument_shadowed_alias_rejected(self):
        report = self.inspect("import jax\ndef f(jax):\n    jax.jit(f)\n")
        self.assertEqual(report["observations"], [])

    def test_wildcard_import_never_attributed(self):
        report = self.inspect("from jax import *\njit(f)\n")
        self.assertEqual(report["observations"], [])

    def test_multiversion_parser_reports_version(self):
        report = self.inspect("import jax\njax.devices()\n")
        self.assertEqual(report["python_parser_version"],
                         f"{sys.version_info.major}.{sys.version_info.minor}")

    def test_syntax_error_is_not_pass(self):
        report = self.inspect("import tensorflow as tf\ndef invalid(: pass\n")
        self.assertEqual(report["status"], "NOT_PARSED")
        self.assertEqual(report["observations"], [])

    def test_bounded_source_is_not_pass(self):
        report = self.inspect("z" * (module.SOURCE_LIMIT + 1))
        self.assertEqual(report["status"], "NOT_PARSED")
        self.assertEqual(report["reason"], "source_limit_exceeded")

    def test_bounded_nodes_is_not_pass(self):
        report = self.inspect("a=1\n" * 3_001)
        self.assertEqual(report["status"], "NOT_PARSED")
        self.assertEqual(report["reason"], "ast_node_limit_exceeded")

    def test_non_source_type_refused(self):
        for value in (None, bytearray(b"import jax"), [], 123):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(TypeError):
                module.inspect_source(value)

    def test_invalid_utf8_is_not_pass(self):
        report = self.inspect(b"\xffimport tensorflow")
        self.assertEqual(report["status"], "NOT_PARSED")

    def test_same_source_same_hash(self):
        content = "import jax\njax.devices()\n"
        self.assertEqual(self.inspect(content), self.inspect(content.encode("utf-8")))

    def test_metadata_may_be_missing_without_runtime_import(self):
        with mock.patch.object(module.importlib.metadata, "version", side_effect=module.importlib.metadata.PackageNotFoundError):
            report = module.installed_metadata()
        self.assertEqual(report["status"], "METADATA_ONLY")
        self.assertFalse(report["executed_framework_code"])
        self.assertFalse(report["accelerator_verified"])
        self.assertTrue(all(item["status"] == "NOT_INSTALLED" for item in report["installed"].values()))

    def test_metadata_installed_still_not_runtime_proof(self):
        with mock.patch.object(module.importlib.metadata, "version", return_value="0.0-local"):
            report = module.installed_metadata()
        self.assertTrue(all(item["status"] == "INSTALLED_METADATA_ONLY" for item in report["installed"].values()))
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["graph_compilation_verified"])

    def test_metadata_errors_explicit_not_run(self):
        with mock.patch.object(module.importlib.metadata, "version", side_effect=OSError("/secret/package")):
            report = module.installed_metadata()
        self.assertTrue(all(item["status"] == "NOT_RUN" for item in report["installed"].values()))
        self.assertNotIn("/secret", repr(report))

    def test_metadata_unbounded_version_not_returned(self):
        with mock.patch.object(module.importlib.metadata, "version", return_value="\nSECRET" * 10_000):
            report = module.installed_metadata()
        self.assertTrue(all(item["status"] == "NOT_RUN" for item in report["installed"].values()))
        self.assertNotIn("SECRET", repr(report))


if __name__ == "__main__":
    unittest.main()
