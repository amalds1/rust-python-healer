"""Runtime oracles are separate from non-executing target-source inspection."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'python/graph_framework_runtime_v27.py'
spec = importlib.util.spec_from_file_location('f254_runtime_qualification', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def jax_observation():
    return {'status': 'FIXED_RUNTIME_PASS', 'framework': 'jax', 'framework_version': '0.12.0.1',
            'jaxlib_version': '0.12.0.1', 'requested_device': 'cpu', 'actual_device': 'cpu:0',
            'actual_platform': 'cpu', 'mode': 'jit',
            'executed_rules': ['JAX_JIT', 'JAX_DEVICE_TRANSFER', 'JAX_DEVICE_ENUMERATION', 'JAX_DEFAULT_DEVICE_CONTEXT'],
            'negative_oracles': ['SHAPE_MISMATCH_REJECTED', 'JIT_DYNAMIC_BOOL_REJECTED', 'INVALID_DEVICE_REJECTED'],
            'user_source_executed': False, 'optimization_level': 0}


class FixedRuntimeQualificationTests(unittest.TestCase):
    def test_fixed_sources_have_actual_static_rule_observations_without_execution(self):
        for source, required in ((module.TF_FIXED_SOURCE, {'TF_GRAPH_FUNCTION', 'TF_DEVICE_CONTEXT', 'TF_LEGACY_GRAPH_MODE_CONTROL', 'TF_LEGACY_EAGER_MODE_CONTROL', 'TF_EAGER_MODE_CONTROL'}),
                                 (module.JAX_FIXED_SOURCE, {'JAX_JIT', 'JAX_DEVICE_TRANSFER', 'JAX_DEVICE_ENUMERATION', 'JAX_DEFAULT_DEVICE_CONTEXT'})):
            result = module.inspect_source(source)
            self.assertEqual(result['status'], 'STATIC_OBSERVATIONS')
            self.assertTrue(required <= {x['rule'] for x in result['observations']})
            self.assertFalse(result['executed'])
            self.assertFalse(result['runtime_verified'])

    def test_invalid_framework_device_timeout_refused_before_child(self):
        with mock.patch.object(module.subprocess, 'run') as child:
            for args in [('torch', 'cpu', 90), ('tensorflow;cmd', 'cpu', 90), ('jax', 'cuda;cmd', 90), ('jax', 'cpu', True), ('jax', 'cpu', 0), ('jax', 'cpu', 121), ('jax', 'cpu', 1.2)]:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    module.qualify_fixed_runtime(*args)
            child.assert_not_called()

    def test_positive_jax_receipt_is_bound_to_literal_not_user_source(self):
        receipt = jax_observation()
        with mock.patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(receipt).encode(), b'')) as child:
            result = module.qualify_fixed_runtime('jax')
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(child.call_args.args[0][-3], module.JAX_FIXED_SOURCE)
        self.assertEqual(child.call_args.args[0][1:4], ['-I', '-B', '-c'])
        self.assertNotIn('shell', child.call_args.kwargs)
        self.assertFalse(result['user_source_executed'])
        self.assertFalse(result['arbitrary_graph_compatibility_verified'])
        self.assertEqual(result['fixture_source_sha256'], module.inspect_source(module.JAX_FIXED_SOURCE)['source_sha256'])

    def test_malformed_partial_or_cpu_fallback_receipts_never_pass(self):
        original = jax_observation()
        mutations = [None, [], {'extra': 'secret'}, dict(original, actual_platform='gpu'),
                     dict(original, actual_device='cuda:0'), dict(original, requested_device='gpu'),
                     dict(original, optimization_level=True), dict(original, optimization_level=1),
                     dict(original, executed_rules=['JAX_JIT']), dict(original, negative_oracles=[]),
                     dict(original, executed_rules=[{}]), dict(original, negative_oracles=[[]]),
                     dict(original, framework_version='bad\nsecret'), dict(original, user_source_executed=True),
                     dict(original, actual_device='private\nsecret'), dict(original, extra='secret')]
        for receipt in mutations:
            with self.subTest(receipt=receipt), mock.patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(receipt).encode(), b'')):
                result = module.qualify_fixed_runtime('jax')
                self.assertEqual(result['status'], 'FAIL')
                self.assertNotIn('secret', repr(result))

    def test_child_error_timeout_or_invalid_json_is_not_a_pass(self):
        for process in [subprocess.CompletedProcess([], 1, b'', b'secret error'), subprocess.CompletedProcess([], 0, b'invalid', b''), subprocess.CompletedProcess([], 0, b'x'*16385, b'')]:
            with self.subTest(process=process.returncode), mock.patch.object(module.subprocess, 'run', return_value=process):
                result = module.qualify_fixed_runtime('jax')
                self.assertEqual(result['status'], 'FAIL')
                self.assertNotIn('secret', repr(result))
        with mock.patch.object(module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('private command', 1)):
            result = module.qualify_fixed_runtime('jax')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['cases'][0]['status'], 'NOT_RUN')
        self.assertNotIn('private', repr(result))

    def test_child_environment_has_no_parent_secrets_or_injection_paths(self):
        with mock.patch.dict(module.os.environ, {'PATH':'untrusted', 'SystemRoot':'C:/Windows', 'SECRET':'private', 'PYTHONPATH':'evil', 'LD_LIBRARY_PATH':'evil'}, clear=True), mock.patch.object(module.sys, 'platform', 'win32'):
            environment = module._fixed_runtime_environment('tensorflow')
        self.assertEqual(environment['SystemRoot'], 'C:/Windows')
        self.assertEqual(environment['PATH'], module.os.defpath)
        for key in ['SECRET','PYTHONPATH','LD_LIBRARY_PATH','PYTHONHOME']:
            self.assertNotIn(key, environment)


if __name__ == '__main__':
    unittest.main()
