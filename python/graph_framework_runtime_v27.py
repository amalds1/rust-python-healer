"""Bounded TensorFlow/JAX static inventory and separate fixed-fixture probes.

inspect_source never imports or executes target Python source or frameworks;
installed_metadata never imports frameworks. Metadata is not runtime proof.
qualify_fixed_runtime explicitly starts only this module's literal trusted
fixtures in isolated interpreter processes; caller source and checkpoints
cannot be supplied. Its PASS is restricted to the tested interpreter,
framework version and actual CPU/GPU, and does not qualify arbitrary graphs.
Version syntax unsupported by the host parser stays NOT_PARSED, never PASS.
"""

import ast
import hashlib
import importlib.metadata
import re
import sys
import json
import os
from pathlib import Path
import subprocess

SOURCE_LIMIT = 262_144
NODE_LIMIT = 12_000
OBSERVATION_LIMIT = 256
FRAMEWORK_DISTS = {"tensorflow": "tensorflow", "jax": "jax", "jaxlib": "jaxlib"}
ALLOWED_ROOTS = ("tensorflow", "jax")
ALLOWED_CALLS = {
    "tensorflow.function": "TF_GRAPH_FUNCTION",
    "tensorflow.device": "TF_DEVICE_CONTEXT",
    "tensorflow.config.list_physical_devices": "TF_DEVICE_ENUMERATION",
    "tensorflow.config.list_logical_devices": "TF_DEVICE_ENUMERATION",
    "tensorflow.config.run_functions_eagerly": "TF_EAGER_MODE_CONTROL",
    "tensorflow.compat.v1.disable_eager_execution": "TF_LEGACY_GRAPH_MODE_CONTROL",
    "tensorflow.compat.v1.enable_eager_execution": "TF_LEGACY_EAGER_MODE_CONTROL",
    "tensorflow.saved_model.load": "TF_MODEL_LOAD_REFERENCE",
    "jax.jit": "JAX_JIT",
    "jax.device_put": "JAX_DEVICE_TRANSFER",
    "jax.devices": "JAX_DEVICE_ENUMERATION",
    "jax.local_devices": "JAX_DEVICE_ENUMERATION",
    "jax.default_device": "JAX_DEFAULT_DEVICE_CONTEXT",
}
LITERAL_NAME = re.compile(r"^[A-Za-z0-9_.+-]{1,100}$")


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return parent + "." + node.attr if parent else None
    return None


def _binding_aliases(tree):
    """Only top-level explicit bindings; conservatively suppress shadowed names."""
    aliases = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                root = alias.name.split(".", 1)[0]
                if root not in ALLOWED_ROOTS:
                    continue
                binding = alias.asname or root
                aliases[binding] = alias.name if alias.asname else root
        elif isinstance(statement, ast.ImportFrom) and statement.module and statement.level == 0:
            root = statement.module.split(".", 1)[0]
            if root not in ALLOWED_ROOTS:
                continue
            for alias in statement.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = statement.module + "." + alias.name
    shadows = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            shadows.add(node.id)
        elif isinstance(node, ast.arg):
            shadows.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadows.add(node.name)
    return {alias: path for alias, path in aliases.items() if alias not in shadows}


def _resolved_path(node, aliases):
    name = _name(node)
    if name is None:
        return None
    parts = name.split(".")
    base = aliases.get(parts[0])
    return ".".join([base] + parts[1:]) if base else None


def _bool_keyword(node, key):
    for keyword in node.keywords:
        if keyword.arg == key:
            if isinstance(keyword.value, ast.Constant) and type(keyword.value.value) is bool:
                return keyword.value.value
            return "DYNAMIC_UNVERIFIED"
    return "UNSPECIFIED"


def _static_tuple_keyword(node, key):
    for keyword in node.keywords:
        if keyword.arg != key:
            continue
        raw = keyword.value
        if isinstance(raw, ast.Constant) and type(raw.value) in (int, str):
            values = [raw.value]
        elif isinstance(raw, (ast.Tuple, ast.List)) and len(raw.elts) <= 32:
            values = [item.value for item in raw.elts if isinstance(item, ast.Constant) and
                      type(item.value) in (int, str)]
            if len(values) != len(raw.elts):
                return "DYNAMIC_UNVERIFIED"
        else:
            return "DYNAMIC_UNVERIFIED"
        if len(values) > 32 or any(type(value) is str and not LITERAL_NAME.fullmatch(value)
                                   for value in values):
            return "DYNAMIC_UNVERIFIED"
        return values
    return "UNSPECIFIED"


def inspect_source(source):
    """AST-only, pure, bounded and deterministic; no arbitrary source eval."""
    if type(source) is str:
        try:
            raw = source.encode("utf-8", "strict")
        except UnicodeError:
            return {"status": "NOT_PARSED", "reason": "encoding_invalid", "executed": False}
    elif type(source) is bytes:
        raw = source
    else:
        raise TypeError("source_must_be_str_or_bytes")
    digest = hashlib.sha256(raw).hexdigest()
    base = {"schema_version": 1, "source_sha256": digest,
            "analysis": "AST_ONLY_STATIC", "executed": False,
            "imported_target_packages": False, "runtime_verified": False,
            "device_verified": False, "graph_compilation_verified": False,
            "checkpoint_loaded": False, "auto_repair_allowed": False,
            "python_parser_version": "{}.{}".format(*sys.version_info[:2])}
    if len(raw) > SOURCE_LIMIT:
        return dict(base, status="NOT_PARSED", reason="source_limit_exceeded", observations=[])
    try:
        text = raw.decode("utf-8", "strict")
        tree = ast.parse(text, filename="[STATIC_GRAPH_SOURCE]", mode="exec")
    except (SyntaxError, ValueError, UnicodeError, RecursionError):
        return dict(base, status="NOT_PARSED", reason="invalid_or_unsupported_source", observations=[])
    nodes = []
    for node in ast.walk(tree):
        nodes.append(node)
        if len(nodes) > NODE_LIMIT:
            return dict(base, status="NOT_PARSED", reason="ast_node_limit_exceeded", observations=[])
    aliases = _binding_aliases(tree)
    observations = []
    for node in nodes:
        if isinstance(node, ast.Call):
            resolved = _resolved_path(node.func, aliases)
            rule = ALLOWED_CALLS.get(resolved)
            if not rule:
                continue
            candidate = {"rule": rule, "api": resolved,
                         "line": node.lineno, "column": node.col_offset,
                         "basis": "AST_CALL", "verified": False}
            if resolved == "tensorflow.function":
                candidate["jit_compile"] = _bool_keyword(node, "jit_compile")
                candidate["autograph"] = _bool_keyword(node, "autograph")
            elif resolved == "jax.jit":
                candidate["static_argnums"] = _static_tuple_keyword(node, "static_argnums")
                candidate["static_argnames"] = _static_tuple_keyword(node, "static_argnames")
            observations.append(candidate)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    continue  # call visitor already records decorator as AST_CALL
                resolved = _resolved_path(decorator, aliases)
                rule = ALLOWED_CALLS.get(resolved)
                if rule in ("TF_GRAPH_FUNCTION", "JAX_JIT"):
                    observations.append({"rule": rule, "api": resolved,
                                         "line": getattr(decorator, "lineno", node.lineno),
                                         "column": getattr(decorator, "col_offset", node.col_offset),
                                         "basis": "AST_DECORATOR", "verified": False})
        if len(observations) > OBSERVATION_LIMIT:
            return dict(base, status="NOT_PARSED", reason="observation_limit_exceeded", observations=[])
    return dict(base, status="STATIC_OBSERVATIONS", aliases=sorted(aliases),
                observations=sorted(observations, key=lambda x: (x["line"], x["column"], x["rule"])),
                total_observations=len(observations))


def installed_metadata():
    """Distribution metadata only. Never imports a framework or probes a GPU."""
    result = {}
    for library, distribution in FRAMEWORK_DISTS.items():
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            result[library] = {"status": "NOT_INSTALLED"}
            continue
        except (OSError, ValueError) as error:
            result[library] = {"status": "NOT_RUN", "reason": type(error).__name__}
            continue
        if type(version) is not str or len(version) > 128 or any(
                ord(char) < 33 or ord(char) > 126 for char in version):
            result[library] = {"status": "NOT_RUN", "reason": "invalid_version_metadata"}
            continue
        result[library] = {"status": "INSTALLED_METADATA_ONLY", "version": version,
                           "imported": False, "runtime_verified": False}
    return {"status": "METADATA_ONLY", "installed": result,
            "runtime_verified": False, "accelerator_verified": False,
            "graph_compilation_verified": False, "executed_framework_code": False}


# Only these literal fixtures may execute. inspect_source remains non-executing;
# callers cannot supply a program, callback, module path or checkpoint here.
TF_FIXED_SOURCE = r'''
import json, sys
import tensorflow as tf
device, mode = sys.argv[1:3]
tf.config.set_soft_device_placement(False)
physical = tf.config.list_physical_devices('GPU' if device == 'gpu' else 'CPU')
assert physical, 'requested_device_not_available'
for gpu in tf.config.list_physical_devices('GPU'):
    tf.config.experimental.set_memory_growth(gpu, True)
target = '/GPU:0' if device == 'gpu' else '/CPU:0'
rules = ['TF_DEVICE_CONTEXT', 'TF_DEVICE_ENUMERATION']
negative = []
if mode == 'legacy_graph':
    tf.compat.v1.disable_eager_execution()
    assert not tf.executing_eagerly()
    with tf.device(target):
        value = tf.constant([1., 2., 3.]) * 2.
    config = tf.compat.v1.ConfigProto(allow_soft_placement=False)
    config.gpu_options.allow_growth = True
    with tf.compat.v1.Session(config=config) as session:
        assert session.run(value).tolist() == [2., 4., 6.]
    actual_device = value.device
    rules.append('TF_LEGACY_GRAPH_MODE_CONTROL')
elif mode == 'legacy_eager':
    tf.compat.v1.enable_eager_execution()
    assert tf.executing_eagerly()
    with tf.device(target):
        value = tf.constant([1., 2., 3.]) * 2.
    assert value.numpy().tolist() == [2., 4., 6.]
    actual_device = value.device
    rules.append('TF_LEGACY_EAGER_MODE_CONTROL')
else:
    tf.config.run_functions_eagerly(True)
    assert tf.config.functions_run_eagerly()
    tf.config.run_functions_eagerly(False)
    assert not tf.config.functions_run_eagerly()
    @tf.function(jit_compile=False, autograph=False)
    def graph(x):
        return x*x+1.
    @tf.function(jit_compile=True, autograph=False)
    def compiled(x):
        return x*x+1.
    @tf.function(autograph=False)
    def invalid_graph(x):
        return x.numpy()
    with tf.device(target):
        value = tf.constant([1., 2., 3.])
        graph_result = graph(value)
        compiled_result = compiled(value)
        assert graph_result.numpy().tolist() == [2., 5., 10.]
        assert compiled_result.numpy().tolist() == [2., 5., 10.]
        actual_device = compiled_result.device
        try:
            tf.matmul(tf.ones((2, 3)), tf.ones((2, 3)))
        except tf.errors.InvalidArgumentError:
            negative.append('SHAPE_MISMATCH_REJECTED')
        else:
            raise AssertionError('shape_mismatch_accepted')
        try:
            invalid_graph(value)
        except AttributeError:
            negative.append('GRAPH_EAGER_ONLY_API_REJECTED')
        else:
            raise AssertionError('graph_eager_only_api_accepted')
    rules += ['TF_GRAPH_FUNCTION', 'TF_EAGER_MODE_CONTROL']
    assert tf.config.list_logical_devices('GPU' if device == 'gpu' else 'CPU')
assert ('GPU:0' if device == 'gpu' else 'CPU:0') in actual_device, actual_device
try:
    with tf.device('/RPH_INVALID_DEVICE:0'):
        tf.constant([1.]) + 1.
except (ValueError, tf.errors.InvalidArgumentError, RuntimeError):
    negative.append('INVALID_DEVICE_REJECTED')
else:
    raise AssertionError('invalid_device_accepted')
print(json.dumps({'status':'FIXED_RUNTIME_PASS','framework':'tensorflow',
    'framework_version':tf.__version__,'requested_device':device,
    'actual_device':actual_device,'mode':mode,'executed_rules':rules,
    'negative_oracles':negative,'user_source_executed':False,
    'optimization_level':sys.flags.optimize}))
'''

JAX_FIXED_SOURCE = r'''
import json, sys
import jax
import jax.numpy as jnp
device = sys.argv[1]
devices = jax.devices('gpu' if device == 'gpu' else 'cpu')
assert devices, 'requested_device_not_available'
assert jax.local_devices(backend='gpu' if device == 'gpu' else 'cpu')
with jax.default_device(devices[0]):
    value = jax.device_put(jnp.array([1., 2., 3.]), devices[0])
    @jax.jit
    def compiled(x):
        return x*x+1.
    result = compiled(value)
    result.block_until_ready()
    assert result.tolist() == [2., 5., 10.]
    assert all(d.platform == ('gpu' if device == 'gpu' else 'cpu') for d in result.devices())
    selected = jax.jit(lambda x, axis: jnp.sum(x, axis=axis), static_argnums=(1,))
    assert selected(value, 0).item() == 6.
    named = jax.jit(lambda x, axis: jnp.sum(x, axis=axis), static_argnames=('axis',))
    assert named(value, axis=0).item() == 6.
    negative = []
    try:
        jnp.ones((2, 3)) @ jnp.ones((2, 3))
    except (TypeError, ValueError):
        negative.append('SHAPE_MISMATCH_REJECTED')
    else:
        raise AssertionError('shape_mismatch_accepted')
    try:
        jax.jit(lambda x: x if x > 0 else -x)(jnp.array(1.))
    except jax.errors.TracerBoolConversionError:
        negative.append('JIT_DYNAMIC_BOOL_REJECTED')
    else:
        raise AssertionError('dynamic_bool_accepted')
try:
    jax.devices('rph_invalid_backend')
except RuntimeError:
    negative.append('INVALID_DEVICE_REJECTED')
else:
    raise AssertionError('invalid_backend_accepted')
print(json.dumps({'status':'FIXED_RUNTIME_PASS','framework':'jax',
    'framework_version':jax.__version__,'jaxlib_version':__import__('jaxlib').__version__,
    'requested_device':device,'actual_device':str(next(iter(result.devices()))),
    'actual_platform':next(iter(result.devices())).platform,'mode':'jit',
    'executed_rules':['JAX_JIT','JAX_DEVICE_TRANSFER','JAX_DEVICE_ENUMERATION','JAX_DEFAULT_DEVICE_CONTEXT'],
    'negative_oracles':negative,'user_source_executed':False,
    'optimization_level':sys.flags.optimize}))
'''


def _fixed_runtime_environment(framework):
    environment = {"PATH": os.defpath, "OMP_NUM_THREADS": "1",
                   "TF_NUM_INTRAOP_THREADS": "1", "TF_NUM_INTEROP_THREADS": "1",
                   "TF_FORCE_GPU_ALLOW_GROWTH": "true",
                   "XLA_PYTHON_CLIENT_PREALLOCATE": "false",
                   "PYTHONIOENCODING": "utf-8"}
    if sys.platform == "win32" and os.environ.get("SystemRoot"):
        environment["SystemRoot"] = os.environ["SystemRoot"]
    if sys.platform.startswith("linux"):
        prefix = Path(sys.prefix).resolve()
        packages = prefix / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
        libraries = [p.resolve() for p in sorted((packages / "nvidia").glob("*/lib")) if p.is_dir()]
        if any(not p.is_relative_to(prefix) for p in libraries):
            raise ValueError("private_cuda_library_root_required")
        if libraries:
            environment["LD_LIBRARY_PATH"] = ":".join(map(str, libraries)) + ":/usr/lib/wsl/lib"
        compiler = packages / "nvidia" / "cuda_nvcc"
        if framework == "tensorflow" and compiler.is_dir():
            if not compiler.resolve().is_relative_to(prefix):
                raise ValueError("private_cuda_compiler_root_required")
            environment["XLA_FLAGS"] = "--xla_gpu_cuda_data_dir=" + str(compiler)
            environment["PATH"] = str(compiler / "bin") + ":" + os.defpath
    return environment


def _valid_runtime_observation(observed, framework, device, mode, static_rules):
    keys = {"status", "framework", "framework_version", "requested_device", "actual_device",
            "mode", "executed_rules", "negative_oracles", "user_source_executed", "optimization_level"}
    if framework == "jax":
        keys |= {"jaxlib_version", "actual_platform"}
    if type(observed) is not dict or set(observed) != keys:
        return False
    if (observed["status"] != "FIXED_RUNTIME_PASS" or observed["framework"] != framework or
            observed["requested_device"] != device or observed["mode"] != mode or
            type(observed["optimization_level"]) is not int or observed["optimization_level"] != 0 or
            observed["user_source_executed"] is not False):
        return False
    for field in ("framework_version", "jaxlib_version") if framework == "jax" else ("framework_version",):
        value = observed[field]
        if type(value) is not str or not 1 <= len(value) <= 128 or any(not 33 <= ord(c) <= 126 for c in value):
            return False
    actual = observed["actual_device"]
    if type(actual) is not str or not re.fullmatch(r"[A-Za-z0-9_:/.-]{1,256}", actual):
        return False
    required_rules = {
        "modern": {"TF_DEVICE_CONTEXT", "TF_DEVICE_ENUMERATION", "TF_GRAPH_FUNCTION", "TF_EAGER_MODE_CONTROL"},
        "legacy_graph": {"TF_DEVICE_CONTEXT", "TF_DEVICE_ENUMERATION", "TF_LEGACY_GRAPH_MODE_CONTROL"},
        "legacy_eager": {"TF_DEVICE_CONTEXT", "TF_DEVICE_ENUMERATION", "TF_LEGACY_EAGER_MODE_CONTROL"},
        "jit": {"JAX_JIT", "JAX_DEVICE_TRANSFER", "JAX_DEVICE_ENUMERATION", "JAX_DEFAULT_DEVICE_CONTEXT"},
    }[mode]
    required_negative = {"INVALID_DEVICE_REJECTED"}
    if mode in ("modern", "jit"):
        required_negative |= {"SHAPE_MISMATCH_REJECTED", "GRAPH_EAGER_ONLY_API_REJECTED" if framework == "tensorflow" else "JIT_DYNAMIC_BOOL_REJECTED"}
    for field, expected in (("executed_rules", required_rules), ("negative_oracles", required_negative)):
        values = observed[field]
        if type(values) is not list or any(type(v) is not str for v in values):
            return False
        if len(values) != len(set(values)) or set(values) != expected:
            return False
    if not required_rules <= static_rules:
        return False
    if framework == "jax":
        prefix_matches = actual.lower().startswith(("cuda:", "gpu:")) if device == "gpu" else actual.lower().startswith(("cpu:", "tfrt_cpu_"))
        return observed["actual_platform"] == ("gpu" if device == "gpu" else "cpu") and prefix_matches
    return ("GPU:0" if device == "gpu" else "CPU:0") in actual


def qualify_fixed_runtime(framework, device="cpu", timeout_seconds=90):
    """Test literal fixtures only; never executes inspect_source's caller input.

    A PASS is bound to this interpreter/framework/device and the literal source
    digest. Arbitrary graph/checkpoint/package compatibility is not asserted.
    Native Windows CUDA refusal does not become a CPU fallback PASS.
    """
    if framework not in ("tensorflow", "jax") or device not in ("cpu", "gpu"):
        raise ValueError("invalid_framework_or_device")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise ValueError("invalid_timeout")
    source = TF_FIXED_SOURCE if framework == "tensorflow" else JAX_FIXED_SOURCE
    static = inspect_source(source)
    if static["status"] != "STATIC_OBSERVATIONS":
        raise ValueError("fixed_fixture_static_inspection_failed")
    static_rules = {row["rule"] for row in static["observations"]}
    modes = ("modern", "legacy_graph", "legacy_eager") if framework == "tensorflow" else ("jit",)
    rows = []
    for mode in modes:
        try:
            child = subprocess.run([sys.executable, "-I", "-B", "-c", source, device, mode],
                                   capture_output=True, check=False, timeout=timeout_seconds,
                                   env=_fixed_runtime_environment(framework))
        except (OSError, subprocess.TimeoutExpired) as exc:
            rows.append({"mode": mode, "status": "NOT_RUN", "reason": type(exc).__name__})
            continue
        if child.returncode or len(child.stdout) > 16384 or len(child.stderr) > 65536:
            rows.append({"mode": mode, "status": "FAIL", "reason": "fixed_fixture_failed",
                         "exit_code": child.returncode,
                         "stderr_sha256": hashlib.sha256(child.stderr).hexdigest()})
            continue
        try:
            observed = json.loads(child.stdout)
        except (ValueError, UnicodeError):
            rows.append({"mode": mode, "status": "FAIL", "reason": "invalid_child_json"})
            continue
        valid = _valid_runtime_observation(observed, framework, device, mode, static_rules)
        row = {"mode": mode, "status": "PASS" if valid else "FAIL",
               "reason": "fixed_fixture_and_static_rule_link_verified" if valid else "child_oracle_mismatch",
               "stdout_sha256": hashlib.sha256(child.stdout).hexdigest()}
        if valid:
            row["observed"] = observed
        rows.append(row)
    return {"status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL",
            "framework": framework, "requested_device": device,
            "interpreter": sys.executable, "python_version": sys.version,
            "host_platform": sys.platform, "fixture_source_sha256": static["source_sha256"],
            "static_rules": sorted(static_rules), "static_observations": static["observations"], "cases": rows,
            "user_source_executed": False, "arbitrary_graph_compatibility_verified": False,
            "scope": "literal fixed fixtures, actual package/interpreter/device only"}
