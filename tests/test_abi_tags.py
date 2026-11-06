"""F175: real-interpreter read-only wheel ABI comparison, 3.9 through 3.15."""

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("abi_tags", ROOT / "python" / "abi_tags.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def runtime(minor=None, debug=False, threaded=False, platform="linux_x86_64", soabi=None):
    return {
        "implementation": "cpython", "major": 3,
        "minor": minor if minor is not None else sys.version_info.minor,
        "debug": debug, "debug_known": True,
        "free_threaded": threaded, "soabi": soabi,
        "platform": platform, "metadata_source": "SYNTHETIC_TEST_FIXTURE",
    }


def wheel(py, abi="none", platform="any", build=None):
    suffix = "-{}".format(build) if build is not None else ""
    return "harmless-1.2{}-{}-{}-{}.whl".format(suffix, py, abi, platform)


def compatibility(name, meta=None):
    return module.compare_wheel(name, meta)["compatibility"]


class AbiTagTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Actual Windows release metadata")
    def test_windows_missing_debug_flag_requires_exact_native_metadata(self):
        original = module.sysconfig.get_config_var
        with mock.patch.object(module.sysconfig, "get_config_var",
                side_effect=lambda key: None if key == "Py_DEBUG" else original(key)):
            self.assertTrue(module.inspect_runtime()["debug_known"])
            with mock.patch.object(module.platform, "machine", return_value="unknown_arch"):
                self.assertFalse(module.inspect_runtime()["debug_known"])
        with mock.patch.object(module.sysconfig, "get_config_var",
                side_effect=lambda key: None if key == "Py_DEBUG" else ".cp999-win_amd64.pyd" if key == "EXT_SUFFIX" else original(key)):
            self.assertFalse(module.inspect_runtime()["debug_known"])

    def test_windows_identifiable_soabi_must_match_minor_flags_and_architecture(self):
        for soabi in ("cp399-win_amd64", "cp314t-win_amd64", "cp314-win_arm64"):
            with self.subTest(soabi=soabi):
                detail = module.compare_wheel(wheel("cp314", "cp314", "win_amd64"),
                    runtime(minor=14, platform="win_amd64", soabi=soabi))
                self.assertNotEqual(detail["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
    def test_inspects_actual_interpreter_not_pretense(self):
        actual = module.inspect_runtime()
        self.assertEqual(actual["implementation"], sys.implementation.name)
        self.assertEqual((actual["major"], actual["minor"]), sys.version_info[:2])
        self.assertEqual(actual["soabi"], sysconfig.get_config_var("SOABI"))
        self.assertEqual(actual["metadata_source"], "ACTUAL_RUNNING_INTERPRETER")
        self.assertEqual(actual["free_threaded"],
                         bool(sysconfig.get_config_var("Py_GIL_DISABLED")))

    def test_actual_runtime_python3_pure_tag_acceptance(self):
        result = module.compare_wheel(wheel("py3"))
        self.assertEqual(result["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
        self.assertEqual(result["source"], "ACTUAL_RUNNING_INTERPRETER")
        self.assertFalse(result["native_extensions_loaded"])
        self.assertFalse(result["artifact_authenticated"])
        self.assertFalse(result["installation_performed"])

    def test_actual_runtime_minor_specific_pure_wheel(self):
        self.assertEqual(compatibility(wheel("py3{}".format(sys.version_info.minor))),
                         "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_actual_runtime_cross_version_pure_tag_rejected(self):
        different = sys.version_info.minor + 1
        self.assertEqual(compatibility(wheel("py3{}".format(different))),
                         "INCOMPATIBLE_TAG")

    def test_python_39_pure_wheel_tag_is_accepted_on_later_minor_versions(self):
        for minor in range(9, 16):
            self.assertEqual(compatibility(wheel("py39"), runtime(minor=minor)),
                             "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
        self.assertEqual(compatibility(wheel("py315"), runtime(minor=14)),
                         "INCOMPATIBLE_TAG")

    def test_actual_runtime_exact_cp_abi_matches_not_import_proven(self):
        meta = module.inspect_runtime()
        py = "cp3{}".format(meta["minor"])
        abi = "cp3{}{}{}".format(meta["minor"],
                                "t" if meta["free_threaded"] else "",
                                "d" if meta["debug"] else "")
        result = module.compare_wheel(wheel(py, abi, meta["platform"]))
        self.assertEqual(result["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
        self.assertFalse(result["native_import_verified"])
        self.assertFalse(result["platform_policy_verified"])

    def test_actual_runtime_cross_version_native_tag_rejected(self):
        meta = module.inspect_runtime()
        different = 9 if meta["minor"] != 9 else 15
        self.assertEqual(compatibility(wheel("cp3{}".format(different),
                                              "cp3{}".format(different), meta["platform"])),
                         "INCOMPATIBLE_TAG")

    def test_runtime_abi_shape_gil_release(self):
        for minor in range(9, 16):
            result = module.compare_wheel(wheel("cp3{}".format(minor),
                                                "cp3{}".format(minor), "linux_x86_64"),
                                          runtime(minor=minor))
            self.assertEqual(result["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
            self.assertEqual(result["runtime_abi"], "cp3{}".format(minor))

    def test_debug_build_matches_same_version_debug_abi(self):
        for minor in range(9, 16):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor),
                                                 "cp3{}d".format(minor), "linux_x86_64"),
                                           runtime(minor=minor, debug=True)),
                             "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_debug_build_can_use_release_abi_since_python38(self):
        for minor in range(9, 16):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor),
                                                 "cp3{}".format(minor), "linux_x86_64"),
                                           runtime(minor=minor, debug=True)),
                             "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_release_build_rejects_debug_wheel(self):
        for minor in range(9, 16):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor),
                                                 "cp3{}d".format(minor), "linux_x86_64"),
                                           runtime(minor=minor)), "INCOMPATIBLE_TAG")

    def test_free_threaded_313_314_315_exact_native_abi(self):
        for minor in range(13, 16):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor),
                                                 "cp3{}t".format(minor), "linux_x86_64"),
                                           runtime(minor=minor, threaded=True)),
                             "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_free_threaded_debug_build_abi(self):
        for minor in range(13, 16):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor),
                                                 "cp3{}td".format(minor), "linux_x86_64"),
                                           runtime(minor=minor, threaded=True, debug=True)),
                             "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_free_threaded_rejects_gil_native_wheel(self):
        for minor in range(13, 16):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor),
                                                 "cp3{}".format(minor), "linux_x86_64"),
                                           runtime(minor=minor, threaded=True)),
                             "INCOMPATIBLE_TAG")

    def test_gil_rejects_free_threaded_native_wheel(self):
        for minor in range(13, 16):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor),
                                                 "cp3{}t".format(minor), "linux_x86_64"),
                                           runtime(minor=minor)), "INCOMPATIBLE_TAG")

    def test_free_threaded_313_314_rejects_both_stable_abis(self):
        for minor in (13, 14):
            for abi in ("abi3", "abi3t"):
                self.assertEqual(compatibility(wheel("cp3{}".format(minor), abi,
                                                     "linux_x86_64"),
                                               runtime(minor=minor, threaded=True)),
                                 "INCOMPATIBLE_TAG")

    def test_free_threaded_315_accepts_abi3t_with_older_minimum_tag(self):
        for declared in (9, 10, 13, 14, 15):
            self.assertEqual(compatibility(wheel("cp3{}".format(declared), "abi3t",
                                                 "linux_x86_64"),
                                           runtime(minor=15, threaded=True)),
                             "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_free_threaded_315_rejects_gil_abi3(self):
        self.assertEqual(compatibility(wheel("cp315", "abi3", "linux_x86_64"),
                                       runtime(minor=15, threaded=True)), "INCOMPATIBLE_TAG")

    def test_gil_315_rejects_free_threaded_abi3t(self):
        self.assertEqual(compatibility(wheel("cp315", "abi3t", "linux_x86_64"),
                                       runtime(minor=15)), "INCOMPATIBLE_TAG")

    def test_gil_accepts_previous_stable_abi_tags(self):
        for minor in range(9, 16):
            for declared in range(9, minor + 1):
                self.assertEqual(compatibility(wheel("cp3{}".format(declared), "abi3",
                                                     "linux_x86_64"),
                                               runtime(minor=minor)),
                                 "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_stable_abi_rejects_newer_minimum_version(self):
        for minor in range(9, 15):
            self.assertEqual(compatibility(wheel("cp3{}".format(minor + 1), "abi3",
                                                 "linux_x86_64"),
                                           runtime(minor=minor)), "INCOMPATIBLE_TAG")

    def test_known_cross_os_platform_is_incompatible(self):
        self.assertEqual(compatibility(wheel("py3", "none", "win_amd64"),
                                       runtime(platform="linux_x86_64")), "INCOMPATIBLE_TAG")
        self.assertEqual(compatibility(wheel("py3", "none", "macosx_11_0_arm64"),
                                       runtime(platform="win_amd64")), "INCOMPATIBLE_TAG")

    def test_non_exact_platform_policy_remains_unverified(self):
        self.assertEqual(compatibility(wheel("cp39", "abi3", "manylinux_2_17_x86_64"),
                                       runtime(minor=15)), "UNKNOWN_NOT_VERIFIED")
        self.assertEqual(compatibility(wheel("cp39", "abi3", "musllinux_1_2_x86_64"),
                                       runtime(minor=15)), "UNKNOWN_NOT_VERIFIED")
        self.assertEqual(compatibility(wheel("py3", "none", "linux_aarch64"),
                                       runtime(platform="linux_x86_64")), "UNKNOWN_NOT_VERIFIED")

    def test_compressed_tags_are_cartesian_product(self):
        tag = "harmless-1.2-cp39.py3-cp39.none-win_amd64.linux_x86_64.whl"
        parsed = module.parse_wheel_filename(tag)
        self.assertEqual(len(parsed["python_tags"]), 2)
        self.assertEqual(len(parsed["abi_tags"]), 2)
        self.assertEqual(len(parsed["platform_tags"]), 2)
        result = module.compare_wheel(tag, runtime(minor=15))
        self.assertEqual(result["evaluated_combinations"], 8)
        self.assertEqual(result["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
        self.assertEqual(result["matching_tag"], "py3-none-linux_x86_64")

    def test_build_tag_supported_without_execution(self):
        parsed = module.parse_wheel_filename(wheel("py3", build="2abc"))
        self.assertEqual(parsed["build"], "2abc")
        self.assertEqual(compatibility(wheel("py3", build="2abc")),
                         "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_malformed_wheels_never_assumed_compatible(self):
        malformed = (
            "", "not_a_wheel", "package-1.0.whl", "-1.0-py3-none-any.whl",
            "x--py3-none-any.whl", "x-one-py3-none-any.whl",
            "x-1.0-abc-py3-none-any.whl", "x-1.0-py3..py39-none-any.whl",
            "x-1.0-py3.py3-none-any.whl", "x-1.0-py3-none-any.any.whl",
            "x-1.0-py3-none-any.wHl", "x-1.0-py3-none-any.whl.zip",
            "x-1.0-py3-abi3-any.whl/../somewhere", "../x-1.0-py3-none-any.whl",
        )
        for candidate in malformed:
            with self.subTest(name=candidate):
                self.assertEqual(module.compare_wheel(candidate)["status"],
                                 "INVALID_WHEEL_FILENAME")

    def test_rejects_path_traversal_absolute_backslash_and_nonascii(self):
        for prefix in ("/tmp/", "../../", "../", "C:\\temp\\", "./", "é", "\x00"):
            self.assertEqual(module.compare_wheel(prefix + wheel("py3"))["status"],
                             "INVALID_WHEEL_FILENAME")

    def test_symlink_and_hardlink_paths_do_not_access_wheel_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / wheel("py3")
            original.write_bytes(b"PRIVATE_WHEEL_PAYLOAD_987654321\n")
            symlink = Path(directory) / "linked.whl"
            symlink.symlink_to(original)
            hardlink = Path(directory) / "hard.whl"
            os.link(original, hardlink)
            for target in (str(original), str(symlink), str(hardlink)):
                result = module.compare_wheel(target)
                self.assertEqual(result["status"], "INVALID_WHEEL_FILENAME")
                self.assertNotIn("PRIVATE_WHEEL", json.dumps(result))
            # A filename-only comparison does not require a file to exist.
            result = module.compare_wheel(wheel("py3"))
            self.assertEqual(result["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
            self.assertFalse(result["source_executed"])

    def test_oversize_and_unbounded_tag_combinations_rejected(self):
        self.assertEqual(module.compare_wheel(wheel("py3") + "z" * 1000)["status"],
                         "INVALID_WHEEL_FILENAME")
        many = ".".join("py3{}".format(x) for x in range(2, 26))
        self.assertEqual(module.compare_wheel(wheel(many))["status"],
                         "INSPECTED_TAGS")
        too_many = many + ".py326"
        result = module.compare_wheel(wheel(too_many))
        self.assertEqual(result["reason"], "wheel_tag_count_limit")
        self.assertEqual(result["status"], "INVALID_WHEEL_FILENAME")
        products = ".".join("p{}".format(x) for x in range(7))
        result = module.compare_wheel(wheel(products, products, products))
        self.assertEqual(result["reason"], "wheel_tag_combination_limit")

    def test_unknown_abi_does_not_assume_compatibility(self):
        self.assertEqual(compatibility(wheel("cp39", "futureabi", "linux_x86_64"),
                                       runtime(minor=9)), "UNKNOWN_NOT_VERIFIED")

    def test_generic_python_tag_cannot_pair_with_native_abi(self):
        self.assertEqual(compatibility(wheel("py3", "cp39", "linux_x86_64"),
                                       runtime(minor=9)), "INCOMPATIBLE_TAG")
        self.assertEqual(compatibility(wheel("py39", "abi3", "linux_x86_64"),
                                       runtime(minor=9)), "INCOMPATIBLE_TAG")

    def test_native_tag_cannot_use_platform_any(self):
        self.assertEqual(compatibility(wheel("cp39", "cp39", "any"),
                                       runtime(minor=9)), "INCOMPATIBLE_TAG")
        self.assertEqual(compatibility(wheel("cp39", "abi3", "any"),
                                       runtime(minor=15)), "INCOMPATIBLE_TAG")

    def test_inconsistent_soabi_never_yields_a_pass(self):
        mixed = runtime(minor=13, threaded=True, soabi="cpython-313-x86_64-linux-gnu")
        result = module.compare_wheel(wheel("cp313", "cp313t", "linux_x86_64"), mixed)
        self.assertEqual(result["compatibility"], "UNKNOWN_NOT_VERIFIED")
        self.assertEqual(result["reason"], "runtime_abi_metadata_inconsistent")

    def test_invalid_runtime_metadata_and_unsupported_version_fail_closed(self):
        self.assertEqual(module.compare_wheel(wheel("py3"), {})["status"],
                         "INVALID_RUNTIME_METADATA")
        for minor in (8, 16):
            result = module.compare_wheel(wheel("py3"), runtime(minor=minor))
            self.assertEqual(result["compatibility"], "UNKNOWN_NOT_VERIFIED")
            self.assertEqual(result["reason"], "runtime_version_not_supported")
        impossible = module.compare_wheel(wheel("py3"), runtime(minor=12, threaded=True))
        self.assertEqual(impossible["compatibility"], "UNKNOWN_NOT_VERIFIED")
        self.assertEqual(impossible["reason"], "impossible_runtime_abi_flags")

    def test_result_never_includes_raw_filename_or_private_payload(self):
        secret = "SENSITIVE_TOKEN_983749"
        bad = module.compare_wheel(secret + "/../" + wheel("py3"))
        self.assertNotIn(secret, json.dumps(bad))
        self.assertFalse(bad["artifact_authenticated"])
        self.assertFalse(bad["source_executed"])

    def test_cli_is_standalone_isolated_json_no_native_extension_load(self):
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(ROOT / "python" / "abi_tags.py"),
             "--wheel", wheel("py3")],
            capture_output=True, text=True, timeout=15, check=True)
        data = json.loads(result.stdout)
        self.assertEqual(data["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
        self.assertEqual(data["source"], "ACTUAL_RUNNING_INTERPRETER")
        self.assertFalse(data["native_extensions_loaded"])
        self.assertFalse(data["native_import_verified"])


if __name__ == "__main__":
    unittest.main()
