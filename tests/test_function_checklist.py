"""The checklist must fail closed when functions or requirements drift."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import hashlib
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("function_checklist_audit", ROOT / "tools" / "audit_function_checklist.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class ChecklistTests(unittest.TestCase):
    def test_distinct_rust_drop_owners_are_distinct_registered_methods(self):
        source = "impl Drop for First {\n    fn drop(&mut self) {}\n}\nimpl Drop for Second {\n    fn drop(&mut self) {}\n}\n"
        self.assertEqual(module.rust_names(source), ["Drop<First>.drop", "Drop<Second>.drop"])

    def test_real_duplicate_rust_functions_or_drop_owners_still_fail(self):
        for source in ("fn duplicate() {}\nfn duplicate() {}\n",
                       "impl Drop for Same {\n fn drop(&mut self) {}\n}\nimpl Drop for Same {\n fn drop(&mut self) {}\n}\n"):
            with self.assertRaisesRegex(ValueError, "dubbele Rust"):
                module.rust_names(source)

    def test_all_existing_code_functions_are_registered(self):
        result = module.audit()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["unregistered_symbols"], [])
        self.assertEqual(result["stale_registered_symbols"], [])

    def test_registry_has_260_unique_feature_ids(self):
        items = module.parse_checklist(module.CHECKLIST.read_text(encoding="utf-8"))
        self.assertEqual(len(items), 260)
        self.assertEqual(len({item["id"] for item in items}), 260)

    def test_every_open_feature_has_an_explicit_reason(self):
        items = module.parse_checklist(module.CHECKLIST.read_text(encoding="utf-8"))
        self.assertEqual(sum(item["reason"] is not None for item in items), 25)
        self.assertEqual(sum(item["status"] == "IMPLEMENTED_TESTED" for item in items), 235)
        self.assertTrue(all(item["reason"] for item in items
                            if item["status"] != "IMPLEMENTED_TESTED"))

    def test_v020_exactly_25_new_verified_functions(self):
        items = {item["id"]: item for item in module.parse_checklist(
            module.CHECKLIST.read_text(encoding="utf-8"))}
        v20 = {59, 69, 80, 98, 100, 116, 117, 161, 162, 163, 165, 166,
               168, 170, 189, 197, 198, 199, 202, 216, 224, 225, 232,
               234, 249}
        self.assertEqual(len(v20), 25)
        self.assertTrue(all(items["F{:03d}".format(fid)]["status"] == "IMPLEMENTED_TESTED"
                            for fid in v20))
        for fid in (239,):
            item = items["F{:03d}".format(fid)]
            self.assertEqual(item["status"], "PARTIAL")
            self.assertTrue(item["reason"])

    def test_v021_exactly_50_new_verified_functions(self):
        items = {item["id"]: item for item in module.parse_checklist(
            module.CHECKLIST.read_text(encoding="utf-8"))}
        v21 = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 27, 28, 29,
               30, 57, 58, 115, 122, 123, 126, 128, 129, 130, 136, 137,
               138, 140, 148, 164, 179, 183, 184, 187, 190, 191, 192,
               193, 196, 200, 215, 233, 236, 242, 243, 244, 245, 246,
               250, 260}
        self.assertEqual(len(v21), 50)
        self.assertTrue(all(items["F{:03d}".format(fid)]["status"] == "IMPLEMENTED_TESTED"
                            for fid in v21))
        for fid in (114,):
            item = items["F{:03d}".format(fid)]
            self.assertEqual(item["status"], "PARTIAL")
            self.assertTrue(item["reason"])

    def test_v022_exactly_25_new_verified_functions(self):
        items = {item["id"]: item for item in module.parse_checklist(
            module.CHECKLIST.read_text(encoding="utf-8"))}
        v22 = {60, 89, 95, 97, 99, 105, 109, 152, 153, 154, 155, 156,
               157, 158, 178, 181, 182, 185, 186, 201, 203, 210,
               214, 219, 229}
        self.assertEqual(len(v22), 25)
        self.assertTrue(all(items["F{:03d}".format(fid)]["status"] == "IMPLEMENTED_TESTED"
                            for fid in v22))
        # These remain explicitly PARTIAL despite added bounded adapters;
        # no native Windows, general-purpose type checker, external AI audit,
        # or universal sensitive-log redaction has been demonstrated.
        for fid in (114, 207, 208, 239):
            item = items["F{:03d}".format(fid)]
            self.assertEqual(item["status"], "PARTIAL")
            self.assertTrue(item["reason"])
        proof_root = ROOT / "evidence/windows_r8/F167"
        proof = json.loads((proof_root / "contract.json").read_text(encoding="utf-8"))
        self.assertEqual(items["F167"]["status"], "IMPLEMENTED_TESTED")
        self.assertEqual(proof["status"], "IMPLEMENTED_TESTED")
        self.assertEqual(proof["runtime_phase_of_316"], "alpha1")
        self.assertEqual(proof["F046_future_stable_316"], "NOT_RUN")
        self.assertFalse(proof["production_release_authorized"])
        for path, digest in proof["source_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)
        for path, digest in proof["receipts_sha256"].items():
            self.assertEqual(hashlib.sha256((proof_root / path).read_bytes()).hexdigest(), digest)

    def test_v023_thirty_new_verified_functions_with_real_local_boundaries(self):
        items = {item["id"]: item for item in module.parse_checklist(
            module.CHECKLIST.read_text(encoding="utf-8"))}
        v23 = {47, 49, 67, 68, 77, 79, 91, 92, 93, 149, 159, 160, 171, 172, 173, 174, 176,
               188, 209, 211, 220, 226, 235, 251, 252, 255, 256, 257, 258, 259}
        self.assertEqual(len(v23), 30)
        self.assertTrue(all(items["F{:03d}".format(fid)]["status"] == "IMPLEMENTED_TESTED"
                            for fid in v23))
        for fid in (39, 46, 50, 90, 107, 108, 110, 134, 135,
                    146, 147, 150, 204, 205, 206, 208,
                    239, 241, 247, 248,
                    127):
            item = items["F{:03d}".format(fid)]
            self.assertNotEqual(item["status"], "IMPLEMENTED_TESTED")
            self.assertTrue(item["reason"])
        # F145 now has actual bounded native evidence; external CI stays open.
        native = json.loads((ROOT / "evidence/windows_r8/CORE_VALIDATION.json").read_text(encoding="utf-8"))
        self.assertEqual(items["F145"]["status"], "IMPLEMENTED_TESTED")
        self.assertEqual(native["feature"], "F145")
        self.assertTrue(native["development_checkbox_only"])
        self.assertEqual(native["binary_sha256"], hashlib.sha256(
            (ROOT / "target/release/rust-python-healer.exe").read_bytes()).hexdigest())
        self.assertFalse(native["release_authorized"])
        self.assertEqual(native["external_hosted_CI"], "NOT_RUN")

    def test_new_framework_passes_require_exact_runtime_source_and_review(self):
        evidence = ROOT / "evidence" / "windows_v029"
        for feature, module_name, runtime_name, review_name in (
            ("F253", "pytorch_runtime_v27.py", "F253-runtime.json", "F253-independent-review.json"),
            ("F254", "graph_framework_runtime_v27.py", "F254-verdict.json", "F254-independent-review.json"),
        ):
            with self.subTest(feature=feature):
                expected = hashlib.sha256((ROOT / "python" / module_name).read_bytes()).hexdigest()
                runtime = json.loads((evidence / runtime_name).read_text(encoding="utf-8"))
                self.assertEqual(runtime["module_sha256"], expected)
                self.assertEqual(runtime.get("status", runtime.get("verdict")), "PASS")
                review = json.loads((evidence / review_name).read_text(encoding="utf-8"))
                self.assertEqual(review["verdict"], "PASS")
                reviewed_hash = review.get("module_sha256", review.get("current_source", {}).get("module_sha256"))
                self.assertEqual(reviewed_hash, expected)
        for filename in ("runtime-native-tf-cpu-closed.json", "runtime-native-jax-cpu-closed.json",
                         "runtime-wsl-tf-gpu-closed.json", "runtime-wsl-jax-gpu-closed.json"):
            route = json.loads((evidence / filename).read_text(encoding="utf-8"))
            self.assertEqual(route["status"], "PASS")
            self.assertTrue(all(row["status"] == "PASS" for row in route["cases"]))

    def test_a_missing_reason_fails_closed(self):
        source = module.CHECKLIST.read_text(encoding="utf-8")
        damaged = source.replace("  - Reden: ", "  - Ontbreekt: ", 1)
        with self.assertRaisesRegex(ValueError, "geen reden"):
            module.parse_checklist(damaged)

    def test_completed_feature_must_not_have_open_reason(self):
        source = module.CHECKLIST.read_text(encoding="utf-8")
        source = source.replace("- [x] F001 Python-bron compile-only controleren — IMPLEMENTED_TESTED",
                                "- [x] F001 Python-bron compile-only controleren — IMPLEMENTED_TESTED\n"
                                "  - Reden: Nog een reden na PASS is tegenstrijdig en wordt geweigerd.", 1)
        with self.assertRaisesRegex(ValueError, "geen openstaande reden"):
            module.parse_checklist(source)

    def test_feature_checkbox_cannot_claim_unbuilt_pass(self):
        with self.assertRaises(ValueError):
            module.parse_checklist("- [x] F001 New feature — NOT_IMPLEMENTED\n")

    def test_duplicate_feature_id_is_rejected(self):
        invalid = "- [ ] F001 Placeholder — NOT_IMPLEMENTED\n" * 80
        with self.assertRaises(ValueError):
            module.parse_checklist(invalid)

    def test_added_code_function_causes_audit_failure(self):
        missing, stale = module.compare({"src/main.rs": ["main", "new_function"]},
                                        {"src/main.rs": ["main"]})
        self.assertEqual(missing, ["src/main.rs::new_function"])
        self.assertEqual(stale, [])

    def test_rust_generic_unsafe_and_const_functions_are_inventoried(self):
        source = (
            "fn simple() {}\n"
            "pub fn generic<T: Clone>(value: T) {}\n"
            "pub(crate) unsafe fn checked<I: Iterator>(value: I) {}\n"
            "pub const fn fixed() {}\n"
            "pub extern \"C\" fn foreign() {}\n"
        )
        self.assertEqual(set(module.RUST_FUNCTION.findall(source)),
                         {"simple", "generic", "checked", "fixed", "foreign"})

    def test_removed_code_function_causes_audit_failure(self):
        missing, stale = module.compare({"python/a.py": ["one"]},
                                        {"python/a.py": ["one", "old"]})
        self.assertEqual(missing, [])
        self.assertEqual(stale, ["python/a.py::old"])

    def test_every_exposed_rust_command_is_registered(self):
        report = module.audit()
        self.assertEqual(report["cli_commands"]["Commands"], [
            "Ast", "Bench", "Catalog", "Check", "Dap", "Deps", "Flaky", "Lab",
            "Matrix", "Project", "Property", "Qualify", "Record", "Repair",
            "Runtime", "Sbom", "Scan", "Static", "Trace", "Update", "VersionRegression"
        ])
        self.assertEqual(len(report["cli_commands"]["CatalogCommands"]), 7)
        self.assertEqual(report["unregistered_cli_commands"], [])

    def test_new_cli_command_without_registry_entry_fails(self):
        missing, stale = module.compare({"Commands": ["Check", "NewCommand"]},
                                        {"Commands": ["Check"]})
        self.assertEqual(missing, ["Commands::NewCommand"])
        self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
