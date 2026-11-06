"""No Windows-only scope edit may silently manufacture a PASS."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WindowsScopeGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = json.loads((ROOT / "windows_scope.json").read_text(encoding="utf-8"))

    def test_seven_real_target_minors_planned(self):
        self.assertEqual(self.scope["target"]["python_minors"],
                         ["3.{}".format(i) for i in range(9, 16)])

    def test_exact_windows_target_is_recorded(self):
        self.assertEqual(self.scope["target"]["windows"], "11 Home")
        self.assertEqual(self.scope["target"]["architecture"], "x86_64")
        self.assertEqual(self.scope["target"]["gpu"], "NVIDIA")

    def test_thirty_canonical_open_ids_not_reduced_without_evidence(self):
        items = self.scope["open_features_last_observed"]
        self.assertEqual(len(items), 30)
        self.assertEqual(len(set(items)), 30)
        self.assertEqual(self.scope["baseline_implemented_tested_count_last_observed"], 230)
        self.assertTrue(self.scope["baseline_checklist_recovered"])
        self.assertTrue(self.scope["baseline_260_features_reaudited"])

    def test_macos_exclusion_is_not_a_completion(self):
        item = self.scope["scope_changes"]["F177"]
        self.assertEqual(item["status"], "OUT_OF_SCOPE_NOT_A_PASS")
        self.assertFalse(item["production_qualified"])

    def test_linux_updater_does_not_become_windows_pass(self):
        item = self.scope["scope_changes"]["F090"]
        self.assertEqual(item["status"], "LINUX_ELF_UPDATER_NOT_WINDOWS_SUPPORTED")
        self.assertFalse(item["production_qualified"])

    def test_nvidia_hardware_never_assumed(self):
        for item in ("F253", "F254"):
            self.assertTrue(self.scope["historical_scope_changes_v028"][item]["status"].endswith("NOT_RUN"))
            self.assertEqual(self.scope["scope_changes"][item]["status"], "IMPLEMENTED_TESTED_FIXED_RUNTIME_SCOPE")
            self.assertEqual(len(self.scope["scope_changes"][item]["source_sha256"]), 64)
            self.assertFalse(self.scope["scope_changes"][item]["production_qualified"])
        self.assertEqual(self.scope["current_implemented_tested_count"], 232)
        self.assertEqual(len(self.scope["current_open_features"]), 28)

    def test_six_gates_fail_closed(self):
        gates = self.scope["quality_gates"]
        self.assertEqual(set(gates), {"VEILIGHEID", "CORRECTHEID", "SNELHEID",
                                      "BETROUWBAARHEID", "COMPATIBILITEIT",
                                      "TOEKOMSTBESTENDIGHEID"})
        self.assertTrue(all(value in ("HOLD", "NOT_RUN", "FAIL") for value in gates.values()))
        self.assertIsNone(self.scope["winner"])
        self.assertIsNone(self.scope["verified_reserve"])

    def test_no_publish_or_audit_claim(self):
        self.assertFalse(self.scope["production_release_authorized"])
        self.assertFalse(self.scope["independent_audit"])


if __name__ == "__main__":
    unittest.main()
