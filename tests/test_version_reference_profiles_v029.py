"""Exact build identity and malformed-reference negatives; no learned golden."""
import copy, hashlib, importlib.util, json, platform, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('reference_profile_module',ROOT/'python/version_regression.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ExactReferenceProfiles(unittest.TestCase):
    def document(self):
        data=json.loads((ROOT/'config/version_regression_cases.json').read_text())
        data['require_exact_profile_for_minors']=[module.VERSION]
        data['runtime_profiles']=[{'id':'own-negative-fixture','python_minor':module.VERSION,
            'version':list(sys.version_info[:3]),'releaselevel':sys.version_info.releaselevel,
            'serial':sys.version_info.serial,'platform':sys.platform,'machine':platform.machine(),
            'executable_sha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            'reference':module.reference(module.observations())}]
        return data
    def inspect_document(self,data):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'reference.json';path.write_text(json.dumps(data))
            return module.inspect(path)
    def test_wrong_executable_identity_cannot_fall_back_to_minor(self):
        data=self.document();data['runtime_profiles'][0]['executable_sha256']='0'*64
        result=self.inspect_document(data)
        self.assertEqual(result['status'],'NOT_RUN')
        self.assertEqual(result['reason'],'exact_runtime_reference_identity_mismatch_or_ambiguous')
        self.assertFalse(result['trusted_embedded_probes_executed'])
    def test_unknown_exact_build_cannot_fall_back_to_minor(self):
        data=self.document();data['runtime_profiles'][0]['version'][2]+=1
        result=self.inspect_document(data)
        self.assertEqual(result['status'],'NOT_RUN');self.assertEqual(result['reason'],'exact_runtime_reference_missing')
    def test_ambiguous_matching_profiles_are_refused(self):
        data=self.document();other=copy.deepcopy(data['runtime_profiles'][0]);other['id']='other-id';data['runtime_profiles'].append(other)
        self.assertEqual(self.inspect_document(data)['status'],'NOT_RUN')
    def test_duplicate_profile_ids_are_invalid(self):
        data=self.document();data['runtime_profiles'].append(copy.deepcopy(data['runtime_profiles'][0]))
        self.assertEqual(self.inspect_document(data)['reason'],'invalid_runtime_profile_schema')
    def test_unhashable_minor_selector_is_rejected_without_crash(self):
        data=self.document();data['require_exact_profile_for_minors']=[[]]
        self.assertEqual(self.inspect_document(data)['reason'],'invalid_runtime_profile_schema')
    def test_profile_corruption_remains_real_regression(self):
        data=self.document();data['runtime_profiles'][0]['reference']['bytecode']['sha256']='0'*64
        result=self.inspect_document(data)
        self.assertEqual(result['status'],'REGRESSION');self.assertFalse(result['checks']['bytecode'])
        self.assertEqual(result['reference_authenticity'],'UNSIGNED_NOT_VERIFIED')
    def test_exact_minor_metadata_must_match_version(self):
        data=self.document();data['runtime_profiles'][0]['python_minor']='3.99'
        self.assertEqual(self.inspect_document(data)['reason'],'invalid_runtime_profile_schema')
    def test_legacy_315_reference_is_preserved(self):
        data=json.loads((ROOT/'config/version_regression_cases.json').read_text())
        self.assertEqual(data['versions']['3.15']['bytecode']['exception_table_bytes'],12)
        self.assertEqual(data['versions']['3.15']['bytecode']['sha256'],'26576bc454f473c3ecce705caea3bbdc82c7b9578220a2da2a5be1e3fc455224')
if __name__=='__main__':unittest.main()
