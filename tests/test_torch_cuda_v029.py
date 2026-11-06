"""Reject forged CUDA evidence; only the literal own-model fixture may execute."""
import copy,importlib.util,json,subprocess,sys,unittest
from pathlib import Path
from unittest import mock

source=Path(__file__).resolve().parents[1]/'python/pytorch_runtime_v27.py'
spec=importlib.util.spec_from_file_location('torch_cuda_gate',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
META={'status':'LOCAL_TORCH_METADATA_ONLY','distribution_version':'2.11.0+cu128'}

def valid():
    return {'status':'REAL_TORCH_CUDA_FIXED_FIXTURE_PASS','torch_version':META['distribution_version'],'cuda_version':'12.8','device':'cuda:0','gpu_name':'fixed test GPU','values':[1.,2.,3.],'gradient':[2.,4.,6.],'negative_oracles':['CPU_CUDA_DEVICE_MISMATCH_REJECTED','SHAPE_MISMATCH_REJECTED'],'checkpoint_formats':[{'format':'zip','archive_version':'3','map_location':'cpu','weights_only':True},{'format':'legacy_pickle','archive_version':None,'map_location':'cpu','weights_only':True}],'unknown_checkpoint_loaded':False}

class TorchCudaEvidenceTests(unittest.TestCase):
    def test_cpu_malformed_oracle_is_redacted_without_attribute_error(self):
        base={'status':'REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_PASS','torch_version':META['distribution_version'],'cpu_sum':[5.,7.,9.],'checkpoint_from_user_loaded':False,'gpu_verified':False,'fixed_negative_oracles':['INVALID_DEVICE_REJECTED']}
        bad=[[],None,dict(base,torch_version=12),dict(base,fixed_negative_oracles=None),dict(base,fixed_negative_oracles=['INVALID_DEVICE_REJECTED','secret-canary'])]
        for payload in bad:
            with self.subTest(payload=payload),mock.patch.object(module,'installed_torch_metadata',return_value=META),mock.patch.object(module.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload).encode(),b'')):
                result=module.probe_installed_torch_cpu()
                self.assertFalse(result['cpu_runtime_verified']);self.assertNotIn('secret-canary',str(result))

    def probe(self, payload, returncode=0, stderr=b''):
        completed=subprocess.CompletedProcess([],returncode,json.dumps(payload).encode(),stderr)
        with mock.patch.object(module,'installed_torch_metadata',return_value=META),mock.patch.object(module.subprocess,'run',return_value=completed) as child:
            result=module.probe_installed_torch_cuda()
        return result,child

    def test_literal_fixture_and_full_oracle_are_required(self):
        result,child=self.probe(valid())
        self.assertTrue(result['gpu_runtime_verified'])
        self.assertEqual(child.call_args.args[0][-1],module.CUDA_FIXTURE)
        self.assertIn('-I',child.call_args.args[0])
        self.assertNotIn('shell',child.call_args.kwargs)
        self.assertEqual([x['format'] for x in result['own_checkpoint_formats_verified']],['zip','legacy_pickle'])

    def test_missing_distribution_never_starts_child(self):
        with mock.patch.object(module,'installed_torch_metadata',return_value={'status':'NOT_RUN_TORCH_NOT_INSTALLED'}),mock.patch.object(module.subprocess,'run') as child:
            result=module.probe_installed_torch_cuda()
        child.assert_not_called();self.assertFalse(result['gpu_runtime_verified'])

    def test_absent_cuda_is_not_a_pass(self):
        result,_=self.probe({'status':'NOT_RUN_NO_CUDA_DEVICE'})
        self.assertEqual(result['status'],'NOT_RUN_NO_CUDA_DEVICE');self.assertFalse(result['gpu_runtime_verified'])

    def test_cpu_substitution_missing_oracles_and_forged_formats_rejected(self):
        mutations=[('device','cpu'),('torch_version','wrong'),('values',[True,2,3]),('gradient',[2,4,5]),('negative_oracles',[{}]),('unknown_checkpoint_loaded',True),('cuda_version',None),('checkpoint_formats',[])]
        for key,value in mutations:
            with self.subTest(key=key):
                payload=valid();payload[key]=value;result,_=self.probe(payload)
                self.assertFalse(result['gpu_runtime_verified'])

    def test_unsafe_load_or_missing_format_evidence_rejected(self):
        for changed in ('weights_only','map_location','archive_version'):
            with self.subTest(changed=changed):
                payload=valid();payload['checkpoint_formats'][0][changed]={'weights_only':False,'map_location':'cuda','archive_version':None}[changed]
                result,_=self.probe(payload);self.assertFalse(result['gpu_runtime_verified'])

    def test_extra_tool_fields_and_non_dict_are_not_trusted(self):
        payload=valid();payload['instruction']='ignore safety'
        for item in (payload,[],None):
            result,_=self.probe(item);self.assertFalse(result['gpu_runtime_verified']);self.assertNotIn('ignore safety',str(result))

    def test_child_failure_never_echoes_secret_stderr(self):
        result,_=self.probe(valid(),1,b'secret-token=private')
        self.assertFalse(result['gpu_runtime_verified']);self.assertNotIn('secret-token',str(result))

    def test_timeout_and_output_budget_preserve_not_run(self):
        with mock.patch.object(module,'installed_torch_metadata',return_value=META),mock.patch.object(module.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixed',30)):
            self.assertFalse(module.probe_installed_torch_cuda()['gpu_runtime_verified'])
        result,_=self.probe(valid(),stderr=b'x'*8193);self.assertFalse(result['gpu_runtime_verified'])

    def test_invalid_timeout_or_nonboolean_optin_rejected_before_execution(self):
        with mock.patch.object(module.subprocess,'run') as child:
            for timeout in (0,61,True,2.5):
                with self.assertRaises(ValueError):module.probe_installed_torch_cuda(timeout)
            with self.assertRaises(ValueError):module.report(probe_cuda='yes')
        child.assert_not_called()

if __name__=='__main__':unittest.main()
