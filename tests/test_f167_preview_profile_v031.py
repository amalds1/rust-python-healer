"""Reject unselected future profiles before any process probe is dispatched."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('f167_preview',ROOT/'python/windows_spawn_f167.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class F167PreviewProfileTests(unittest.TestCase):
    def test_316_requires_separate_consent_before_process_or_channels(self):
        with mock.patch.object(module.core,'inspect_method') as run, self.assertRaisesRegex(ValueError,'separate_opt_in'):
            module.qualify('3.16')
        run.assert_not_called()
    def test_preview_consent_does_not_widen_stable_profiles(self):
        with mock.patch.object(module.core,'inspect_method') as run, self.assertRaisesRegex(ValueError,'separate_opt_in'):
            module.qualify('3.15',allow_reviewed_preview=True)
        run.assert_not_called()
    def test_non_boolean_consent_refused_before_execution(self):
        for value in (1,'yes',[],None):
            with self.subTest(value=value), mock.patch.object(module.core,'inspect_method') as run, self.assertRaisesRegex(ValueError,'must_be_boolean'):
                module.qualify('3.16',allow_reviewed_preview=value)
            run.assert_not_called()
    def test_other_future_minor_refused_before_execution(self):
        with mock.patch.object(module.core,'inspect_method') as run, self.assertRaisesRegex(ValueError,'unsupported_requested_minor'):
            module.qualify('3.17',allow_reviewed_preview=True)
        run.assert_not_called()

if __name__=='__main__':unittest.main()
