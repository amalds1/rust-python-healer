"""F257 genuine Redis broker, two Celery workers and Redis Streams evidence.

Every interpreter runs actual Redis/Celery processes, not fake mocks or a
synthetic in-memory queue.  Only reviewed immutable worker task is executed.
"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "real_queue_v23.py"
spec = importlib.util.spec_from_file_location("real_queue_v23", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
MINOR = "{}.{}".format(*sys.version_info[:2])


LEGACY_READY = (os.name=="posix" and module.REDIS_BUILD is not None and module.REDIS_BUILD.is_file()
                and module.REDIS_TARBALL.is_file()
                and module._sha(module.REDIS_BUILD,module.MAX_BINARY_BYTES)==module.LOCAL_BUILT_REDIS_SHA256)
LEGACY_NOT_RUN = ("NOT_RUN_NATIVE_WINDOWS_REDIS_UNSUPPORTED" if os.name=="nt" else
                  "NOT_RUN_ORIGINAL_LEGACY_LINUX_BUILD_NOT_PRESENT; separate WSL-R6 profile is not its replacement")

def private_folder(folder):
    os.chmod(folder,0o700)
    if os.name=="nt":
        import windows_privacy_fixtures
        windows_privacy_fixtures.set_private_acl(Path(folder))


def embedded_cli(mode):
    # Exercise exec without __file__ while avoiding Windows' 32K argv limit.
    # Only this reviewed repository source is supplied on stdin.
    return subprocess.run([sys.executable,"-I","-S","-B","-c",
        "import sys;exec(compile(sys.stdin.buffer.read(),'<trusted-embedded-queue>','exec'),globals())",
        "--mode",mode],input=SCRIPT.read_bytes(),capture_output=True,check=False,timeout=6)


class RealCeleryRedisTests(unittest.TestCase):
    @unittest.skipUnless(LEGACY_READY,LEGACY_NOT_RUN)
    def test_official_redis_tarball_and_compiled_binary_sha_pinned(self):
        report = module.verified_redis_binary()
        self.assertEqual(report["status"], "OFFICIAL_SOURCE_SHA_AND_LOCAL_BUILD_VERIFIED")
        self.assertEqual(report["source_sha256"], module.REDIS_SOURCE_SHA256)
        self.assertEqual(report["local_binary_sha256"], module.LOCAL_BUILT_REDIS_SHA256)
        self.assertFalse(report["production_binary_publisher_attested"])

    @unittest.skipUnless(LEGACY_READY,LEGACY_NOT_RUN)
    def test_real_redis_binary_reports_expected_version(self):
        done = subprocess.run([str(module.REDIS_BUILD), "--version"],
                              capture_output=True, check=False, timeout=4)
        self.assertEqual(done.returncode, 0)
        self.assertIn(b"Redis server v=7.2.11", done.stdout)

    @unittest.skipUnless(LEGACY_READY,LEGACY_NOT_RUN)
    def test_celery_and_redis_clients_are_real_pinned_wheels_for_this_python(self):
        report = module.verify_private_clients(MINOR, sys.executable)
        self.assertEqual(report["status"], "ACTUAL_OFFLINE_CELERY_REDIS_IMPORTS_VERIFIED")
        self.assertEqual(report["python_minor"], MINOR)
        self.assertEqual(report["celery"], "5.5.3")
        self.assertEqual(report["redis_client"], "6.4.0")

    def test_future_unsupported_minor_fails_closed(self):
        with self.assertRaisesRegex(module.QueueEvidenceRejected, "NOT_SUPPORTED"):
            module.verify_private_clients("3.16", sys.executable)

    def test_invalid_redis_binary_pin_cannot_start_fake_server(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-fake-redis-") as folder:
            fake = Path(folder) / "redis-server"
            fake.write_bytes(b"NOT_AN_AUTHENTIC_REDIS_BINARY")
            with self.assertRaisesRegex(module.QueueEvidenceRejected, "SHA_MISMATCH"):
                module.verified_redis_binary(fake,module.backend_profile(module.WSL_R6_BACKEND_PROFILE).tarball,profile=module.WSL_R6_BACKEND_PROFILE)

    def test_missing_redis_binary_is_not_a_false_success(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-missing-redis-") as folder:
            report = module.verified_redis_binary(Path(folder) / "missing-server",
                                                  module.REDIS_TARBALL)
            self.assertEqual(report["status"], "NOT_RUN_NATIVE_WINDOWS_REDIS_UNSUPPORTED" if os.name=="nt" else "NOT_RUN_NO_LOCAL_REDIS_SERVER")
            self.assertFalse(report["crossprocess_tested"])

    def test_wrong_upstream_tarball_pin_blocks_redis_execution(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-fake-source-") as folder:
            fake = Path(folder) / "redis-7.2.11.tar.gz"
            fake.write_bytes(b"not the official Redis source tarball")
            with self.assertRaisesRegex(module.QueueEvidenceRejected, "SHA_MISMATCH"):
                module.verified_redis_binary(module.backend_profile(module.WSL_R6_BACKEND_PROFILE).binary,fake,profile=module.WSL_R6_BACKEND_PROFILE)

    def test_redis_private_config_always_loopback_protected_and_password(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-config-") as folder:
            private_folder(folder)
            secret = "a" * 64
            config = module._private_redis_config(folder, 54321, secret)
            raw = config.read_text(encoding="ascii")
            self.assertIn("bind 127.0.0.1", raw)
            self.assertIn("protected-mode yes", raw)
            self.assertIn("requirepass " + secret, raw)
            self.assertIn("save \"\"", raw)
            self.assertIn("appendonly no", raw)
            self.assertNotIn("0.0.0.0", raw)
            if os.name=="nt":
                self.assertEqual(module._windows_privacy().assert_private_file(config)['status'],'PRIVATE_WINDOWS_LEAF_CONFIRMED')
            else:self.assertEqual(config.stat().st_mode & 0o777,0o600)

    def test_public_config_directory_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-public-config-") as folder:
            os.chmod(folder, 0o755)
            if os.name=="nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_public_read_acl(Path(folder))
            with self.assertRaisesRegex(module.QueueEvidenceRejected, "OWNER_PRIVATE"):
                module._private_redis_config(folder, 54321, "b" * 64)

    def test_invalid_password_or_port_cannot_create_config(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-bad-config-") as folder:
            with self.assertRaises(module.QueueEvidenceRejected):
                module._private_redis_config(folder, 0, "short")

    def test_worker_refuses_any_non_loopback_broker_before_running_task(self):
        cmd = [sys.executable, "-I", "-S", "-B", str(SCRIPT),
               "--mode", "worker", "--minor", MINOR]
        done = subprocess.run(cmd, capture_output=True, check=False,
                              timeout=8, env=dict(os.environ,RPH_TRUSTED_REDIS_URL=
                                              "redis://:fake@0.0.0.0:6379/0",
                                              RPH_TRUSTED_WORKER_NAME="rph_v23_a@localhost"))
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(b"redis://:fake@0.0.0.0:6379/0", done.stdout)
        self.assertEqual(json.loads(done.stdout)["reason"],"WORKER_BROKER_NOT_LOOPBACK")

    @unittest.skipUnless(LEGACY_READY,LEGACY_NOT_RUN)
    def test_cli_availability_is_read_only_and_bounded(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                               "--mode", "availability"], capture_output=True,
                              check=False, timeout=6)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["status"],
                         "OFFICIAL_SOURCE_SHA_AND_LOCAL_BUILD_VERIFIED")

    def test_standalone_capability_never_claims_real_broker_execution(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                               "--mode", "capabilities"], capture_output=True,
                              check=False, timeout=6)
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["status"],
                         "REAL_REDIS_CELERY_PRIVATE_ADAPTER_AVAILABLE")
        self.assertFalse(report["redis_server_executed"])
        self.assertFalse(report["crossprocess_tested"])
        self.assertFalse(report["unknown_project_source_executed"])

    def test_rust_embedded_capability_without_file_is_read_only(self):
        done = embedded_cli("capabilities")
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["status"],
                         "REAL_REDIS_CELERY_PRIVATE_ADAPTER_AVAILABLE")
        self.assertFalse(report["redis_server_executed"])
        self.assertFalse(report["crossprocess_tested"])

    def test_rust_embedded_real_run_without_file_fails_closed(self):
        done = embedded_cli("run")
        self.assertEqual(done.returncode, 2, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["status"], "NOT_VERIFIED")
        self.assertEqual(report["reason"],
                         "REQUIRES_STANDALONE_TRUSTED_SOURCE")
        self.assertFalse(report["unknown_project_code_executed"])

    @unittest.skipUnless(LEGACY_READY,LEGACY_NOT_RUN)
    def test_real_broker_two_worker_processes_queue_success_and_error_correlation(self):
        # The entire trusted broker+Celery scenario must run in its own
        # isolated interpreter: earlier unittest modules may already have
        # imported an unrelated, incompatible `packaging` namespace into
        # sys.modules. An inherited test-process module cache must never
        # decide whether real Redis-worker correlation succeeds.
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                               "--mode", "run", "--minor", MINOR],
                              capture_output=True, text=True, check=False,
                              timeout=40)
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["status"],
                         "REAL_REDIS_CELERY_CROSSPROCESS_ERROR_CORRELATION_PASS")
        self.assertEqual(report["real_broker_processes"], 1)
        self.assertEqual(report["real_worker_processes"], 2)
        self.assertGreaterEqual(report["distinct_workers_observed"], 2)
        self.assertEqual(report["tasks_successful"], 24)
        self.assertEqual(report["tasks_failed_expected"], 1)
        self.assertEqual(report["redis_stream_events_correlated"], 25)
        self.assertEqual(report["broker_bind"], "127.0.0.1")
        self.assertFalse(report["password_disclosed"])
        self.assertFalse(report["unknown_project_code_executed"])
        self.assertFalse(report["external_redis_network_used"])
        self.assertFalse(report["windows_macos_real_worker_proven"])
        self.assertNotIn("redis://:", json.dumps(report))


class PortableQueueContractTests(unittest.TestCase):
    def test_separate_profile_never_replaces_original_local_build_pin(self):
        self.assertEqual(module.LOCAL_BUILT_REDIS_SHA256,"213b4b0be30768e156092d6bd2bc1bd53133463d202b60b42ff955f4e5a38800")
        legacy=module.backend_profile();new=module.backend_profile(module.WSL_R6_BACKEND_PROFILE)
        self.assertNotEqual(legacy.binary_sha256,new.binary_sha256)
        self.assertEqual(new.python_minors,("3.12",))
        with self.assertRaisesRegex(module.QueueEvidenceRejected,"NOT_ALLOWLISTED"):
            module.backend_profile("arbitrary-binary")

    def test_profile_host_guard_matches_only_its_reviewed_metadata(self):
        observed={'system':'Linux','release':module.WSL_R6_HOST_KERNEL,'machine':'x86_64',
                  'uid':module.WSL_R6_HOST_UID,'os_release_sha256':module.WSL_R6_OS_RELEASE_SHA256}
        self.assertTrue(module.wsl_r6_host_scope_qualified(observed))
        for field,value in [('uid',0),('uid',1001),('uid','1000'),('release','other-WSL2-kernel'),
                            ('machine','aarch64'),('system','Windows'),('os_release_sha256','0'*64)]:
            self.assertFalse(module.wsl_r6_host_scope_qualified(dict(observed,**{field:value})))

    def test_hash_reader_rejects_symlink_and_hardlink_without_execution(self):
        with tempfile.TemporaryDirectory(prefix="r6-queue-hash-") as folder:
            path=Path(folder)/"fixed.txt";path.write_bytes(b"fixed byte oracle")
            import hashlib
            self.assertEqual(module._sha(path,1024),hashlib.sha256(b"fixed byte oracle").hexdigest())
            alias=Path(folder)/"alias.txt";alias.symlink_to(path)
            with self.assertRaises((module.QueueEvidenceRejected,OSError)):
                module._sha(alias,1024)
            alias.unlink();os.link(path,alias)
            with self.assertRaisesRegex(module.QueueEvidenceRejected,"UNSAFE"):
                module._sha(path,1024)

    def test_invalid_config_injection_cannot_create_any_config(self):
        for port,password in [(True,"a"*64),(0,"a"*64),(65536,"a"*64),(54321,"a"*40+"\nport 6379"),(54321,"short")]:
            with tempfile.TemporaryDirectory(prefix="r6-queue-config-") as folder:
                private_folder(folder)
                with self.assertRaises(module.QueueEvidenceRejected):module._private_redis_config(folder,port,password)
                self.assertFalse((Path(folder)/"redis.conf").exists())

    @unittest.skipUnless(os.name=="nt","native Windows unsupported-backend contract")
    def test_windows_verifies_artifact_identity_but_does_not_execute_linux_backend(self):
        report=module.verified_redis_binary(profile=module.WSL_R6_BACKEND_PROFILE)
        self.assertEqual(report['status'],'NOT_RUN_NATIVE_WINDOWS_REDIS_UNSUPPORTED')
        self.assertTrue(report['artifact_identity_verified'])
        self.assertFalse(report['redis_server_available'])
        self.assertFalse(report['crossprocess_tested'])
        self.assertFalse(report['native_windows_execution_proven'])


@unittest.skipUnless(os.name=="posix" and 'microsoft' in __import__('platform').release().lower(),
                     "NOT_RUN_WSL_R6_EXECUTION_REQUIRES_WSL_LINUX; not a native Windows PASS")
class WslR6QueueFixtureTests(unittest.TestCase):
    def test_exact_reviewed_source_compiler_binary_and_host_profile(self):
        report=module.verified_redis_binary(profile=module.WSL_R6_BACKEND_PROFILE)
        self.assertTrue(report['redis_server_available'])
        self.assertEqual(report['local_binary_sha256'],module.WSL_R6_BUILT_REDIS_SHA256)
        self.assertEqual(report['peer_review_sha256'],module.WSL_R6_PEER_REVIEW_SHA256)
        self.assertEqual(report['backend_host_distribution'],'kali')
        self.assertFalse(report['production_binary_publisher_attested'])
        self.assertFalse(report['native_windows_execution_proven'])

    def test_actual_private_snapshot_imports_exact_clients(self):
        report=module.verify_private_clients('3.12',sys.executable,profile=module.WSL_R6_BACKEND_PROFILE)
        self.assertEqual(report['celery'],'5.5.3');self.assertEqual(report['redis_client'],'6.4.0')
        self.assertTrue(report['private_linux_snapshot_used'])
        self.assertEqual(report['python_minor'],'3.12');self.assertEqual(report['python_implementation'],'cpython')
        self.assertIn('3.12.16',report['python_runtime_version'])

    def test_client_probe_refuses_claimed_minor_that_differs_from_real_interpreter(self):
        with module._prepared_clients('3.12',module.WSL_R6_BACKEND_PROFILE) as site:
            with self.assertRaisesRegex(module.QueueEvidenceRejected,'ACTUAL_CLIENT_PROBE_PYTHON_MINOR_MISMATCH'):
                module._probe_private_clients('3.9',sys.executable,site,module.WSL_R6_BACKEND_PROFILE)

    def test_other_python_minor_not_silently_qualified_on_this_backend(self):
        with self.assertRaisesRegex(module.QueueEvidenceRejected,'MINOR_NOT_QUALIFIED'):
            module.verify_private_clients('3.14',sys.executable,profile=module.WSL_R6_BACKEND_PROFILE)

    def test_private_snapshot_detects_actual_modified_module_before_import(self):
        with module._prepared_clients('3.12',module.WSL_R6_BACKEND_PROFILE) as site:
            target=site/'redis/__init__.py'
            raw=target.read_bytes();target.write_bytes(raw+b'\n# fixed tamper fixture\n')
            with self.assertRaisesRegex(module.QueueEvidenceRejected,'MODULE_HASH_MISMATCH'):
                module._private_linux_site(site)

    def test_real_wsl_broker_two_workers_actual_success_error_stream_and_cleanup(self):
        done=subprocess.run([sys.executable,'-I','-S','-B',str(SCRIPT),'--mode','run','--minor','3.12',
                             '--backend-profile',module.WSL_R6_BACKEND_PROFILE],capture_output=True,text=True,timeout=60)
        self.assertEqual(done.returncode,0,done.stderr)
        report=json.loads(done.stdout)
        type(self).queue_proof=report
        self.assertEqual(report['status'],'REAL_REDIS_CELERY_CROSSPROCESS_ERROR_CORRELATION_PASS')
        self.assertEqual(report['backend_profile'],module.WSL_R6_BACKEND_PROFILE)
        self.assertEqual(report['real_broker_processes'],1);self.assertEqual(report['real_worker_processes'],2)
        self.assertGreaterEqual(report['distinct_workers_observed'],2)
        self.assertEqual(report['tasks_successful'],24);self.assertEqual(report['tasks_failed_expected'],1)
        self.assertEqual(report['redis_stream_events_correlated'],25)
        self.assertTrue(report['cleanup']['loopback_port_closed'])
        self.assertTrue(all(p['reaped'] for p in report['cleanup']['owned_processes']))
        self.assertFalse(report['windows_macos_real_worker_proven'])
        self.assertFalse(report['backend_identity']['native_windows_execution_proven'])
        self.assertNotIn('redis://:',json.dumps(report))


    def test_owned_process_timeout_uses_same_pidfd_and_reaps_forced_kill(self):
        import select
        code="import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('READY',flush=True);time.sleep(30)"
        child=module._owned_spawn([sys.executable,'-I','-S','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(select.select([child.stdout],[],[],4)[0])
            self.assertEqual(child.stdout.readline(),b'READY\n')
            proof=module._stop(child)
            type(self).timeout_proof=proof
            self.assertTrue(proof['kernel_pidfd_used']);self.assertTrue(proof['kill_after_timeout'])
            self.assertEqual(proof['exit_code'],-9);self.assertTrue(proof['reaped'])
            self.assertEqual(proof['before']['start_ticks'],proof['before_signal']['start_ticks'])
            self.assertEqual(proof['before']['command_line'],proof['before_signal']['command_line'])
        finally:
            if child.poll() is None:module._stop(child)
            child.stdout.close()

    def test_kernel_parent_death_kills_and_subreaper_reaps_exact_owned_descendant(self):
        import ctypes,select,signal,time
        libc=ctypes.CDLL(None,use_errno=True);old=ctypes.c_int()
        self.assertEqual(libc.prctl(37,ctypes.byref(old),0,0,0),0)
        self.assertEqual(libc.prctl(36,1,0,0,0),0)
        parent=None;descendant=None;descendant_fd=None;reaped=False
        bootstrap=("import importlib.util,json,pathlib,subprocess,sys,time;"
                   "s=importlib.util.spec_from_file_location('owned_queue_parent',sys.argv[1]);"
                   "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);"
                   "p=m._owned_spawn([sys.executable,'-I','-S','-B','-c','import time;time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                   "pathlib.Path(sys.argv[2]).write_text(json.dumps(m._process_identity(p)));print('READY',flush=True);time.sleep(30)")
        try:
            with tempfile.TemporaryDirectory(prefix='r6-owned-parent-death-',dir='/tmp') as folder:
                lease=Path(folder)/'child.json'
                parent=module._owned_spawn([sys.executable,'-I','-S','-B','-c',bootstrap,str(SCRIPT),str(lease)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                self.assertTrue(select.select([parent.stdout],[],[],5)[0]);self.assertEqual(parent.stdout.readline(),b'READY\n')
                identity=json.loads(lease.read_text());descendant=identity['pid'];descendant_fd=os.pidfd_open(descendant)
                from types import SimpleNamespace
                current=module._process_identity(SimpleNamespace(pid=descendant))
                self.assertEqual(current,identity)
                parent_proof=module._stop(parent)
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    got,status=os.waitpid(descendant,os.WNOHANG)
                    if got:reaped=True;break
                    time.sleep(.02)
                self.assertTrue(reaped,'kernel parent-death signal must stop its exact child')
                self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
                type(self).parent_death_proof={'parent':parent_proof,'descendant_before':identity,'kernel_parent_death_signal':9,'descendant_reaped':True}
        finally:
            if parent is not None:
                if parent.poll() is None:module._stop(parent)
                parent.stdout.close()
            if descendant_fd is not None:
                if not reaped:
                    try:signal.pidfd_send_signal(descendant_fd,signal.SIGKILL);os.waitpid(descendant,0)
                    except (ProcessLookupError,ChildProcessError):pass
                os.close(descendant_fd)
            self.assertEqual(libc.prctl(36,old.value,0,0,0),0)


if __name__ == "__main__":
    unittest.main()
