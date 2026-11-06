"""Real Windows privacy/hash/scale negative contracts, no synthetic scale PASS."""
import hashlib
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('own_corpus',ROOT/'python/corpus_scale_v031.py')
MOD=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MOD)
import windows_privacy_fixtures as acl

@unittest.skipUnless(os.name=='nt','NOT_RUN actual Windows metrics/privacy fixture only')
class CorpusContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rph-corpus-policy-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);acl.set_private_acl(self.root)
        self.manifest=self.root/'manifest.json';self.db=self.root/'tiny.sqlite'
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('CREATE TABLE chunks(normalized_sha256 BLOB)')
            conn.execute('CREATE TABLE documents(rowid INTEGER PRIMARY KEY)')
            conn.execute('CREATE TABLE corpus_meta(key TEXT PRIMARY KEY,value TEXT)')
            conn.execute('INSERT INTO chunks VALUES(?)',(b'fixed-small-negative-only',))
            conn.commit()
        self.data={'schema_version':1,'unique_chunks':1000000,'content_minimum':15,
                   'content_maximum':512,'preflight_status':'REAL_MILLION_SCALE_INPUT_READY',
                   'fts_build_integrity':'PASS','database_sha256':self.sha(self.db),
                   'corpus_digest':'0'*64,'source_archive_sha256':'1'*64}
        self.save()

    def sha(self,path):return hashlib.sha256(path.read_bytes()).hexdigest()
    def save(self):
        self.manifest.write_text(json.dumps(self.data));self.pin=self.sha(self.manifest)

    def test_real_nearest_rank_percentile(self):
        self.assertEqual(MOD.percentile(list(range(1,101)),95),95)
        self.assertEqual(MOD.percentile([8,1,3,4,9],50),4)

    def test_no_measurements_never_get_fake_zero(self):
        with self.assertRaisesRegex(ValueError,'missing_actual'):MOD.percentile([],95)

    def test_materialized_fts_ranking_returns_stable_actual_rows(self):
        with closing(sqlite3.connect(':memory:')) as conn:
            conn.executescript('''CREATE TABLE documents(rowid INTEGER PRIMARY KEY,source_uri,document_id);
            CREATE TABLE chunks(rowid INTEGER PRIMARY KEY,document_rowid,content,content_sha256,char_start,char_end);
            CREATE VIRTUAL TABLE chunks_fts USING fts5(content,content='chunks',content_rowid='rowid');''')
            conn.execute('INSERT INTO documents VALUES(1,?,?)',('https://example.test/fixed-unit','OWN_FIXED_UNIT'))
            for i,text in enumerate(['science research article','science learning article','python library article'],1):
                conn.execute('INSERT INTO chunks VALUES(?,?,?,?,?,?)',(i,1,text,hashlib.sha256(text.encode()).digest(),0,len(text)))
            conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
            self.assertEqual([r[0] for r in conn.execute(MOD.QUERY_SQL,('"science"',))],[1,2])

    def test_actual_handle_cpu_and_memory_observation(self):
        result=MOD.windows_process_observation()
        self.assertEqual(result['pid'],os.getpid())
        self.assertGreater(result['working_set_bytes'],0)
        self.assertGreaterEqual(result['peak_working_set_bytes'],result['working_set_bytes'])
        self.assertGreater(result['handle_count'],0)
        self.assertGreater(result['process_creation_filetime'],0)

    def test_small_actual_database_cannot_fake_million_scale(self):
        with self.assertRaisesRegex(ValueError,'million_distinct'):
            MOD.benchmark_existing(self.db,self.manifest,self.pin,5)

    def test_manifest_below_one_million_cannot_reduce_floor(self):
        self.data['unique_chunks']=999999;self.save()
        with self.assertRaisesRegex(ValueError,'insufficient'):
            MOD.checked_manifest(self.manifest,self.pin)

    def test_manifest_excessive_rows_rejected(self):
        self.data['unique_chunks']=1500001;self.save()
        with self.assertRaisesRegex(ValueError,'insufficient'):MOD.checked_manifest(self.manifest,self.pin)

    def test_manifest_digest_required(self):
        with self.assertRaisesRegex(ValueError,'digest_required'):MOD.checked_manifest(self.manifest,None)

    def test_changed_manifest_rejected(self):
        self.manifest.write_bytes(self.manifest.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'digest_mismatch'):MOD.checked_manifest(self.manifest,self.pin)

    def test_changed_database_rejected_before_queries(self):
        self.data['database_sha256']='0'*64;self.save()
        with self.assertRaisesRegex(ValueError,'database_digest_mismatch'):
            MOD.benchmark_existing(self.db,self.manifest,self.pin,5)

    def test_public_manifest_acl_rejected(self):
        acl.set_public_read_acl(self.manifest)
        with self.assertRaises(ValueError):MOD.checked_manifest(self.manifest,self.pin)

    def test_manifest_symlink_rejected(self):
        original=self.root/'original.json';self.manifest.rename(original);self.manifest.symlink_to(original)
        with self.assertRaises((ValueError,OSError)):MOD.checked_manifest(self.manifest,self.pin)

    def test_hardlink_database_rejected(self):
        os.link(self.db,self.root/'alias.sqlite')
        with self.assertRaises(ValueError):MOD.benchmark_existing(self.db,self.manifest,self.pin,5)

    def test_owned_descriptor_closed_after_error(self):
        descriptor=None
        with self.assertRaisesRegex(RuntimeError,'fixed-interruption'):
            with MOD.private_data_lease(self.manifest,65536) as (fd,info):
                descriptor=fd;raise RuntimeError('fixed-interruption')
        with self.assertRaises(OSError):os.fstat(descriptor)

    def test_relative_paths_rejected(self):
        with self.assertRaisesRegex(ValueError,'absolute_private'):
            with MOD.private_data_lease(Path('relative.sqlite'),65536):pass

    def test_actual_ancestor_rename_blocked_then_succeeds_after_close(self):
        alias=self.root.with_name(self.root.name+'-renamed')
        self.root.rename(alias);alias.rename(self.root)  # Prove own rename rights.
        with MOD.private_data_lease(self.manifest,65536):
            with self.assertRaises(OSError) as caught:self.root.rename(alias)
            self.assertEqual(caught.exception.winerror,32)
            self.assertTrue(self.root.is_dir());self.assertFalse(alias.exists())
        self.root.rename(alias);alias.rename(self.root)

    def test_actual_ancestor_symlink_alias_rejected(self):
        alias=self.root.with_name(self.root.name+'-alias')
        alias.symlink_to(self.root,target_is_directory=True);self.addCleanup(alias.unlink)
        with self.assertRaisesRegex(ValueError,'ancestor_reparse'):
            with MOD.private_data_lease(alias/self.manifest.name,65536):pass

    def test_alternate_stream_path_rejected_before_open(self):
        with self.assertRaisesRegex(ValueError,'alternate_stream'):
            with MOD.private_data_lease(Path(str(self.manifest)+':stream'),65536):pass

    def test_unc_refused_before_any_directory_or_network_io(self):
        with mock.patch.object(MOD,'_directory_chain_lease',side_effect=AssertionError('unexpected traversal')):
            with self.assertRaisesRegex(ValueError,'local_absolute'):
                with MOD.private_data_lease(Path(r'\\untrusted.example\share\data'),65536):pass

    def test_recursive_view_cannot_masquerade_as_plain_corpus_table(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('DROP TABLE chunks')
            conn.execute('CREATE VIEW chunks AS WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT x AS normalized_sha256 FROM n')
        self.data['database_sha256']=self.sha(self.db);self.save()
        with self.assertRaisesRegex(ValueError,'plain_bounded'):
            MOD.benchmark_existing(self.db,self.manifest,self.pin,5)

    def test_iterations_are_bounded_without_threshold_downgrade(self):
        for value in [True,1,4,1001,None]:
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'iterations'):
                MOD.benchmark_existing(self.db,self.manifest,self.pin,value)

    def test_duplicate_manifest_fields_rejected(self):
        self.manifest.write_text('{"schema_version":1,"schema_version":1}');self.pin=self.sha(self.manifest)
        with self.assertRaisesRegex(ValueError,'duplicate_corpus'):MOD.checked_manifest(self.manifest,self.pin)

if __name__=='__main__':unittest.main()
