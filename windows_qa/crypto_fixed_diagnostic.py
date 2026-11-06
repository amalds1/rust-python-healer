"""CI-only diagnostic on the exact embedded dependency graph; no raw secrets."""
import hashlib,json,pathlib,re,sys,traceback
ROOT=pathlib.Path(__file__).resolve().parents[1]
TEMPLATE="import types, os\n_RPH_PINNED_PIP_WHEEL=os.environ.get('RPH_PINNED_PIP_WHEEL')\n_RPH_WINDOWS_PRIVACY=types.ModuleType('rph_bundled_windows_privacy')\nexec({privacy},_RPH_WINDOWS_PRIVACY.__dict__)\n_RPH_WINDOWS_BLOB_READER=types.ModuleType('rph_bundled_windows_blob_reader')\n_RPH_WINDOWS_BLOB_READER._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({blobs},_RPH_WINDOWS_BLOB_READER.__dict__)\n_RPH_PLATFORM_PRIVACY=types.ModuleType('rph_bundled_platform_privacy')\n_RPH_PLATFORM_PRIVACY._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({platform},_RPH_PLATFORM_PRIVACY.__dict__)\n_RPH_PROCESS_MEMORY=types.ModuleType('rph_bundled_process_memory')\nexec({memory},_RPH_PROCESS_MEMORY.__dict__)\n_RPH_WINDOWS_CHECKER=types.ModuleType('rph_bundled_windows_checker')\nexec({checker},_RPH_WINDOWS_CHECKER.__dict__)\n_RPH_WINDOWS_SECURITY=types.ModuleType('rph_bundled_windows_security')\n_RPH_WINDOWS_SECURITY._RPH_WINDOWS_BLOB_READER=_RPH_WINDOWS_BLOB_READER\n_RPH_WINDOWS_SECURITY._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({security},_RPH_WINDOWS_SECURITY.__dict__)\n_RPH_ECOSYSTEM_INTEGRITY=types.ModuleType('rph_bundled_ecosystem_wheel_integrity')\n_RPH_ECOSYSTEM_INTEGRITY._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({ecosystem_integrity},_RPH_ECOSYSTEM_INTEGRITY.__dict__)\n_RPH_MODEL_EVIDENCE_IO=types.ModuleType('rph_bundled_model_evidence_io')\n_RPH_MODEL_EVIDENCE_IO._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\n_RPH_MODEL_EVIDENCE_IO._RPH_WINDOWS_BLOB=_RPH_WINDOWS_BLOB_READER\nexec({model},_RPH_MODEL_EVIDENCE_IO.__dict__)\n_RPH_PREVIEW_MODULE_SOURCE={preview_module}\n_RPH_PREVIEW_SUITE_SOURCE={preview_suite}\n"
BINDINGS={'privacy': {'path': 'python/windows_private_paths.py', 'sha256': '4757571c16b83bd3bfff832b9838c6f75794ccbbd16cd27f78dfd4fa7e855f43'}, 'blobs': {'path': 'python/windows_blob_reader_v029.py', 'sha256': 'cf29578b3d9e2761855171aef71d135d5a8f02985ceb5e9f7869ecb2b23dd651'}, 'platform': {'path': 'python/platform_privacy_v028.py', 'sha256': '3ce5ee79996ebc89d7e4a1e5f0038e78462128a90f78f1d0ef840274ced49510'}, 'memory': {'path': 'python/process_memory.py', 'sha256': '1f1e9360e9147f533884c101a88a26dc0e16d9a230bd1add336bd328ac4aa97c'}, 'checker': {'path': 'python/windows_checker_process_v028.py', 'sha256': 'f01d3a58696f20570111567062bf693c53cbeeac3a1f67abf41d7951c0ce4cc8'}, 'security': {'path': 'python/windows_descriptor_security_v029.py', 'sha256': '74c5404195ce7cdb27fdf0caf2be88097d8de49ab8ebfc2f31601917329bb9a4'}, 'model': {'path': 'python/model_evidence_io_v029.py', 'sha256': 'da2a9eb9ad7f82285bd7b94af13b5ebb64d0cf8386c0330df45cc5d17bc6a1b2'}, 'ecosystem_integrity': {'path': 'python/ecosystem_wheel_integrity_v030.py', 'sha256': 'a4b150a19eb76a469741a6a3a876c014e38e2f788a634a36acdcd1a8e46d0b18'}, 'preview_module': {'path': 'python/prerelease_matrix_v23.py', 'sha256': '0a0c33fd33668969dcaed357acebd87ff509353fdbf69c15d02f6eb1008c278c'}, 'preview_suite': {'path': 'python/version_suite.py', 'sha256': '6db3a07ff9177552dafaef669184aa0178a6152b0302b76810d5d20f224827ef'}}
CRYPTO_SHA="ea3130992030a0ffcf48b77fad3dc4fa26c6f18e1a4eaefe9a888e035d0ccd0e"
SAFE_REASON_CODES=['archive_changed_before_atomic_swap', 'authentication_failed', 'authentication_tag_unavailable', 'caller_supplied_gcm_nonces_forbidden', 'cipher_unavailable', 'cryptographic_backend_unavailable', 'cryptographic_context_unavailable', 'decrypted_database_integrity_failed', 'decrypted_sqlite_dump_invalid', 'decryption_aad_failed', 'decryption_failed', 'decryption_initialization_failed', 'encrypted_envelope_invalid', 'encryption_aad_failed', 'encryption_failed', 'encryption_final_failed', 'encryption_initialization_failed', 'file_changed_during_open', 'file_changed_during_read', 'file_exceeds_quota', 'key_must_be_exactly_32_bytes', 'key_rotation_requires_distinct_key', 'plaintext_invalid_or_oversized', 'private_owner_only_directory_required', 'restored_database_integrity_failed', 'source_database_dump_quota', 'source_database_integrity_failed', 'source_database_replaced', 'trusted_encrypted_database_roundtrip_failed', 'unsafe_private_created_archive', 'unsafe_private_created_restore', 'unsafe_private_encrypted_archive', 'unsafe_private_key', 'unsafe_private_source_database', 'unsupported_or_unsafe_sqlite_schema', 'windows_ace_layout_unsupported', 'windows_ace_pointer_invalid', 'windows_ace_sid_bounds_invalid', 'windows_ace_sid_length_invalid', 'windows_ace_type_unsupported', 'windows_ace_unavailable', 'windows_dacl_budget', 'windows_effective_token_unavailable', 'windows_file_descriptor_invalid', 'windows_invalid_dacl', 'windows_invalid_sid', 'windows_local_absolute_leaf_required', 'windows_native_privacy_api_required', 'windows_null_dacl_refused', 'windows_privacy_disk_leaf_required', 'windows_privacy_leaf_open_refused', 'windows_privacy_leaf_type_mismatch', 'windows_privacy_owner_mismatch', 'windows_privacy_path_invalid', 'windows_privacy_reparse_leaf_refused', 'windows_privacy_security_info_unavailable', 'windows_privacy_single_link_required', 'windows_private_descriptor_transfer_failed', 'windows_private_read_open_refused', 'windows_process_token_unavailable', 'windows_same_directory_swap_required', 'windows_sid_budget', 'windows_token_sid_bounds_invalid', 'windows_token_sid_outside_buffer', 'windows_token_sid_pointer_invalid', 'windows_token_user_size_invalid', 'windows_token_user_unavailable', 'windows_untrusted_effective_allow_ace', 'windows_untrusted_inheritable_allow_ace']
SOURCE_IDENTITIES=[]

def pinned(path, expected):
    data=(ROOT/path).read_bytes()
    actual=hashlib.sha256(data).hexdigest()
    SOURCE_IDENTITIES.append({"module":pathlib.Path(path).name,"expected_sha256":expected,
                              "actual_sha256":actual,"byte_count":len(data),
                              "identity_match":actual==expected})
    if actual!=expected:
        raise RuntimeError("reviewed_source_identity_changed")
    return data.decode("utf-8")
def safe_failure(error):
    frames=[{"function":frame.name,"line":frame.lineno,
             "module":pathlib.Path(frame.filename).name}
            for frame in traceback.extract_tb(error.__traceback__)]
    chain=[];seen=set()
    while error is not None and id(error) not in seen and len(chain)<8:
        seen.add(id(error))
        item={"type":type(error).__name__,"errno":getattr(error,"errno",None),
              "winerror":getattr(error,"winerror",None)}
        text=str(error)
        if text in SAFE_REASON_CODES:
            item["static_error_code"]=text
        next_error=error.__cause__ or error.__context__
        item["next_link"]=("cause" if error.__cause__ else "context" if error.__context__ else None)
        chain.append(item);error=next_error
    return {"status":"FIXED_SELFTEST_FAILED","frames":frames,"exception_chain":chain}
def main():
    source=pinned("python/encrypted_catalog_v22.py",CRYPTO_SHA)
    prelude=TEMPLATE
    for name,pin in BINDINGS.items():
        prelude=prelude.replace("{"+name+"}",json.dumps(pinned(pin["path"],pin["sha256"])))
    report={"scope":"fixed crypto diagnostics; not a CI qualification verdict",
            "python_version":list(sys.version_info),"crypto_source_sha256":CRYPTO_SHA,
            "helper_source_sha256":{name:pin["sha256"] for name,pin in BINDINGS.items()},
            "source_identities":SOURCE_IDENTITIES,
            "prelude_sha256":hashlib.sha256(prelude.encode()).hexdigest(),"modes":[]}
    for mode in ("direct_reviewed_module","embedded_rust_prelude"):
        try:
            if mode=="embedded_rust_prelude":
                namespace={"__name__":"rph_fixed_crypto_diagnostic","__file__":__file__}
                exec(prelude,namespace)
                exec(source,namespace)
            else:
                import importlib.util
                spec=importlib.util.spec_from_file_location("rph_fixed_crypto_direct",ROOT/"python/encrypted_catalog_v22.py")
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                namespace=module.__dict__
            result={"capabilities":namespace["backend_capabilities"]()}
            try: result["selftest"]=namespace["trusted_selftest"]()
            except Exception as error: result["selftest"]=safe_failure(error)
        except Exception as error: result=safe_failure(error)
        report["modes"].append(dict(mode=mode,**result))
    passed=all(row.get("capabilities",{}).get("authenticated_encryption") is True
               and row.get("selftest",{}).get("status")=="TRUSTED_LOCAL_AES256_GCM_ROTATION_AND_RESTORE_PASS"
               for row in report["modes"])
    report["status"]="FIXED_DIRECT_AND_EMBEDDED_SELFTEST_PASS" if passed else "FIXED_CRYPTO_DIAGNOSTIC_FAIL"
    print(json.dumps(report,sort_keys=True))
    return 0 if passed else 1
if __name__=="__main__":
    try: code=main()
    except Exception as error:
        print(json.dumps({**safe_failure(error),"status":"DIAGNOSTIC_SOURCE_OR_SETUP_FAILED","source_identities":SOURCE_IDENTITIES},sort_keys=True));code=2
    raise SystemExit(code)
