#![cfg(windows)]
//! Actual executable policy tests in disposable, separately provisioned local
//! installations. No production policy path or environment bypass is used.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[repr(C)]
struct Security { length: u32, descriptor: *mut c_void, inherit: i32 }
#[link(name="kernel32")]
extern "system" {
    fn CreateDirectoryW(path:*const u16, security:*const Security)->i32;
    fn CreateFileW(path:*const u16, access:u32, share:u32, security:*const Security,
                   disposition:u32, flags:u32, template:*mut c_void)->*mut c_void;
    fn LocalFree(memory:*mut c_void)->*mut c_void;
}
#[link(name="advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text:*const u16, revision:u32,
        descriptor:*mut *mut c_void, size:*mut u32)->i32;
}

fn native_private(path:&Path, sid:&str, bytes:Option<&[u8]>) {
    let text:Vec<u16>=format!("O:{sid}D:P(A;OICI;FA;;;{sid})").encode_utf16().chain(Some(0)).collect();
    let mut descriptor=std::ptr::null_mut();
    assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(),1,&mut descriptor,std::ptr::null_mut()) },0);
    let security=Security { length:std::mem::size_of::<Security>() as u32,descriptor,inherit:0 };
    let name:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
    if let Some(bytes)=bytes {
        let handle=unsafe { CreateFileW(name.as_ptr(),0xc0020000,1,&security,1,0x80,std::ptr::null_mut()) };
        assert_ne!(handle as isize,-1);
        let mut file=unsafe { File::from_raw_handle(handle) };
        file.write_all(bytes).unwrap();file.sync_all().unwrap();
    } else { assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(),&security) },0); }
    unsafe { LocalFree(descriptor); }
}

fn call(binary:&Path, args:&[&str])->Output {
    Command::new(binary).args(args).output().unwrap()
}

fn installation()->(tempfile::TempDir,PathBuf) {
    let root=tempfile::tempdir().unwrap();
    let binary=root.path().join("rust-python-healer.exe");
    fs::copy(env!("CARGO_BIN_EXE_rust-python-healer"),&binary).unwrap();
    (root,binary)
}

fn hmac(payload:&[u8], key:u8)->String {
    let mut inner=[0x36_u8;64];let mut outer=[0x5c_u8;64];
    for i in 0..32 {inner[i]^=key;outer[i]^=key;}
    let mut hash=Sha256::new();hash.update(inner);hash.update(payload);
    let inside=hash.finalize();let mut hash=Sha256::new();hash.update(outer);hash.update(inside);
    hex::encode(hash.finalize())
}

fn provision_token(binary:&Path, args:&[&str], nonce:char, bad_signature:bool)->PathBuf {
    let mut draft=args.to_vec();draft.push("--approval-request");
    let output=call(binary,&draft);
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
    let draft:Value=serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(draft["external_human_identity_verified"],false);
    assert_eq!(draft["release_authorized"],false);
    let actor=draft["actor_id"].as_str().unwrap();let sid=actor.strip_prefix("sid:").unwrap();
    let store=binary.parent().unwrap().join(".rph-policy");
    if !store.exists() {
        native_private(&store,sid,None);
        let bytes=serde_json::to_vec(&json!({"schema_version":1,"key_hex":"42".repeat(32)})).unwrap();
        native_private(&store.join("operator-key.json"),sid,Some(&bytes));
    }
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut token=BTreeMap::from([
        ("schema_version",json!(1)),("policy_id",json!("rust-cli-v23")),
        ("nonce",json!(nonce.to_string().repeat(32))),("issued_at",json!(now)),("expires_at",json!(now+60)),
        ("actor_id",json!(actor)),("approver_id",json!("fixture-local-approver")),
        ("action",draft["action"].clone()),("command_sha256",draft["command_sha256"].clone()),
        ("artifact_sha256",draft["artifact_sha256"].clone()),("target_sha256",draft["target_sha256"].clone()),
    ]);
    let signature=if bad_signature {"0".repeat(64)} else {hmac(&serde_json::to_vec(&token).unwrap(),0x42)};
    token.insert("signature",json!(signature));
    let path=store.join(format!("token-{nonce}.json"));
    native_private(&path,sid,Some(&serde_json::to_vec(&token).unwrap()));path
}

#[test]
fn f239_cli_denies_risky_dispatch_without_token_before_any_target_creation() {
    let (root,binary)=installation();let db=root.path().join("missing.sqlite");
    let output=call(&binary,&["catalog","maintain","--db",db.to_str().unwrap()]);
    assert!(!output.status.success());assert!(!db.exists());
    assert!(!root.path().join(".rph-policy").exists());
    let file=root.path().join("source.py");fs::write(&file,b"value=42\n").unwrap();
    let output=call(&binary,&["repair",file.to_str().unwrap(),"--ledger",db.to_str().unwrap()]);
    assert!(!output.status.success());assert!(!db.exists());
    assert_eq!(fs::read(&file).unwrap(),b"value=42\n");
}

#[test]
fn f239_cli_update_watch_has_no_single_use_approval_scope() {
    let (root,binary)=installation();
    let manifest=root.path().join("versions.json");
    let database=root.path().join("knowledge.sqlite");
    let args=["update","--watch","--apply","--manifest",manifest.to_str().unwrap(),"--db",database.to_str().unwrap()];
    let mut request=args.to_vec();request.push("--approval-request");
    let draft=call(&binary,&request);
    assert!(draft.status.success());
    let value:Value=serde_json::from_slice(&draft.stdout).unwrap();
    assert_eq!(value["status"],"HOLD_NO_TYPED_MUTATION_TARGET_SCOPE");
    assert_eq!(value["approval_token_issued"],false);
    assert!(!call(&binary,&args).status.success());
    assert!(!manifest.exists());assert!(!database.exists());
    assert!(!root.path().join(".rph-policy").exists());
}

#[test]
fn f239_cli_artifact_hardlink_is_refused_even_for_approval_draft() {
    let (root,binary)=installation();
    let alias=root.path().join("binary-alias.exe");
    fs::hard_link(&binary,&alias).unwrap();
    let source=root.path().join("fixed.py");fs::write(&source,b"value=42\n").unwrap();
    let ledger=root.path().join("ledger.sqlite");
    let output=call(&binary,&["--approval-request","repair",source.to_str().unwrap(),"--ledger",ledger.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(!ledger.exists());assert!(!source.with_extension("healed.py").exists());
    assert!(!root.path().join(".rph-policy").exists());
}

#[test]
fn f239_cli_real_local_token_allows_exact_catalog_add_and_invalid_signature_denies() {
    let (root,binary)=installation();let db=root.path().join("catalog.sqlite");
    let document=root.path().join("document.txt");fs::write(&document,b"fixed fixture knowledge").unwrap();
    let args=["catalog","add",document.to_str().unwrap(),"--db",db.to_str().unwrap(),
        "--source","fixture","--uri","fixture://one","--title","Fixture","--package","demo","--version","1"];
    let invalid=provision_token(&binary,&args,'a',true);
    let mut invocation=args.to_vec();invocation.extend(["--approval-token",invalid.to_str().unwrap()]);
    let rejected=call(&binary,&invocation);assert!(!rejected.status.success());assert!(!db.exists());
    assert!(!root.path().join(".rph-policy/nonce-ledger.jsonl").exists());
    let valid=provision_token(&binary,&args,'b',false);
    let mut invocation=args.to_vec();invocation.extend(["--approval-token",valid.to_str().unwrap()]);
    let accepted=call(&binary,&invocation);
    assert!(accepted.status.success(),"{}",String::from_utf8_lossy(&accepted.stderr));
    let connection=rusqlite::Connection::open_with_flags(&db,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM documents",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    drop(connection);
    let receipt=fs::read_to_string(root.path().join(".rph-policy/nonce-ledger.jsonl")).unwrap();
    assert_eq!(receipt.lines().count(),1);
    assert!(!call(&binary,&invocation).status.success());
    assert_eq!(fs::read_to_string(root.path().join(".rph-policy/nonce-ledger.jsonl")).unwrap(),receipt);
}

#[test]
fn f239_cli_target_changes_and_arbitrary_key_option_are_denied() {
    let (root,binary)=installation();let db=root.path().join("catalog.sqlite");
    let document=root.path().join("document.txt");fs::write(&document,b"fixed original").unwrap();
    let args=["catalog","add",document.to_str().unwrap(),"--db",db.to_str().unwrap(),
        "--source","fixture","--uri","fixture://one","--title","Fixture","--package","demo","--version","1"];
    let token=provision_token(&binary,&args,'c',false);fs::write(&document,b"changed after approval").unwrap();
    let mut invocation=args.to_vec();invocation.extend(["--approval-token",token.to_str().unwrap()]);
    assert!(!call(&binary,&invocation).status.success());assert!(!db.exists());
    assert!(!call(&binary,&["--approval-key","attacker.json","repair","some.py"]).status.success());
}

#[test]
fn f239_cli_catalog_readonly_never_creates_migrates_or_changes_source_database() {
    let (root,binary)=installation();let missing=root.path().join("missing.sqlite");
    assert!(!call(&binary,&["catalog","stats","--db",missing.to_str().unwrap()]).status.success());
    assert!(!missing.exists());
    let old=root.path().join("v1.sqlite");let connection=rusqlite::Connection::open(&old).unwrap();
    connection.execute_batch(include_str!("../sql/knowledge.sql")).unwrap();
    connection.execute_batch("PRAGMA user_version=1").unwrap();drop(connection);
    let before=fs::read(&old).unwrap();
    let output=call(&binary,&["catalog","stats","--db",old.to_str().unwrap()]);
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
    let report:Value=serde_json::from_slice(&output.stdout).unwrap();assert_eq!(report["schema_version"],1);
    assert_eq!(fs::read(&old).unwrap(),before);
    assert!(!PathBuf::from(format!("{}-wal",old.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm",old.display())).exists());
}

#[test]
fn f239_cli_typed_safe_lab_and_embedded_dependencies_still_work_without_token() {
    let (_root,binary)=installation();
    for tool in ["package-policy","provenance","ast-cst-typing","typecheck-integration","native-serialization","typed-flow",
                 "code-model-router","semantic-retrieval","real-model-router"] {
        let output=call(&binary,&["lab",tool,"--","--mode","capabilities"]);
        assert!(output.status.success(),"{tool}: {}",String::from_utf8_lossy(&output.stderr));
    }
    let status=call(&binary,&["lab","git-review","--","--status"]);
    assert!(status.status.success(),"{}",String::from_utf8_lossy(&status.stderr));
    let report:Value=serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(report["external_github_pr_approved"],false);
    let selftest=call(&binary,&["lab","code-model-router","--","--mode","selftest"]);
    assert!(selftest.status.success(),"{}",String::from_utf8_lossy(&selftest.stderr));
    let report:Value=serde_json::from_slice(&selftest.stdout).unwrap();
    assert_eq!(report["source_code_executed"],false);
    let output=call(&binary,&["lab","resource-meter","--","worker","--iterations","100000","--memory-bytes","1048576"]);
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
    let report:Value=serde_json::from_slice(&output.stdout).unwrap();assert_eq!(report["bound_handle_pid_verified"],true);
    assert!(!call(&binary,&["lab","vector","--","untyped-mutation"]).status.success());
}


#[test]
fn f239_cli_fixed_fixture_readonly_drafts_never_issue_tokens_or_consume_nonces() {
    let (root,binary)=installation();
    let source=root.path().join("fixed-input.json");fs::write(&source,b"{\"fixed\":true}\n").unwrap();
    let before=fs::read(&source).unwrap();
    let input=source.to_str().unwrap();
    let cases=vec![
        vec!["signed-release-policy","--policy",input,"--public-key",input,"--manifest",input,"--signature",input,"--artifact",input],
        vec!["ecosystem-runtime","--mode","web","--target",input],
        vec!["ecosystem-runtime","--mode","orm","--target",input],
        vec!["ecosystem-runtime","--mode","numpy","--target",input],
        vec!["ecosystem-runtime","--mode","pandas","--target",input],
        vec!["native-serialization","--mode","serialization","--target",input],
        vec!["native-serialization","--mode","native","--target",input],
        vec!["adaptive-jobs","--mode","schedule","--input",input],
        vec!["adaptive-jobs","--mode","variants","--input",input],
        vec!["adaptive-jobs","--mode","correlation","--input",input],
        vec!["adaptive-jobs","--mode","live","--input",input,"--python","fixed-operator-runtime.exe"],
        vec!["reliability-bench","--mode","trusted-repeat","--python","fixed-operator-runtime.exe"],
        vec!["reliability-bench","--mode","latency-measure","--python","fixed-operator-runtime.exe","--runs","10"],
    ];
    for fixture in cases {
        let mut arguments=vec!["--approval-request","lab",fixture[0],"--python","fixed-operator-runtime.exe","--"];
        arguments.extend_from_slice(&fixture[1..]);
        let draft=call(&binary,&arguments);
        assert!(draft.status.success(),"{fixture:?}: {}",String::from_utf8_lossy(&draft.stderr));
        let result:Value=serde_json::from_slice(&draft.stdout).unwrap();
        assert_eq!(result["status"],"READ_ONLY_TYPED_COMMAND");
        assert_eq!(result["mutation_performed"],false);
        assert!(result.get("approval_token_issued").is_none());
        assert!(result.get("target_sha256").is_none());
        assert_eq!(fs::read(&source).unwrap(),before);
        assert!(!root.path().join(".rph-policy").exists());
    }
    // Even a supplied token is rejected for a typed read-only route, before
    // the token path or any adapter input is opened. This is not a token bypass.
    let token=root.path().join("never-consumed-token.json");
    let token_bytes=b"fixed-untrusted-token-bytes-not-an-approval";
    fs::write(&token,token_bytes).unwrap();
    let result=call(&binary,&["--approval-token",token.to_str().unwrap(),"lab","ecosystem-runtime","--","--mode","web","--target",input]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("policy_dispatch_refused_target_not_dispatched"));
    assert_eq!(fs::read(&token).unwrap(),token_bytes);
    assert_eq!(fs::read(&source).unwrap(),before);
    assert!(!root.path().join(".rph-policy").exists());
}

#[test]
fn f239_cli_fixed_fixture_mutating_or_unknown_options_remain_hold_without_scope() {
    let (root,binary)=installation();let output=root.path().join("never-created.sqlite");
    let target=output.to_str().unwrap();
    let cases=vec![
        vec!["signed-release-policy","--policy",target,"--public-key",target,"--manifest",target,"--signature",target,"--artifact",target,"--record-ledger",target],
        vec!["signed-release-policy","--policy",target,"--public-key",target,"--manifest",target,"--signature",target,"--artifact",target,"--record-ledger=forbidden.sqlite"],
        vec!["ecosystem-runtime","--mode","web","--target",target,"--json",target],
        vec!["ecosystem-runtime","--mode","install","--target",target],
        vec!["native-serialization","--mode","native","--target",target,"--install"],
        vec!["adaptive-jobs","--mode","schedule","--input",target,"--python",target],
        vec!["adaptive-jobs","--mode","live","--input",target,"--python",target],
        vec!["reliability-bench","--mode","trusted-repeat","--python",target],
        vec!["reliability-bench","--mode","trusted-repeat","--python","fixed-operator-runtime.exe","--runs","11"],
        vec!["reliability-bench","--mode","latency-measure","--python","fixed-operator-runtime.exe","--latency-profile","p95-regression"],
        vec!["reliability-bench","--mode","repair-pipeline","--python",target,"--binary",target,"--ruff",target],
    ];
    for fixture in cases {
        let mut arguments=vec!["--approval-request","lab",fixture[0],"--python","fixed-operator-runtime.exe","--"];
        arguments.extend_from_slice(&fixture[1..]);
        let draft=call(&binary,&arguments);
        assert!(draft.status.success(),"{fixture:?}: {}",String::from_utf8_lossy(&draft.stderr));
        let result:Value=serde_json::from_slice(&draft.stdout).unwrap();
        assert_eq!(result["status"],"HOLD_NO_TYPED_MUTATION_TARGET_SCOPE");
        assert_eq!(result["approval_token_issued"],false);
        assert_eq!(result["mutation_performed"],false);
        let arguments=&arguments[1..];
        let rejected=call(&binary,arguments);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("policy_dispatch_refused_target_not_dispatched"));
        assert!(!output.exists());assert!(!root.path().join(".rph-policy").exists());
    }
}
