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
    assert_eq!(draft["external_human_identity_verified"],false, "args={args:?} draft={draft}");
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

// Each invocation owns its installation and private approval store. Only the
// exact typed draft is signed; no production key or policy bypass is used.
pub fn approved_call(args: &[&str]) -> Output {
    let (_installation, binary) = installation();
    let token = provision_token(&binary, args, 'a', false);
    let mut invocation = args.to_vec();
    invocation.extend(["--approval-token", token.to_str().unwrap()]);
    call(&binary, &invocation)
}

// Deterministic interleaving: a real write after signing must invalidate the
// approved target. Callers may then request one fresh approval explicitly.
pub fn approved_call_after_change(args: &[&str], change: impl FnOnce()) -> Output {
    let (_installation, binary) = installation();
    let token = provision_token(&binary, args, 'b', false);
    change();
    let mut invocation = args.to_vec();
    invocation.extend(["--approval-token", token.to_str().unwrap()]);
    let output = call(&binary, &invocation);
    assert!(!output.status.success(), "a stale target approval must never dispatch");
    assert!(!binary.parent().unwrap().join(".rph-policy/nonce-ledger.jsonl").exists(),
        "a mismatching target must fail before consuming its nonce");
    output
}
