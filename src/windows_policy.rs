//! Native local-policy storage. No external human identity or publisher claim.
//! Pins every directory HANDLE without delete sharing, rejects reparse leaves,
//! checks current-user ownership/protected DACL, and serializes one ledger file.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::time::{Duration, Instant};

type Handle = *mut c_void;
const READ_CONTROL: u32 = 0x0002_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_REPARSE: u32 = 0x0020_0000;
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
const WRITE_THROUGH: u32 = 0x8000_0000;
const REPARSE_ATTRIBUTE: u32 = 0x0400;
const DIRECTORY_ATTRIBUTE: u32 = 0x0010;
const MAX_LEDGER: u64 = 2_000_000;
const MAX_EVENTS: usize = 10_000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileInfo {
    attributes: u32,
    creation: [u32; 2],
    accessed: [u32; 2],
    written: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

#[repr(C)]
#[derive(Default)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: Handle,
}

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: Handle,
    inherit: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Acl {
    revision: u8,
    reserved: u8,
    size: u16,
    count: u16,
    reserved2: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(path: *const u16, access: u32, share: u32, security: *const SecurityAttributes,
                   disposition: u32, flags: u32, template: Handle) -> Handle;
    fn CreateDirectoryW(path: *const u16, security: *const SecurityAttributes) -> i32;
    fn GetFileInformationByHandle(file: Handle, info: *mut FileInfo) -> i32;
    fn GetFileType(file: Handle) -> u32;
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: Handle) -> Handle;
    fn LockFileEx(file: Handle, flags: u32, reserved: u32, low: u32, high: u32,
                  overlapped: *mut Overlapped) -> i32;
    fn UnlockFileEx(file: Handle, reserved: u32, low: u32, high: u32,
                    overlapped: *mut Overlapped) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(token: Handle, class: u32, data: Handle, size: u32,
                           required: *mut u32) -> i32;
    fn GetLengthSid(sid: Handle) -> u32;
    fn IsValidSid(sid: Handle) -> i32;
    fn EqualSid(left: Handle, right: Handle) -> i32;
    fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16, revision: u32, descriptor: *mut Handle, size: *mut u32) -> i32;
    fn GetSecurityInfo(file: Handle, kind: u32, info: u32, owner: *mut Handle,
                       group: *mut Handle, dacl: *mut Handle, sacl: *mut Handle,
                       descriptor: *mut Handle) -> u32;
    fn GetSecurityDescriptorControl(descriptor: Handle, control: *mut u16, revision: *mut u32) -> i32;
    fn GetAce(acl: Handle, index: u32, ace: *mut Handle) -> i32;
}

struct LocalMemory(Handle);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() { unsafe { LocalFree(self.0); } }
    }
}

fn current_sid() -> Result<Vec<u8>> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token) } == 0 {
        bail!("policy_current_token_unavailable");
    }
    let result = (|| {
        let mut size = 0;
        unsafe { GetTokenInformation(token, 1, std::ptr::null_mut(), 0, &mut size); }
        if !(8..=8_192).contains(&size) { bail!("policy_token_size_invalid"); }
        let mut data = vec![0_u8; size as usize];
        if unsafe { GetTokenInformation(token, 1, data.as_mut_ptr().cast(), size, &mut size) } == 0 {
            bail!("policy_token_user_unavailable");
        }
        let sid = unsafe { data.as_ptr().cast::<Handle>().read_unaligned() };
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 { bail!("policy_user_sid_invalid"); }
        let length = unsafe { GetLengthSid(sid) } as usize;
        if !(8..=68).contains(&length) { bail!("policy_user_sid_size_invalid"); }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
    })();
    unsafe { CloseHandle(token); }
    result
}

pub(crate) fn actor_id() -> Result<String> {
    let sid = current_sid()?;
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut text) } == 0 {
        bail!("policy_actor_sid_unavailable");
    }
    let _memory = LocalMemory(text.cast());
    let length = (0..=184).find(|i| unsafe { *text.add(*i) } == 0)
        .context("policy_actor_sid_over_budget")?;
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })?;
    Ok(format!("sid:{value}"))
}

fn wide(path: &Path) -> Result<Vec<u16>> {
    let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
    if text.is_empty() || text.len() > 32_000 || text.contains(&0) {
        bail!("policy_native_path_invalid");
    }
    text.push(0);
    Ok(text)
}

fn info(file: &File) -> Result<FileInfo> {
    let mut result = FileInfo::default();
    if unsafe { GetFileType(file.as_raw_handle()) } != 1
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut result) } == 0
    { bail!("policy_native_file_information_failed"); }
    Ok(result)
}

fn identity(info: &FileInfo) -> (u32, u32, u32) {
    (info.volume, info.index_high, info.index_low)
}

fn size(info: &FileInfo) -> u64 {
    (u64::from(info.size_high) << 32) | u64::from(info.size_low)
}

fn private_acl(file: &File) -> Result<()> {
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let code = unsafe { GetSecurityInfo(file.as_raw_handle(), 1, 0x0000_0005,
        &mut owner, std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut descriptor) };
    if code != 0 { bail!("policy_native_owner_dacl_unavailable"); }
    let _memory = LocalMemory(descriptor);
    let sid = current_sid()?;
    if owner.is_null() || dacl.is_null()
        || unsafe { EqualSid(owner, sid.as_ptr().cast_mut().cast()) } == 0
    { bail!("policy_file_owner_not_current_user_or_null_dacl"); }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & 0x1000 == 0
    { bail!("policy_dacl_must_be_protected"); }
    let acl = unsafe { dacl.cast::<Acl>().read_unaligned() };
    if acl.count == 0 || acl.count > 32 || acl.size < 8 { bail!("policy_dacl_budget_or_empty"); }
    let mut own_allow = false;
    for index in 0..u32::from(acl.count) {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            bail!("policy_dacl_ace_unavailable");
        }
        let header = unsafe { ace.cast::<AceHeader>().read_unaligned() };
        // Strict installation profile: owner-only allowed ACEs. No inherited,
        // callback/object/group/unknown principals can grant access.
        if header.kind != 0 || header.flags & 0x10 != 0 || header.size < 16 {
            bail!("policy_dacl_unsupported_ace");
        }
        let ace_sid = unsafe { ace.cast::<u8>().add(8) }.cast::<c_void>();
        if unsafe { IsValidSid(ace_sid) } == 0
            || unsafe { GetLengthSid(ace_sid) } > u32::from(header.size - 8)
            || unsafe { EqualSid(ace_sid, sid.as_ptr().cast_mut().cast()) } == 0
        { bail!("policy_dacl_grants_non_owner"); }
        own_allow = true;
    }
    if !own_allow { bail!("policy_owner_allow_missing"); }
    Ok(())
}

fn open_native(path: &Path, access: u32, share: u32, disposition: u32,
               flags: u32, security: *const SecurityAttributes) -> Result<File> {
    let name = wide(path)?;
    let handle = unsafe { CreateFileW(name.as_ptr(), access, share, security, disposition,
                                     flags | OPEN_REPARSE, std::ptr::null_mut()) };
    if handle.is_null() || handle as isize == -1 { bail!("policy_native_open_refused"); }
    // Ownership of exactly this non-inheritable HANDLE transfers to File.
    Ok(unsafe { File::from_raw_handle(handle) })
}

struct DirectoryPins { files: Vec<File> }

fn pin_parents(path: &Path, require_private_parent: bool) -> Result<DirectoryPins> {
    let parent = path.parent().context("policy_parent_missing")?;
    let mut components = parent.components();
    let prefix = components.next().context("policy_absolute_local_path_required")?;
    if !matches!(prefix, Component::Prefix(p) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || !matches!(components.next(), Some(Component::RootDir))
    { bail!("policy_absolute_local_drive_required"); }
    let mut current = PathBuf::from(prefix.as_os_str());
    current.push("\\");
    let mut paths = vec![current.clone()];
    for part in components {
        let Component::Normal(name) = part else { bail!("policy_relative_parent_refused"); };
        let letters: Vec<u16> = name.encode_wide().collect();
        if letters.contains(&(b':' as u16)) || matches!(letters.last(), Some(32 | 46)) {
            bail!("policy_parent_stream_or_alias_refused");
        }
        current.push(name);
        paths.push(current.clone());
    }
    let mut files = Vec::new();
    for directory in paths {
        let file = open_native(&directory, READ_CONTROL | 0x80, 3, 3,
                               BACKUP_SEMANTICS, std::ptr::null())?;
        let metadata = info(&file)?;
        if metadata.attributes & REPARSE_ATTRIBUTE != 0
            || metadata.attributes & DIRECTORY_ATTRIBUTE == 0
        { bail!("policy_parent_reparse_or_not_directory"); }
        files.push(file);
    }
    if require_private_parent { private_acl(files.last().context("policy_parent_missing")?)?; }
    Ok(DirectoryPins { files })
}

fn private_descriptor() -> Result<LocalMemory> {
    let actor = actor_id()?;
    let sid = actor.strip_prefix("sid:").context("policy_sid_invalid")?;
    let sddl = format!("O:{sid}D:P(A;OICI;FA;;;{sid})");
    descriptor_from_sddl(&sddl)
}

fn descriptor_from_sddl(sddl: &str) -> Result<LocalMemory> {
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) } == 0
    { bail!("policy_private_descriptor_failed"); }
    Ok(LocalMemory(descriptor))
}

pub(crate) struct CheckedFile {
    file: File,
    _parents: DirectoryPins,
    first: FileInfo,
    private: bool,
}

impl CheckedFile {
    fn validate(&self, budget: u64) -> Result<FileInfo> {
        let current = info(&self.file)?;
        if current.attributes & (REPARSE_ATTRIBUTE | DIRECTORY_ATTRIBUTE) != 0
            || current.links != 1 || size(&current) > budget
            || identity(&current) != identity(&self.first)
        { bail!("policy_leaf_reparse_hardlink_identity_or_budget"); }
        if self.private { private_acl(&self.file)?; }
        Ok(current)
    }

    pub(crate) fn read_bounded(&mut self, budget: u64) -> Result<Vec<u8>> {
        let before = self.validate(budget)?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut data = Vec::new();
        (&mut self.file).take(budget + 1).read_to_end(&mut data)?;
        let after = self.validate(budget)?;
        if data.len() as u64 != size(&before) || size(&after) != size(&before)
            || before.written != after.written || data.len() as u64 > budget
        { bail!("policy_leaf_changed_during_read"); }
        Ok(data)
    }
}

pub(crate) fn open_readonly(path: &Path, private: bool, budget: u64) -> Result<CheckedFile> {
    validate_leaf_path(path)?;
    let parents = pin_parents(path, private)?;
    let file = open_native(path, GENERIC_READ | READ_CONTROL, 1, 3, 0, std::ptr::null())?;
    let first = info(&file)?;
    let result = CheckedFile { file, _parents: parents, first, private };
    result.validate(budget)?;
    Ok(result)
}

fn validate_leaf_path(path: &Path) -> Result<()> {
    let name = path.file_name().context("policy_file_leaf_missing")?;
    let text: Vec<u16> = name.encode_wide().collect();
    if text.is_empty() || text.contains(&(b':' as u16))
        || matches!(text.last(), Some(32 | 46))
    { bail!("policy_file_leaf_alias_or_stream_refused"); }
    Ok(())
}

struct LockedLedger { inner: CheckedFile, overlapped: Box<Overlapped> }
impl Drop for LockedLedger {
    fn drop(&mut self) {
        unsafe { UnlockFileEx(self.inner.file.as_raw_handle(), 0, u32::MAX, u32::MAX,
                              &mut *self.overlapped); }
    }
}

fn open_locked_ledger(path: &Path) -> Result<LockedLedger> {
    validate_leaf_path(path)?;
    let parents = pin_parents(path, true)?;
    let descriptor = private_descriptor()?;
    let security = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: descriptor.0, inherit: 0 };
    let file = open_native(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 3, 4,
                           WRITE_THROUGH, &security)?;
    let first = info(&file)?;
    let inner = CheckedFile { file, _parents: parents, first, private: true };
    inner.validate(MAX_LEDGER)?;
    let mut overlapped = Box::<Overlapped>::default();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if unsafe { LockFileEx(inner.file.as_raw_handle(), 3, 0, u32::MAX, u32::MAX,
                               &mut *overlapped) } != 0 { break; }
        let error = std::io::Error::last_os_error().raw_os_error();
        if error != Some(33) || Instant::now() >= deadline { bail!("policy_ledger_lock_refused_or_timeout"); }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(LockedLedger { inner, overlapped })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerRow { nonce: String, intent_sha256: String, previous: String, event_sha256: String }

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn consume_nonce(path: &Path, nonce: &str, digest: &str, expires: u64,
                           now: u64, key: &[u8]) -> Result<Value> {
    let start = Instant::now();
    if now >= expires || key.len() != 32 || !lower_hex(nonce, 32) || !lower_hex(digest, 64) {
        bail!("policy_intent_cannot_be_consumed");
    }
    let mut locked = open_locked_ledger(path)?;
    if now.saturating_add(start.elapsed().as_secs()) >= expires { bail!("policy_intent_expired_while_waiting"); }
    let bytes = locked.inner.read_bounded(MAX_LEDGER)?;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") { bail!("policy_ledger_partial_write"); }
    let mut previous = "0".repeat(64);
    let mut count = 0;
    for line in bytes.split(|b| *b == b'\n').filter(|row| !row.is_empty()) {
        count += 1;
        if count > MAX_EVENTS { bail!("policy_ledger_event_budget"); }
        let row: LedgerRow = serde_json::from_slice(line).context("policy_ledger_row_invalid")?;
        if !lower_hex(&row.nonce, 32) || !lower_hex(&row.intent_sha256, 64)
            || row.previous != previous || !lower_hex(&row.event_sha256, 64)
        { bail!("policy_ledger_row_invalid"); }
        let unsigned = BTreeMap::from([
            ("nonce", json!(row.nonce)), ("intent_sha256", json!(row.intent_sha256)),
            ("previous", json!(row.previous)),
        ]);
        let expected = hex::encode(crate::policy_boundary_v23::hmac_sha256(key, &serde_json::to_vec(&unsigned)?));
        if !crate::policy_boundary_v23::constant_time_eq(expected.as_bytes(), row.event_sha256.as_bytes()) {
            bail!("policy_ledger_authentication_invalid");
        }
        if row.nonce == nonce { bail!("policy_approval_nonce_replay"); }
        previous = row.event_sha256;
    }
    if count >= MAX_EVENTS { bail!("policy_ledger_event_budget"); }
    let mut row = BTreeMap::from([("nonce", json!(nonce)), ("intent_sha256", json!(digest)),
                                 ("previous", json!(previous))]);
    let mac = hex::encode(crate::policy_boundary_v23::hmac_sha256(key, &serde_json::to_vec(&row)?));
    row.insert("event_sha256", json!(mac));
    let mut next = serde_json::to_vec(&row)?;
    next.push(b'\n');
    if bytes.len() as u64 + next.len() as u64 > MAX_LEDGER { bail!("policy_ledger_event_budget"); }
    if now.saturating_add(start.elapsed().as_secs()) >= expires {
        bail!("policy_intent_expired_before_commit");
    }
    let before = locked.inner.validate(MAX_LEDGER)?;
    if size(&before) != bytes.len() as u64 { bail!("policy_ledger_changed_under_lock"); }
    locked.inner.file.seek(SeekFrom::End(0))?;
    locked.inner.file.write_all(&next)?;
    locked.inner.file.sync_all()?;
    let after = locked.inner.validate(MAX_LEDGER)?;
    if size(&after) != bytes.len() as u64 + next.len() as u64 { bail!("policy_ledger_append_size_mismatch"); }
    Ok(json!({"status":"LOCAL_APPROVAL_INTENT_CONSUMED_NO_MUTATION",
        "intent_sha256":digest,"nonce_consumed":true,"mutation_performed":false,
        "release_authorized":false,"external_human_identity_verified":false,
        "ledger_authentication":"LOCAL_OPERATOR_HMAC_SHA256_CHAIN",
        "independent_rollback_checkpoint_verified":false}))
}

#[cfg(test)]
pub(crate) fn test_private_directory(path: &Path) -> Result<()> {
    let descriptor = private_descriptor()?;
    let security = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: descriptor.0, inherit: 0 };
    if unsafe { CreateDirectoryW(wide(path)?.as_ptr(), &security) } == 0 {
        bail!("test_private_directory_create_failed");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let descriptor = private_descriptor()?;
    let security = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: descriptor.0, inherit: 0 };
    let mut file = open_native(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 1, 1, 0, &security)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_boundary_v23::{self as policy, ExpectedIntent, VerifiedIntent};
    use std::process::Command;

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    fn intent(nonce: &str, issued: u64, expires: u64) -> VerifiedIntent {
        let mut fields = BTreeMap::from([
            ("schema_version", json!(1)), ("policy_id", json!("rust-cli-v23")),
            ("nonce", json!(nonce)), ("issued_at", json!(issued)), ("expires_at", json!(expires)),
            ("actor_id", json!("requester")), ("approver_id", json!("fixture-local-approver")),
            ("action", json!("SOURCE_MODIFY")), ("command_sha256", json!("1".repeat(64))),
            ("artifact_sha256", json!("2".repeat(64))), ("target_sha256", json!("3".repeat(64))),
        ]);
        let signature = hex::encode(policy::hmac_sha256(&[0x6b; 32], &serde_json::to_vec(&fields).unwrap()));
        fields.insert("signature", json!(signature));
        policy::verify_intent(&serde_json::to_vec(&fields).unwrap(),
            br#"{"schema_version":1,"key_hex":"6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"}"#,
            &ExpectedIntent { actor_id: "requester", action: "SOURCE_MODIFY",
                command_sha256: &"1".repeat(64), artifact_sha256: &"2".repeat(64),
                target_sha256: &"3".repeat(64) }, issued).unwrap()
    }

    fn private_root() -> (tempfile::TempDir, PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("owner-private");
        test_private_directory(&root).unwrap();
        (temporary, root)
    }

    #[test]
    fn windows_policy_real_owner_dacl_read_and_parent_rename_pin() {
        let (_temporary, root) = private_root();
        let path = root.join("operator-key.json");
        test_private_file(&path, b"private-fixture").unwrap();
        let mut opened = open_readonly(&path, true, 64).unwrap();
        assert_eq!(opened.read_bounded(64).unwrap(), b"private-fixture");
        assert!(std::fs::rename(&root, root.with_file_name("renamed")).is_err());
        drop(opened);
        std::fs::rename(&root, root.with_file_name("renamed")).unwrap();
    }

    #[test]
    fn windows_policy_nonce_is_durable_one_use_and_key_debug_is_redacted() {
        let (_temporary, root) = private_root();
        let ledger = root.join("nonce.jsonl");
        let time = now();
        let approved = intent(&"a".repeat(32), time, time + 60);
        assert!(!format!("{approved:?}").contains(&"6b".repeat(32)));
        let receipt = policy::consume_nonce(&ledger, &approved, time).unwrap();
        assert_eq!(receipt["nonce_consumed"], true);
        assert_eq!(receipt["external_human_identity_verified"], false);
        assert_eq!(receipt["release_authorized"], false);
        let bytes = std::fs::read(&ledger).unwrap();
        assert!(bytes.ends_with(b"\n"));
        assert!(policy::consume_nonce(&ledger, &approved, time).unwrap_err().to_string().contains("nonce_replay"));
        assert_eq!(std::fs::read(&ledger).unwrap(), bytes);
    }

    #[test]
    fn windows_policy_nonce_detects_tamper_partial_write_and_expiry_without_append() {
        let (_temporary, root) = private_root();
        let ledger = root.join("nonce.jsonl");
        let time = now();
        let approved = intent(&"a".repeat(32), time, time + 60);
        policy::consume_nonce(&ledger, &approved, time).unwrap();
        let original = std::fs::read(&ledger).unwrap();
        let mut row: serde_json::Value = serde_json::from_slice(&original).unwrap();
        row["intent_sha256"] = json!("e".repeat(64));
        let mut changed = serde_json::to_vec(&row).unwrap();
        changed.push(b'\n');
        std::fs::write(&ledger, &changed).unwrap();
        let second = intent(&"b".repeat(32), time, time + 60);
        assert_eq!(policy::consume_nonce(&ledger, &second, time).unwrap_err().to_string(), "policy_ledger_authentication_invalid");
        assert_eq!(std::fs::read(&ledger).unwrap(), changed);
        std::fs::write(&ledger, &original[..original.len() - 1]).unwrap();
        assert!(policy::consume_nonce(&ledger, &second, time).is_err());
        let absent = root.join("expired.jsonl");
        assert!(policy::consume_nonce(&absent, &approved, time + 60).is_err());
        assert!(!absent.exists());
    }

    #[test]
    fn windows_policy_real_broad_dacl_hardlink_reparse_and_stream_refused() {
        let (_temporary, root) = private_root();
        let path = root.join("broad.json");
        let sid = actor_id().unwrap().trim_start_matches("sid:").to_owned();
        let descriptor = descriptor_from_sddl(&format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FR;;;WD)")).unwrap();
        let security = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.0, inherit: 0 };
        let mut file = open_native(&path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 1, 1, 0, &security).unwrap();
        file.write_all(b"broad fixture").unwrap();
        drop(file);
        assert!(open_readonly(&path, true, 100).is_err());
        let private = root.join("private.json");
        test_private_file(&private, b"private fixture").unwrap();
        let hardlink = root.join("hardlink.json");
        std::fs::hard_link(&private, &hardlink).unwrap();
        assert!(open_readonly(&private, true, 100).is_err());
        let symlink = root.join("alias.json");
        std::os::windows::fs::symlink_file(&private, &symlink).unwrap();
        assert!(open_readonly(&symlink, true, 100).is_err());
        assert!(open_readonly(&root.join("private.json:stream"), true, 100).is_err());
        let directory_alias = root.with_file_name("directory-alias");
        std::os::windows::fs::symlink_dir(&root, &directory_alias).unwrap();
        assert!(open_readonly(&directory_alias.join("private.json"), true, 100).is_err());
    }

    #[test]
    fn windows_policy_bounded_lock_wait_and_ledger_budget() {
        let (_temporary, root) = private_root();
        let ledger = root.join("busy.jsonl");
        let locked = open_locked_ledger(&ledger).unwrap();
        let time = now();
        let start = Instant::now();
        assert!(consume_nonce(&ledger, &"a".repeat(32), &"1".repeat(64), time + 60, time, &[0x6b; 32]).is_err());
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert!(start.elapsed() < Duration::from_secs(4));
        drop(locked);
        let oversized = root.join("oversized.jsonl");
        test_private_file(&oversized, &[]).unwrap();
        std::fs::OpenOptions::new().write(true).open(&oversized).unwrap().set_len(MAX_LEDGER + 1).unwrap();
        assert!(consume_nonce(&oversized, &"a".repeat(32), &"1".repeat(64), time + 60, time, &[0x6b; 32]).is_err());
        assert_eq!(std::fs::metadata(&oversized).unwrap().len(), MAX_LEDGER + 1);
    }

    #[test]
    #[ignore = "owned subprocess fixture, invoked explicitly by cross-process test"]
    fn native_nonce_worker() {
        let ledger = PathBuf::from(std::env::var_os("RPH_TEST_NONCE_LEDGER").unwrap());
        let result = PathBuf::from(std::env::var_os("RPH_TEST_NONCE_RESULT").unwrap());
        let nonce = std::env::var("RPH_TEST_NONCE_VALUE").unwrap();
        let time = now();
        let approved = intent(&nonce, time, time + 60);
        let outcome = match policy::consume_nonce(&ledger, &approved, time) {
            Ok(_) => "consumed",
            Err(error) if error.to_string().contains("nonce_replay") => "replay",
            Err(error) => panic!("unexpected fixed-fixture failure: {error}"),
        };
        std::fs::write(result, outcome).unwrap();
    }

    #[test]
    fn windows_policy_real_cross_process_replay_and_distinct_append_serialization() {
        let (_temporary, root) = private_root();
        let ledger = root.join("concurrent.jsonl");
        for distinct in [false, true] {
            let mut processes = Vec::new();
            for index in 0..8 {
                let nonce = if distinct { format!("{index:032x}") } else { "f".repeat(32) };
                let output = root.join(format!("result-{distinct}-{index}"));
                let child = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "windows_policy::tests::native_nonce_worker", "--ignored", "--nocapture"])
                    .env("RPH_TEST_NONCE_LEDGER", &ledger).env("RPH_TEST_NONCE_RESULT", &output)
                    .env("RPH_TEST_NONCE_VALUE", nonce).spawn().unwrap();
                processes.push((child, output));
            }
            let mut consumed = 0;
            for (mut process, output) in processes {
                assert!(process.wait().unwrap().success());
                if std::fs::read_to_string(output).unwrap() == "consumed" { consumed += 1; }
            }
            assert_eq!(consumed, if distinct { 8 } else { 1 });
        }
        assert_eq!(std::fs::read_to_string(ledger).unwrap().lines().count(), 9);
    }
}
