//! Fail-closed policy primitives to integrate before every mutating CLI action.
//!
//! IMPORTANT: compiling this module is NOT global enforcement.  The main
//! command dispatcher must invoke `classify_cli`, require an approval when it
//! says so, call `verify_intent` + `consume_nonce` BEFORE mutation, and recheck
//! the exact target/artefact SHA at mutation time.  Every stdout/stderr sink
//! must explicitly route through `redact_event`.  Until then F207/F239 PARTIAL.

#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const MAX_CLI_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4_096;
const MAX_LOG_BYTES: usize = 1_000_000;
const MAX_TOKEN_BYTES: usize = 32_768;
const MAX_LEDGER_BYTES: u64 = 2_000_000;
const MAX_LEDGER_EVENTS: usize = 10_000;
const TOKEN_VALIDITY_SECS: u64 = 300;
const CLOCK_SKEW_SECS: u64 = 30;
const TOP_LEVEL: [&str; 21] = [
    "dap",
    "version-regression",
    "qualify",
    "property",
    "static",
    "lab",
    "runtime",
    "check",
    "trace",
    "deps",
    "record",
    "project",
    "flaky",
    "ast",
    "sbom",
    "scan",
    "matrix",
    "update",
    "repair",
    "catalog",
    "bench",
];
const CATALOG_MUTATIONS: [&str; 5] = ["add", "import-installed", "maintain", "backup", "restore"];
const CATALOG_READ_ONLY: [&str; 2] = ["search", "stats"];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Permission {
    ReadOnly,
    RequireApproval,
    DenyUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Classification {
    pub permission: Permission,
    pub command: String,
    pub risky_action: Option<String>,
    pub execution_performed: bool,
    pub global_enforcement_proven: bool,
}

fn classified(permission: Permission, command: &str, action: Option<&str>) -> Classification {
    Classification {
        permission,
        command: command.to_string(),
        risky_action: action.map(str::to_string),
        execution_performed: false,
        global_enforcement_proven: false,
    }
}

pub fn classify_cli(argv: &[&str]) -> Classification {
    if argv.is_empty()
        || argv.len() > MAX_CLI_ARGS
        || argv
            .iter()
            .any(|arg| arg.len() > MAX_ARG_BYTES || arg.contains('\0'))
    {
        return classified(Permission::DenyUnknown, "unclassified", None);
    }
    let command = argv[0];
    if !TOP_LEVEL.contains(&command) {
        return classified(Permission::DenyUnknown, "unclassified", None);
    }
    // Only unambiguous clap help invocations are harmless.  Do not let a
    // malicious value of a later --option bypass the pre-dispatch gate.
    let help_only = matches!(argv, [_, "--help"] | [_, "-h"])
        || matches!(argv, ["catalog", _, "--help"] | ["catalog", _, "-h"])
        || matches!(argv, ["lab", _, "--help"] | ["lab", _, "-h"]);
    if help_only {
        return classified(Permission::ReadOnly, command, None);
    }
    match command {
        "repair" => classified(Permission::RequireApproval, command, Some("SOURCE_MODIFY")),
        "update" => classified(
            Permission::RequireApproval,
            command,
            Some("KNOWLEDGE_UPDATE"),
        ),
        "lab" => classified(Permission::RequireApproval, command, Some("LAB_MUTATION")),
        "catalog" => match argv.get(1).copied() {
            Some(subcommand) if CATALOG_MUTATIONS.contains(&subcommand) => classified(
                Permission::RequireApproval,
                command,
                Some("CATALOG_MUTATION"),
            ),
            Some(subcommand) if CATALOG_READ_ONLY.contains(&subcommand) => {
                classified(Permission::ReadOnly, command, None)
            }
            _ => classified(Permission::DenyUnknown, command, None),
        },
        _ => classified(Permission::ReadOnly, command, None),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

pub fn command_sha256(argv: &[&str]) -> Result<String> {
    if argv.is_empty()
        || argv.len() > MAX_CLI_ARGS
        || argv
            .iter()
            .any(|arg| arg.len() > MAX_ARG_BYTES || arg.contains('\0'))
    {
        bail!("policy_invalid_cli_arguments");
    }
    Ok(sha256_hex(&serde_json::to_vec(argv)?))
}

fn lowercase_hex(value: &str, chars: usize) -> bool {
    value.len() == chars
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_actor(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'@' | b'-'))
        })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntentToken {
    pub schema_version: u64,
    pub policy_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub actor_id: String,
    pub approver_id: String,
    pub action: String,
    pub command_sha256: String,
    pub artifact_sha256: String,
    pub target_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorKey {
    pub schema_version: u64,
    pub key_hex: String,
}

#[derive(Clone, Debug)]
pub struct ExpectedIntent<'a> {
    pub actor_id: &'a str,
    pub action: &'a str,
    pub command_sha256: &'a str,
    pub artifact_sha256: &'a str,
    pub target_sha256: &'a str,
}

#[derive(Clone, Debug)]
pub struct VerifiedIntent {
    nonce: String,
    intent_sha256: String,
    expires_at: u64,
    action: String,
    external_identity_verified: bool,
    nonce_consumed: bool,
    release_authorized: bool,
    #[cfg(windows)]
    ledger_key: LocalLedgerKey,
}

pub(crate) fn recheck_intent_time(intent: &VerifiedIntent, now_seconds: u64) -> Result<()> {
    if now_seconds >= intent.expires_at { bail!("policy_intent_expired_before_dispatch"); }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone)]
struct LocalLedgerKey([u8; 32]);

#[cfg(windows)]
impl std::fmt::Debug for LocalLedgerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalLedgerKey([REDACTED])")
    }
}

fn unsigned_token_canonical(token: &IntentToken) -> Result<Vec<u8>> {
    let mut fields = BTreeMap::new();
    fields.insert("schema_version", json!(token.schema_version));
    fields.insert("policy_id", json!(token.policy_id));
    fields.insert("nonce", json!(token.nonce));
    fields.insert("issued_at", json!(token.issued_at));
    fields.insert("expires_at", json!(token.expires_at));
    fields.insert("actor_id", json!(token.actor_id));
    fields.insert("approver_id", json!(token.approver_id));
    fields.insert("action", json!(token.action));
    fields.insert("command_sha256", json!(token.command_sha256));
    fields.insert("artifact_sha256", json!(token.artifact_sha256));
    fields.insert("target_sha256", json!(token.target_sha256));
    serde_json::to_vec(&fields).context("policy_canonical_token_invalid")
}

pub(crate) fn hmac_sha256(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0_u8; 64];
    let mut outer = [0_u8; 64];
    for index in 0..64 {
        inner[index] = block[index] ^ 0x36;
        outer[index] = block[index] ^ 0x5c;
    }
    let mut first = Sha256::new();
    first.update(inner);
    first.update(payload);
    let inner_hash = first.finalize();
    let mut second = Sha256::new();
    second.update(outer);
    second.update(inner_hash);
    let result = second.finalize();
    let mut signature = [0_u8; 32];
    signature.copy_from_slice(&result);
    signature
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for (a, b) in left.iter().zip(right) {
        diff |= usize::from(*a ^ *b);
    }
    diff == 0
}

pub fn verify_intent(
    raw_token: &[u8],
    raw_key: &[u8],
    expected: &ExpectedIntent<'_>,
    now_seconds: u64,
) -> Result<VerifiedIntent> {
    if raw_token.len() > MAX_TOKEN_BYTES || raw_key.len() > 1_024 {
        bail!("policy_approval_input_budget");
    }
    let token: IntentToken =
        serde_json::from_slice(raw_token).context("policy_approval_token_invalid")?;
    let key: OperatorKey =
        serde_json::from_slice(raw_key).context("policy_approval_key_invalid")?;
    if key.schema_version != 1
        || !lowercase_hex(&key.key_hex, 64)
        || token.schema_version != 1
        || token.policy_id != "rust-cli-v23"
        || !lowercase_hex(&token.nonce, 32)
        || !valid_actor(&token.actor_id)
        || !valid_actor(&token.approver_id)
        || token.actor_id == token.approver_id
        || !lowercase_hex(&token.command_sha256, 64)
        || !lowercase_hex(&token.artifact_sha256, 64)
        || !lowercase_hex(&token.target_sha256, 64)
        || !lowercase_hex(&token.signature, 64)
        || !matches!(
            token.action.as_str(),
            "SOURCE_MODIFY" | "KNOWLEDGE_UPDATE" | "CATALOG_MUTATION" | "LAB_MUTATION"
        )
    {
        bail!("policy_approval_claim_invalid");
    }
    if token.actor_id != expected.actor_id
        || token.action != expected.action
        || token.command_sha256 != expected.command_sha256
        || token.artifact_sha256 != expected.artifact_sha256
        || token.target_sha256 != expected.target_sha256
    {
        bail!("policy_approval_context_mismatch");
    }
    if token.expires_at <= token.issued_at
        || token.expires_at - token.issued_at > TOKEN_VALIDITY_SECS
        || token.issued_at > now_seconds.saturating_add(CLOCK_SKEW_SECS)
        || now_seconds >= token.expires_at
    {
        bail!("policy_approval_expired_or_future");
    }
    let bytes = hex::decode(&key.key_hex)?;
    let message = unsigned_token_canonical(&token)?;
    let expected_signature = hmac_sha256(&bytes, &message);
    let provided_signature = hex::decode(&token.signature)?;
    if !constant_time_eq(&expected_signature, &provided_signature) {
        bail!("policy_approval_signature_invalid");
    }
    Ok(VerifiedIntent {
        nonce: token.nonce,
        intent_sha256: sha256_hex(&message),
        expires_at: token.expires_at,
        action: token.action,
        external_identity_verified: false,
        nonce_consumed: false,
        release_authorized: false,
        #[cfg(windows)]
        ledger_key: LocalLedgerKey(bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("policy_key_size_invalid"))?),
    })
}

pub fn redact_event(raw: &[u8], channel: &str, outcome: &str) -> Result<Value> {
    if raw.len() > MAX_LOG_BYTES
        || !matches!(
            channel,
            "process" | "python" | "rust" | "updater" | "catalog"
        )
        || !matches!(outcome, "PASS" | "FAIL" | "NOT_RUN" | "BLOCKED")
    {
        bail!("policy_untrusted_log_input");
    }
    Ok(json!({
        "status": "REDACTED_BOUNDARY_EVENT",
        "channel": channel,
        "outcome": outcome,
        "raw_sha256": sha256_hex(raw),
        "raw_bytes": raw.len(),
        "source_or_secrets_emitted": false,
        "global_rust_logging_enforced": false,
    }))
}

#[cfg(unix)]
pub fn consume_nonce_unix(ledger: &Path, intent: &VerifiedIntent, now_seconds: u64) -> Result<Value> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    if !lowercase_hex(&intent.nonce, 32)
        || !lowercase_hex(&intent.intent_sha256, 64)
        || now_seconds >= intent.expires_at
    {
        bail!("policy_intent_cannot_be_consumed");
    }
    let folder = ledger.parent().context("policy_ledger_parent_missing")?;
    let dir_meta = fs::symlink_metadata(folder)?;
    if !dir_meta.is_dir() || dir_meta.permissions().mode() & 0o077 != 0 {
        bail!("policy_ledger_directory_not_private");
    }
    if ledger.symlink_metadata().is_ok_and(|meta| {
        !meta.is_file() || meta.nlink() != 1 || meta.permissions().mode() & 0o077 != 0
    }) {
        bail!("policy_ledger_symlink_hardlink_or_public");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ledger)
        .context("policy_ledger_open_refused")?;
    let fd = file.as_raw_fd();
    // POSIX flock serializes concurrent processes. Unprivileged platforms
    // without flock must NOT silently switch to an in-memory nonce cache.
    if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
        bail!("policy_ledger_lock_failed");
    }
    let result = (|| -> Result<Value> {
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.permissions().mode() & 0o077 != 0
            || meta.len() > MAX_LEDGER_BYTES
        {
            bail!("policy_ledger_insecure_or_over_budget");
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES || (!bytes.is_empty() && !bytes.ends_with(b"\n")) {
            bail!("policy_ledger_tampered_or_partial_write");
        }
        let mut previous = "0".repeat(64);
        let mut count = 0_usize;
        for line in bytes.split(|c| *c == b'\n').filter(|line| !line.is_empty()) {
            count += 1;
            if count > MAX_LEDGER_EVENTS {
                bail!("policy_ledger_event_limit");
            }
            let row: Value = serde_json::from_slice(line)?;
            let (Some(nonce), Some(record_hash), Some(parent_hash), Some(checksum)) = (
                row.get("nonce").and_then(Value::as_str),
                row.get("intent_sha256").and_then(Value::as_str),
                row.get("previous").and_then(Value::as_str),
                row.get("event_sha256").and_then(Value::as_str),
            ) else {
                bail!("policy_ledger_event_invalid");
            };
            if row.as_object().is_none_or(|map| map.len() != 4)
                || !lowercase_hex(nonce, 32)
                || !lowercase_hex(record_hash, 64)
                || parent_hash != previous
                || !lowercase_hex(checksum, 64)
            {
                bail!("policy_ledger_event_invalid");
            }
            let mut unsigned = BTreeMap::new();
            unsigned.insert("nonce", json!(nonce));
            unsigned.insert("intent_sha256", json!(record_hash));
            unsigned.insert("previous", json!(parent_hash));
            if sha256_hex(&serde_json::to_vec(&unsigned)?) != checksum {
                bail!("policy_ledger_hash_chain_invalid");
            }
            if nonce == intent.nonce {
                bail!("policy_approval_nonce_replay");
            }
            previous = checksum.to_owned();
        }
        if count >= MAX_LEDGER_EVENTS {
            bail!("policy_ledger_event_limit");
        }
        let mut next = BTreeMap::new();
        next.insert("nonce", json!(intent.nonce));
        next.insert("intent_sha256", json!(intent.intent_sha256));
        next.insert("previous", json!(previous));
        let next_hash = sha256_hex(&serde_json::to_vec(&next)?);
        let mut complete = next;
        complete.insert("event_sha256", json!(next_hash));
        let mut line = serde_json::to_vec(&complete)?;
        line.push(b'\n');
        if meta.len() + line.len() as u64 > MAX_LEDGER_BYTES {
            bail!("policy_ledger_event_budget");
        }
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(json!({
            "status": "LOCAL_APPROVAL_INTENT_CONSUMED_NO_MUTATION",
            "intent_sha256": intent.intent_sha256,
            "nonce_consumed": true,
            "mutation_performed": false,
            "release_authorized": false,
            "external_human_identity_verified": false,
        }))
    })();
    unsafe {
        libc::flock(fd, libc::LOCK_UN);
    }
    result
}

#[cfg(windows)]
pub fn consume_nonce_windows(ledger: &Path, intent: &VerifiedIntent, now_seconds: u64) -> Result<Value> {
    if !lowercase_hex(&intent.nonce, 32)
        || !lowercase_hex(&intent.intent_sha256, 64)
        || now_seconds >= intent.expires_at
    {
        bail!("policy_intent_cannot_be_consumed");
    }
    crate::windows_policy::consume_nonce(
        ledger, &intent.nonce, &intent.intent_sha256, intent.expires_at,
        now_seconds, &intent.ledger_key.0,
    )
}

#[cfg(not(any(unix, windows)))]
pub fn consume_nonce_unavailable(
    _ledger: &Path,
    _intent: &VerifiedIntent,
    _now_seconds: u64,
) -> Result<Value> {
    bail!("policy_nonce_ledger_platform_unverified")
}

#[cfg(not(any(unix, windows)))]
pub use consume_nonce_unavailable as consume_nonce;

#[cfg(unix)]
pub use consume_nonce_unix as consume_nonce;
#[cfg(windows)]
pub use consume_nonce_windows as consume_nonce;

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>(command: &'a str, artifact: &'a str, target: &'a str) -> ExpectedIntent<'a> {
        ExpectedIntent {
            actor_id: "requester",
            action: command,
            command_sha256: artifact,
            artifact_sha256: target,
            target_sha256: target,
        }
    }

    fn test_token() -> (IntentToken, Vec<u8>, Vec<u8>, String) {
        let args = &["repair", "fixture.py"];
        let command_sha = command_sha256(args).unwrap();
        let artifact = sha256_hex(b"trusted-repair-candidate");
        let mut token = IntentToken {
            schema_version: 1,
            policy_id: "rust-cli-v23".into(),
            nonce: "a".repeat(32),
            issued_at: 1_000,
            expires_at: 1_060,
            actor_id: "requester".into(),
            approver_id: "independent-local-approver".into(),
            action: "SOURCE_MODIFY".into(),
            command_sha256: command_sha,
            artifact_sha256: artifact.clone(),
            target_sha256: artifact.clone(),
            signature: String::new(),
        };
        let key = [0x6b_u8; 32];
        token.signature = hex::encode(hmac_sha256(
            &key,
            &unsigned_token_canonical(&token).unwrap(),
        ));
        let bytes = serde_json::to_vec(&token).unwrap();
        let key_json =
            serde_json::to_vec(&json!({"schema_version": 1, "key_hex": hex::encode(key)})).unwrap();
        (token, bytes, key_json, artifact)
    }

    #[test]
    fn every_expected_root_command_has_an_explicit_classification() {
        for command in TOP_LEVEL {
            let got = classify_cli(&[command]);
            if command == "catalog" {
                assert_eq!(got.permission, Permission::DenyUnknown);
            } else {
                assert_ne!(got.permission, Permission::DenyUnknown, "{command}");
            }
        }
        assert_eq!(
            classify_cli(&["new-mutating-command"]).permission,
            Permission::DenyUnknown
        );
    }

    #[test]
    fn update_repair_and_all_catalog_mutations_require_approval() {
        for command in ["repair", "update", "lab"] {
            assert_eq!(
                classify_cli(&[command]).permission,
                Permission::RequireApproval
            );
        }
        for command in CATALOG_MUTATIONS {
            assert_eq!(
                classify_cli(&["catalog", command]).permission,
                Permission::RequireApproval
            );
        }
        for command in CATALOG_READ_ONLY {
            assert_eq!(
                classify_cli(&["catalog", command]).permission,
                Permission::ReadOnly
            );
        }
        assert_eq!(
            classify_cli(&["catalog", "unknown"]).permission,
            Permission::DenyUnknown
        );
    }

    #[test]
    fn help_cannot_be_smuggled_as_a_late_option_value() {
        assert_eq!(
            classify_cli(&["repair", "--help"]).permission,
            Permission::ReadOnly
        );
        assert_eq!(
            classify_cli(&["repair", "victim.py", "--help"]).permission,
            Permission::RequireApproval
        );
    }

    #[test]
    fn independently_signed_token_verifies_context_and_clock() {
        let (token, raw, key, artifact) = test_token();
        let context = ExpectedIntent {
            actor_id: "requester",
            action: "SOURCE_MODIFY",
            command_sha256: &token.command_sha256,
            artifact_sha256: &artifact,
            target_sha256: &artifact,
        };
        let verified = verify_intent(&raw, &key, &context, 1_020).unwrap();
        assert!(!verified.external_identity_verified);
        assert!(!verified.release_authorized);
        assert!(!verified.nonce_consumed);
        assert_eq!(verified.nonce, "a".repeat(32));
        assert!(verify_intent(&raw, &key, &context, 1_061).is_err());
        assert!(verify_intent(&raw, &key, &context, 900).is_err());
    }

    #[test]
    fn token_wrong_source_or_signature_cannot_authorize() {
        let (token, raw, key, artifact) = test_token();
        let mismatched = ExpectedIntent {
            actor_id: "requester",
            action: "SOURCE_MODIFY",
            command_sha256: &token.command_sha256,
            artifact_sha256: &artifact,
            target_sha256: &sha256_hex(b"different-target"),
        };
        assert!(verify_intent(&raw, &key, &mismatched, 1_020).is_err());
        let context = ExpectedIntent {
            actor_id: "requester",
            action: "SOURCE_MODIFY",
            command_sha256: &token.command_sha256,
            artifact_sha256: &artifact,
            target_sha256: &artifact,
        };
        let mut malicious = token.clone();
        malicious.signature = "f".repeat(64);
        let bytes = serde_json::to_vec(&malicious).unwrap();
        assert!(verify_intent(&bytes, &key, &context, 1_020).is_err());
    }

    #[test]
    fn duplicate_json_token_keys_are_not_accepted() {
        let (token, raw, key, artifact) = test_token();
        let context = ExpectedIntent {
            actor_id: "requester",
            action: "SOURCE_MODIFY",
            command_sha256: &token.command_sha256,
            artifact_sha256: &artifact,
            target_sha256: &artifact,
        };
        let mut value = raw;
        value.pop();
        value.extend_from_slice(b",\"schema_version\":1}");
        assert!(verify_intent(&value, &key, &context, 1_020).is_err());
    }

    #[test]
    fn event_redaction_does_not_expose_arbitrary_python_errors() {
        let leaked = b"Bearer SECRET-XYZ, person@example.invalid, /private/code.py";
        let masked = redact_event(leaked, "python", "FAIL").unwrap();
        let json = masked.to_string();
        assert!(!json.contains("SECRET"));
        assert!(!json.contains("example.invalid"));
        assert!(!json.contains("private/code.py"));
        assert_eq!(masked["source_or_secrets_emitted"], false);
        assert_eq!(masked["global_rust_logging_enforced"], false);
        assert!(redact_event(leaked, "model", "PASS").is_err());
    }

    #[test]
    fn hmac_implementation_matches_rfc4231_known_vector() {
        let result = hmac_sha256(&[0x0b_u8; 20], b"Hi There");
        assert_eq!(
            hex::encode(result),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nonce_ledger_rejects_replay_and_tampered_snapshot() {
        use std::os::unix::fs::PermissionsExt;
        let folder = tempfile::tempdir().unwrap();
        fs::set_permissions(folder.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = folder.path().join("approvals.jsonl");
        let receipt = VerifiedIntent {
            nonce: "a".repeat(32),
            intent_sha256: sha256_hex(b"approved-intent"),
            expires_at: 5_000,
            action: "SOURCE_MODIFY".into(),
            external_identity_verified: false,
            nonce_consumed: false,
            release_authorized: false,
        };
        let result = consume_nonce(&ledger, &receipt, 4_000).unwrap();
        assert_eq!(result["nonce_consumed"], true);
        assert_eq!(result["release_authorized"], false);
        assert!(consume_nonce(&ledger, &receipt, 4_001).is_err());
        let mut bytes = fs::read(&ledger).unwrap();
        bytes[20] ^= 1;
        fs::write(&ledger, bytes).unwrap();
        let new_receipt = VerifiedIntent {
            nonce: "b".repeat(32),
            ..receipt
        };
        assert!(consume_nonce(&ledger, &new_receipt, 4_002).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn nonce_ledger_rejects_public_parent_or_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let folder = tempfile::tempdir().unwrap();
        fs::set_permissions(folder.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let receipt = VerifiedIntent {
            nonce: "c".repeat(32),
            intent_sha256: sha256_hex(b"approval"),
            expires_at: 5_000,
            action: "SOURCE_MODIFY".into(),
            external_identity_verified: false,
            nonce_consumed: false,
            release_authorized: false,
        };
        let ledger = folder.path().join("approvals.jsonl");
        assert!(consume_nonce(&ledger, &receipt, 4_000).is_err());
        fs::set_permissions(folder.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let elsewhere = folder.path().join("other");
        fs::write(&elsewhere, b"").unwrap();
        symlink(&elsewhere, &ledger).unwrap();
        assert!(consume_nonce(&ledger, &receipt, 4_000).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_nonce_consumption_has_exactly_one_winner() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;
        let folder = tempfile::tempdir().unwrap();
        fs::set_permissions(folder.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = folder.path().join("concurrent-approvals.jsonl");
        let intent = Arc::new(VerifiedIntent {
            nonce: "d".repeat(32),
            intent_sha256: sha256_hex(b"single-approval-reused-concurrently"),
            expires_at: 5_000,
            action: "SOURCE_MODIFY".into(),
            external_identity_verified: false,
            nonce_consumed: false,
            release_authorized: false,
        });
        let handles = (0..8)
            .map(|_| {
                let ledger = ledger.clone();
                let intent = Arc::clone(&intent);
                std::thread::spawn(move || consume_nonce(&ledger, &intent, 4_000).is_ok())
            })
            .collect::<Vec<_>>();
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
    }
}
