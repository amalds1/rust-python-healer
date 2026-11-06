use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize)]
pub struct Evaluation {
    pub variant_id: String,
    pub safety: String,
    pub correctness: String,
    pub speed: String,
    pub reliability: String,
    pub compatibility: String,
    pub futureproof: String,
    pub compile: String,
    pub tests: String,
    pub duration_ms: u128,
    pub log: String,
    pub cached: bool,
}

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(include_str!("../sql/ledger.sql"))?;
    Ok(conn)
}

pub fn register(
    conn: &Connection,
    id: &str,
    code_sha: &str,
    config_sha: &str,
    engine: &str,
    parent_id: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO variants(id, code_sha256, config_sha256, engine, parent_id)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![id, code_sha, config_sha, engine, parent_id],
    )?;
    Ok(())
}

pub fn previous(conn: &Connection, id: &str) -> Result<Option<Evaluation>> {
    conn.query_row(
        "SELECT safety, correctness, speed, reliability, compatibility,
                futureproof, compile, tests, duration_ms, log
         FROM evaluations WHERE variant_id=?1 ORDER BY id DESC LIMIT 1",
        [id],
        |r| {
            Ok(Evaluation {
                variant_id: id.to_owned(),
                safety: r.get(0)?,
                correctness: r.get(1)?,
                speed: r.get(2)?,
                reliability: r.get(3)?,
                compatibility: r.get(4)?,
                futureproof: r.get(5)?,
                compile: r.get(6)?,
                tests: r.get(7)?,
                duration_ms: r.get::<_, i64>(8)? as u128,
                log: r.get(9)?,
                cached: true,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn record(conn: &Connection, result: &Evaluation) -> Result<()> {
    conn.execute(
        "INSERT INTO evaluations(variant_id, safety, correctness, speed,
         reliability, compatibility, futureproof, compile, tests, duration_ms, log)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            result.variant_id,
            result.safety,
            result.correctness,
            result.speed,
            result.reliability,
            result.compatibility,
            result.futureproof,
            result.compile,
            result.tests,
            i64::try_from(result.duration_ms).unwrap_or(i64::MAX),
            result.log,
        ],
    )?;
    Ok(())
}

pub fn summary(conn: &Connection) -> Result<serde_json::Value> {
    let variants: i64 = conn.query_row("SELECT COUNT(*) FROM variants", [], |r| r.get(0))?;
    let runs: i64 = conn.query_row("SELECT COUNT(*) FROM evaluations", [], |r| r.get(0))?;
    let eligible: i64 = conn.query_row(
        "SELECT COUNT(*) FROM evaluations
         WHERE safety='PASS' AND correctness='PASS' AND speed='PASS'
           AND reliability='PASS' AND compatibility='PASS' AND futureproof='PASS'",
        [],
        |r| r.get(0),
    )?;
    Ok(serde_json::json!({"variants": variants, "runs": runs,
                            "fully_qualified_runs": eligible}))
}
