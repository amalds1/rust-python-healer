//! Inspect a captured Python traceback as data. No source execution, no file
//! access to locations mentioned in the traceback, and no inferred winner.

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const MAX_TRACE_BYTES: u64 = 2_000_000;
const MAX_FRAMES: usize = 128;

#[derive(Debug, Clone, Serialize)]
struct Frame {
    file: String,
    path_sha256: String,
    line: u32,
    function: String,
    source: Option<String>,
}

fn frame_header(text: &str) -> Option<Frame> {
    let text = text.trim();
    let rest = text.strip_prefix("File \"")?;
    let (file, rest) = rest.split_once("\", line ")?;
    let (line_text, function) = rest.split_once(", in ").unwrap_or((rest, "<unknown>"));
    let line = line_text.trim().parse::<u32>().ok().filter(|n| *n > 0)?;
    if file.is_empty() || file.len() > 4096 || function.len() > 512 {
        return None;
    }
    Some(Frame {
        file: file.into(),
        path_sha256: hex::encode(Sha256::digest(file.as_bytes())),
        line,
        function: function.into(),
        source: None,
    })
}

fn exception_line(text: &str) -> Option<(String, String)> {
    if text.len() > 4096 || text.starts_with(char::is_whitespace) {
        return None;
    }
    let trimmed = text.trim();
    let (name, detail) = if let Some((name, detail)) = trimmed.split_once(':') {
        (name, detail.trim())
    } else {
        (trimmed, "")
    };
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
        || !name.chars().any(|c| c.is_ascii_uppercase())
    {
        return None;
    }
    let short = name.rsplit('.').next()?;
    if !(short.ends_with("Error")
        || short.ends_with("Exception")
        || matches!(
            short,
            "KeyboardInterrupt" | "SystemExit" | "StopIteration" | "GeneratorExit"
        ))
    {
        return None;
    }
    Some((name.to_owned(), detail.to_owned()))
}

fn suggestions(kind: &str) -> Vec<&'static str> {
    match kind.rsplit('.').next().unwrap_or(kind) {
        "ModuleNotFoundError" | "ImportError" => vec![
            "Controleer de geselecteerde Python-interpreter en de virtuele omgeving.",
            "Vergelijk packageversies, lockfile en importnaam; installeer niets automatisch.",
        ],
        "AttributeError" => vec![
            "Controleer de werkelijke objecttype en de versie van de gebruikte package-API.",
            "Verifieer een eventuele API-migratie met officiële, versiegebonden documentatie.",
        ],
        "TypeError" => vec![
            "Controleer argumentnamen, aantallen, types en de signatuur van de aangeroepen functie.",
        ],
        "NameError" => vec![
            "Controleer naamgeving, scope en of de benodigde import of definitie bestaat.",
        ],
        "FileNotFoundError" | "PermissionError" => vec![
            "Controleer het effectieve pad, toegangsrechten en de uitvoerwerkdirectory.",
        ],
        "SyntaxError" | "IndentationError" | "TabError" => vec![
            "Voer een compile-only check uit met exact dezelfde Python-minorversie.",
        ],
        _ => vec![
            "Controleer de laatste relevante stackframe en reproduceer dit uitsluitend in een geïsoleerde testomgeving.",
        ],
    }
}

#[cfg(test)]
fn analyze_text(text: &str) -> Value {
    analyze_text_with_mode(text, false)
}

fn analyze_text_with_mode(text: &str, show_sensitive: bool) -> Value {
    let mut frames: Vec<Frame> = Vec::new();
    let mut saw_traceback = false;
    let mut pending_source = false;
    let mut exception = None;
    for line in text.lines() {
        if line
            .trim_start()
            .starts_with("Traceback (most recent call last):")
        {
            saw_traceback = true;
            pending_source = false;
            continue;
        }
        if !saw_traceback {
            continue;
        }
        if let Some(mut frame) = frame_header(line) {
            if frames.len() < MAX_FRAMES {
                if !show_sensitive {
                    frame.file = "[REDACTED_PATH]".into();
                    frame.function = "[REDACTED_FUNCTION]".into();
                }
                frames.push(frame);
                pending_source = show_sensitive;
            }
            continue;
        }
        if pending_source {
            let code = line.trim();
            if !code.is_empty() && !code.chars().all(|c| c == '^' || c == '~' || c == ' ') {
                if let Some(frame) = frames.last_mut() {
                    frame.source = Some(code.chars().take(1000).collect());
                }
            }
            pending_source = false;
        }
        if let Some(parsed) = exception_line(line) {
            exception = Some(parsed);
        }
    }
    match exception {
        Some((kind, message)) => {
            let relevant = frames.last().cloned();
            json!({
                "status": "DIAGNOSED", "exception_type": kind,
                "message": if show_sensitive { message.as_str() } else { "[REDACTED_EXCEPTION_MESSAGE]" },
                "privacy": if show_sensitive { "USER_OPTED_IN" } else { "REDACTED" },
                "frames": frames,
                "primary_frame": relevant,
                "suggestions": suggestions(&kind),
                "source_executed": false,
                "correctness": "NOT_VERIFIED",
                "reason": "Een tekstuele traceback bewijst de oorzaak of de juistheid van een herstelvoorstel niet",
            })
        }
        None => json!({
            "status": "NOT_RUN", "exception_type": null, "message": null,
            "privacy": if show_sensitive { "USER_OPTED_IN" } else { "REDACTED" },
            "frames": frames, "suggestions": [], "source_executed": false,
            "reason": "Geen herkenbare Python-exception in een volledig traceback",
        }),
    }
}

pub fn analyze_file(path: &Path, show_sensitive: bool) -> Result<Value> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_TRACE_BYTES {
        bail!("traceback moet een gewoon bestand van maximaal 2 MB zijn");
    }
    let content = fs::read_to_string(path)?;
    Ok(analyze_text_with_mode(&content, show_sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_last_frame_and_exception() {
        let log = "Traceback (most recent call last):\n  File \"main.py\", line 2, in <module>\n    step()\n  File \"app.py\", line 8, in step\n    missing\nNameError: name 'missing' is not defined\n";
        let report = analyze_text(log);
        assert_eq!(report["status"], "DIAGNOSED");
        assert_eq!(report["frames"].as_array().unwrap().len(), 2);
        assert_eq!(report["primary_frame"]["file"], "[REDACTED_PATH]");
        assert_eq!(report["exception_type"], "NameError");
        assert_eq!(report["source_executed"], false);
    }

    #[test]
    fn no_traceback_does_not_get_false_pass() {
        assert_eq!(analyze_text("NameError: nope")["status"], "NOT_RUN");
        assert_eq!(analyze_text("ordinary log output")["status"], "NOT_RUN");
    }

    #[test]
    fn parses_chained_exception_tail() {
        let log = "Traceback (most recent call last):\n  File \"a.py\", line 1, in f\n    int('x')\nValueError: bad\n\nDuring handling of the above exception, another exception occurred:\n\nTraceback (most recent call last):\n  File \"b.py\", line 3, in g\n    raise TypeError('new')\nTypeError: new\n";
        let report = analyze_text(log);
        assert_eq!(report["exception_type"], "TypeError");
        assert_eq!(report["primary_frame"]["file"], "[REDACTED_PATH]");
    }

    #[test]
    fn malformed_frame_is_ignored() {
        let report = analyze_text(
            "Traceback (most recent call last):\n  File \"bad\", line abc, in f\nValueError: no\n",
        );
        assert_eq!(report["status"], "DIAGNOSED");
        assert_eq!(report["frames"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn syntax_error_file_without_function_is_supported() {
        let log = "Traceback (most recent call last):\n  File \"<string>\", line 1, in <module>\n  File \"bad.py\", line 3\n    if True\nSyntaxError: expected ':'\n";
        let report = analyze_text(log);
        assert_eq!(report["status"], "DIAGNOSED");
        assert_eq!(report["primary_frame"]["file"], "[REDACTED_PATH]");
        assert_eq!(report["primary_frame"]["line"], 3);
    }

    #[test]
    fn sensitive_trace_material_is_redacted_by_default() {
        let log = "Traceback (most recent call last):\n  File \"/private/Alice/token-secret.py\", line 7, in password_secret\n    api_key = 'sk-test-SUPER_SECRET'\nValueError: token=PRIVATE_PASSWORD alice@example.invalid\n";
        let result = analyze_text(log);
        let rendered = result.to_string();
        assert_eq!(result["status"], "DIAGNOSED");
        assert_eq!(result["privacy"], "REDACTED");
        assert_eq!(result["frames"][0]["source"], Value::Null);
        assert_eq!(result["frames"][0]["line"], 7);
        assert_eq!(result["message"], "[REDACTED_EXCEPTION_MESSAGE]");
        assert_eq!(
            result["frames"][0]["path_sha256"].as_str().unwrap().len(),
            64
        );
        for secret in [
            "Alice",
            "SUPER_SECRET",
            "PRIVATE_PASSWORD",
            "alice@example.invalid",
            "password_secret",
        ] {
            assert!(
                !rendered.contains(secret),
                "sensitive value leaked: {secret}"
            );
        }
    }

    #[test]
    fn explicit_sensitive_mode_recovers_local_diagnostic_details() {
        let log = "Traceback (most recent call last):\n  File \"/private/alice.py\", line 2, in handler\n    raise ValueError('PASSWORD')\nValueError: PASSWORD\n";
        let result = analyze_text_with_mode(log, true);
        assert_eq!(result["privacy"], "USER_OPTED_IN");
        assert_eq!(result["primary_frame"]["file"], "/private/alice.py");
        assert_eq!(
            result["primary_frame"]["source"],
            "raise ValueError('PASSWORD')"
        );
        assert_eq!(result["message"], "PASSWORD");
    }
}
