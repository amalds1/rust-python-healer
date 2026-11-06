//! Bounded, fail-closed Debug Adapter Protocol initialization transport.
//!
//! Implements DAP Content-Length framing, initialize capability negotiation,
//! explicit refusal of unsupported debugging requests and safe disconnection.
//! There is no launch/attach backend, so no untrusted code is executed.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

const MAX_HEADER_BYTES: usize = 4096;
const MAX_MESSAGE_BYTES: usize = 65_536;
const MAX_REQUESTS: usize = 256;

fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Value>> {
    let mut header = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HEADER_BYTES {
            bail!("DAP-header overschrijdt de maximale grootte");
        }
        match reader.read(&mut byte)? {
            0 if header.is_empty() => return Ok(None),
            0 => bail!("onvolledige DAP-header"),
            _ => header.push(byte[0]),
        }
    }
    let text = std::str::from_utf8(&header).context("DAP-header is geen ASCII/UTF-8")?;
    if !text.is_ascii() {
        bail!("DAP-header moet ASCII zijn");
    }
    let mut length = None;
    for line in text.strip_suffix("\r\n\r\n").unwrap_or(text).split("\r\n") {
        let (name, value) = line
            .split_once(": ")
            .context("ongeldig DAP-headerformaat")?;
        if name.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|v| v.is_ascii_digit()) {
                bail!("dubbele of ongeldige DAP Content-Length");
            }
            length = Some(value.parse::<usize>().context("ongeldige DAP-lengte")?);
        }
    }
    let size = length.context("DAP Content-Length ontbreekt")?;
    if size == 0 || size > MAX_MESSAGE_BYTES {
        bail!("DAP-bericht overschrijdt maximale grootte of is leeg");
    }
    let mut payload = vec![0u8; size];
    reader
        .read_exact(&mut payload)
        .context("onvolledige DAP-payload")?;
    let request: Value = serde_json::from_slice(&payload).context("ongeldige DAP-JSON")?;
    if !request.is_object() {
        bail!("DAP-request is geen object");
    }
    Ok(Some(request))
}

fn write_frame<W: Write>(writer: &mut W, message: &Value) -> Result<()> {
    let payload = serde_json::to_vec(message)?;
    if payload.len() > MAX_MESSAGE_BYTES {
        bail!("uitgaand DAP-antwoord te groot");
    }
    writer.write_all(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

fn response(outgoing: &mut i64, seq: i64, command: &str, success: bool, body: Value) -> Value {
    let result = json!({
        "type": "response",
        "seq": *outgoing,
        "request_seq": seq,
        "command": command,
        "success": success,
        "body": body,
    });
    *outgoing += 1;
    result
}

fn event(outgoing: &mut i64, name: &str) -> Value {
    let result = json!({"seq": *outgoing, "type": "event", "event": name});
    *outgoing += 1;
    result
}

fn validate_initialize(request: &Value) -> bool {
    let Some(args) = request.get("arguments").and_then(Value::as_object) else {
        return false;
    };
    let Some(adapter) = args.get("adapterID").and_then(Value::as_str) else {
        return false;
    };
    if adapter.is_empty() || adapter.len() > 128 {
        return false;
    }
    match args.get("pathFormat") {
        None => true,
        Some(value) => matches!(value.as_str(), Some("path" | "uri")),
    }
}

pub fn serve<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<()> {
    let mut initialized = false;
    let mut outgoing_seq = 1;
    for _ in 0..MAX_REQUESTS {
        let Some(req) = read_frame(reader)? else {
            return Ok(());
        };
        let Some(seq) = req.get("seq").and_then(Value::as_i64) else {
            bail!("DAP request_seq ontbreekt of is ongeldig");
        };
        if !(1..=i32::MAX as i64).contains(&seq) || req.get("type") != Some(&json!("request")) {
            bail!("DAP verwacht een geldig clientrequest");
        }
        let Some(command) = req.get("command").and_then(Value::as_str) else {
            bail!("DAP-command ontbreekt");
        };
        if command.is_empty() || command.len() > 64 || !command.is_ascii() {
            bail!("ongeldig DAP-command");
        }
        match command {
            "initialize" if !initialized && validate_initialize(&req) => {
                initialized = true;
                // Empty capabilities: the adapter explicitly claims no runtime backend.
                write_frame(
                    writer,
                    &response(&mut outgoing_seq, seq, command, true, json!({})),
                )?;
                write_frame(writer, &event(&mut outgoing_seq, "initialized"))?;
            }
            "initialize" => {
                write_frame(
                    writer,
                    &response(&mut outgoing_seq, seq, command, false, json!({})),
                )?;
            }
            "disconnect" if initialized => {
                write_frame(
                    writer,
                    &response(&mut outgoing_seq, seq, command, true, json!({})),
                )?;
                write_frame(writer, &event(&mut outgoing_seq, "terminated"))?;
                return Ok(());
            }
            _ => {
                // Never treat a request to start code or evaluate an expression as authorized.
                write_frame(
                    writer,
                    &response(&mut outgoing_seq, seq, command, false, json!({})),
                )?;
            }
        }
    }
    bail!("DAP-berichtlimiet bereikt; sessie veilig beëindigd")
}

pub fn serve_stdio() -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve(&mut stdin.lock(), &mut stdout.lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(value: Value) -> Vec<u8> {
        let mut data = Vec::new();
        write_frame(&mut data, &value).unwrap();
        data
    }

    fn received(data: &[u8]) -> Vec<Value> {
        let mut reader = data;
        let mut frames = Vec::new();
        while let Some(frame) = read_frame(&mut reader).unwrap() {
            frames.push(frame);
        }
        frames
    }

    #[test]
    fn initialize_then_disconnect_negotiates_no_unsafe_capabilities() {
        let mut input = framed(json!({"seq": 7, "type":"request", "command":"initialize",
                                      "arguments":{"adapterID":"rust-python-healer"}}));
        input.extend(framed(
            json!({"seq":8, "type":"request", "command":"disconnect"}),
        ));
        let mut output = Vec::new();
        serve(&mut input.as_slice(), &mut output).unwrap();
        let frames = received(&output);
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0]["request_seq"], 7);
        assert_eq!(frames[0]["success"], true);
        assert_eq!(frames[0]["body"], json!({}));
        assert_eq!(frames[1]["event"], "initialized");
        assert_eq!(frames[2]["request_seq"], 8);
        assert_eq!(frames[3]["event"], "terminated");
    }

    #[test]
    fn unsupported_launch_evaluate_and_repeat_initialize_fail_closed() {
        let requests = [
            json!({"seq":1,"type":"request","command":"initialize","arguments":{"adapterID":"healer"}}),
            json!({"seq":2,"type":"request","command":"launch","arguments":{"program":"/secret.py"}}),
            json!({"seq":3,"type":"request","command":"evaluate","arguments":{"expression":"do_bad()"}}),
            json!({"seq":4,"type":"request","command":"initialize","arguments":{"adapterID":"healer"}}),
        ];
        let input: Vec<u8> = requests.into_iter().flat_map(framed).collect();
        let mut output = Vec::new();
        serve(&mut input.as_slice(), &mut output).unwrap();
        let frames = received(&output);
        assert_eq!(frames.len(), 5);
        assert_eq!(frames[2]["success"], false);
        assert_eq!(frames[3]["success"], false);
        assert_eq!(frames[4]["success"], false);
        assert!(!String::from_utf8_lossy(&output).contains("/secret.py"));
        assert!(!String::from_utf8_lossy(&output).contains("do_bad()"));
    }

    #[test]
    fn invalid_framing_json_and_header_quotas_are_rejected() {
        for bytes in [
            b"Content-Length: -1\r\n\r\n".to_vec(),
            b"Content-Length: 999999999999999999999\r\n\r\n".to_vec(),
            b"Content-Length: 1\r\nContent-Length: 1\r\n\r\nx".to_vec(),
            b"Content-Length: 4\r\n\r\nnull".to_vec(),
            b"Content-Length: 4\r\n\r\n{".to_vec(),
            vec![b'X'; MAX_HEADER_BYTES + 1],
        ] {
            assert!(serve(&mut bytes.as_slice(), &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn malformed_or_repeat_initialize_never_sends_second_event() {
        let mut input =
            framed(json!({"seq":1,"type":"request","command":"initialize","arguments":{}}));
        input.extend(framed(
            json!({"seq":2,"type":"request","command":"initialize",
                                   "arguments":{"adapterID":"healer", "pathFormat":"bad"}}),
        ));
        let mut output = Vec::new();
        serve(&mut input.as_slice(), &mut output).unwrap();
        let frames = received(&output);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["success"], false);
        assert_eq!(frames[1]["success"], false);
    }
}
