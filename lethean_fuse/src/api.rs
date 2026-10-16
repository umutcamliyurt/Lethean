
use std::io::{self, Cursor, Read, Write as _};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use log::warn;
use rand::RngCore;
use serde::Deserialize;
use zeroize::Zeroize;

use crate::types::{EncryptedFilePayload, EncryptedHeader, FileRecord, UsageResponse};

pub struct ApiClient {
    base_url: String,
    agent: ureq::Agent,
    stream_agent: ureq::Agent,
    quick_agent: ureq::Agent,
    vault_id: RwLock<Option<String>>,
    access_token: RwLock<Option<String>>,
    range_support: AtomicU8,
}

const RANGE_UNKNOWN: u8 = 0;
const RANGE_YES: u8 = 1;
const RANGE_NO: u8 = 2;

fn parse_content_range(v: &str) -> Option<(u64, u64, u64)> {
    let rest = v.trim().strip_prefix("bytes")?.trim_start();
    let (span, total) = rest.split_once('/')?;
    let (a, b) = span.split_once('-')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?, total.trim().parse().ok()?))
}

#[derive(Deserialize)]
struct ErrorDetailBody {
    detail: Option<String>,
}

fn assert_safe_id(id: &str) -> Result<()> {
    let ok = !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        bail!("Invalid file id")
    }
}

fn assert_safe_share_token(token: &str) -> Result<()> {
    let ok = token.len() >= 8 && token.len() <= 256 && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        bail!("Invalid share link")
    }
}

#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpError {}

pub fn check_server_url(url: &str) -> Result<()> {
    let lower = url.trim().to_ascii_lowercase();
    let (scheme, rest) = lower.split_once("://").ok_or_else(|| anyhow!("the server URL must start with https://"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || rest.contains('?') || rest.contains('#') {
        bail!("the server URL must be a plain https:// address");
    }
    match scheme {
        "https" => Ok(()),
        "http" => {
            let host = if authority.starts_with('[') { authority.split(']').next().map(|h| format!("{h}]")).unwrap_or_default() } else { authority.split(':').next().unwrap_or("").to_string() };
            if matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
                Ok(())
            } else {
                bail!("the server URL must start with https:// (plain http is only allowed for localhost)")
            }
        }
        _ => bail!("the server URL must start with https://"),
    }
}

#[cfg(test)]
mod url_tests {
    use super::check_server_url;

    #[test]
    fn only_https_or_loopback_http() {
        for ok in ["https://vault.example.com", "https://vault.example.com:8443/", "http://localhost:8000", "http://127.0.0.1:0", "http://[::1]:8000"] {
            assert!(check_server_url(ok).is_ok(), "{ok}");
        }
        for bad in ["http://vault.example.com", "http://192.168.1.5:8000", "ftp://x", "vault.example.com", "https://user:pw@x.com", "http://localhost.evil.com", "http://127.0.0.1.evil.com"] {
            assert!(check_server_url(bad).is_err(), "{bad}");
        }
    }
}

pub fn is_missing_endpoint(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<HttpError>().map(|h| h.status == 404 || h.status == 405).unwrap_or(false))
}

fn finish(label: &str, result: std::result::Result<ureq::Response, ureq::Error>) -> Result<ureq::Response> {
    match result {
        Ok(resp) => Ok(resp),
        Err(ureq::Error::Status(code, resp)) => {
            let status_text = resp.status_text().to_string();
            let body_text = resp.into_string().unwrap_or_default();
            let detail = serde_json::from_str::<ErrorDetailBody>(&body_text).ok().and_then(|b| b.detail).unwrap_or(status_text.clone());
            Err(HttpError { status: code, message: format!("{label}: {} ({code})", sanitize_server_text(&detail)) }.into())
        }
        Err(ureq::Error::Transport(t)) => Err(anyhow!("{label}: network error ({t})")),
    }
}

fn sanitize_server_text(s: &str) -> String {
    const MAX_CHARS: usize = 300;
    let mut out: String = s.chars().filter(|c| !c.is_control() && !matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).take(MAX_CHARS + 1).collect();
    if out.chars().count() > MAX_CHARS {
        out = out.chars().take(MAX_CHARS).collect::<String>() + "…";
    }
    out
}

const MAX_PREALLOC: usize = 64 * 1024 * 1024;

fn read_body_bytes(resp: ureq::Response) -> std::io::Result<Vec<u8>> {
    let content_length = resp.header("Content-Length").and_then(|v| v.trim().parse::<u64>().ok());
    let mut out = Vec::with_capacity(content_length.map(|n| n.min(MAX_PREALLOC as u64) as usize).unwrap_or(0));
    resp.into_reader().read_to_end(&mut out)?;
    Ok(out)
}

fn multipart_boundary() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    format!("----vaultcli{}", hex::encode(buf))
}

fn multipart_head(boundary: &str, text_fields: &[(&str, &str)], file_field: &str, file_name: &str) -> Vec<u8> {
    let mut head = Vec::with_capacity(text_fields.iter().map(|(k, v)| k.len() + v.len() + 64).sum::<usize>() + file_field.len() + file_name.len() + 128);
    for (name, value) in text_fields {
        let _ = write!(head, "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n");
    }
    let _ = write!(head, "--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n");
    head
}

fn multipart_tail(boundary: &str) -> Vec<u8> {
    format!("\r\n--{boundary}--\r\n").into_bytes()
}

fn header_fields(h: &EncryptedHeader) -> [(&'static str, &str); 5] {
    [
        ("content_iv", h.content_iv.as_str()),
        ("encrypted_metadata", h.encrypted_metadata.as_str()),
        ("metadata_iv", h.metadata_iv.as_str()),
        ("wrapped_file_key", h.wrapped_file_key.as_str()),
        ("wrap_iv", h.wrap_iv.as_str()),
    ]
}

fn build_agent(overall_timeout: Option<Duration>) -> ureq::Agent {
    let mut b = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(90))
        .timeout_write(Duration::from_secs(90))
        .max_idle_connections(64)
        .max_idle_connections_per_host(32);
    if let Some(t) = overall_timeout {
        b = b.timeout(t);
    }
    b.build()
}

mod retry {
    use super::*;

    pub const MAX_ATTEMPTS: u32 = 5;
    const BASE_DELAY: Duration = Duration::from_millis(250);
    const MAX_DELAY: Duration = Duration::from_secs(8);

    pub enum AttemptError {
        Ureq(Box<ureq::Error>),
        Io(std::io::Error),
    }

    impl AttemptError {
        fn is_transient(&self) -> bool {
            match self {
                AttemptError::Ureq(e) => match e.as_ref() {
                    ureq::Error::Transport(_) => true,
                    ureq::Error::Status(code, _) => matches!(code, 502..=504),
                },
                AttemptError::Io(e) => matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::NotConnected
                ),
            }
        }

        fn into_anyhow(self, label: &str) -> anyhow::Error {
            match self {
                AttemptError::Ureq(e) => finish(label, Err(*e)).unwrap_err(),
                AttemptError::Io(e) => anyhow!("{label}: connection dropped while reading the response ({e})"),
            }
        }
    }

    impl From<ureq::Error> for AttemptError {
        fn from(e: ureq::Error) -> Self {
            AttemptError::Ureq(Box::new(e))
        }
    }

    impl From<std::io::Error> for AttemptError {
        fn from(e: std::io::Error) -> Self {
            AttemptError::Io(e)
        }
    }

    fn backoff_delay(attempt: u32) -> Duration {
        let mult = 1u64 << attempt.min(6);
        (BASE_DELAY * mult as u32).min(MAX_DELAY)
    }

    pub fn run<T>(label: &str, mut attempt: impl FnMut() -> Result<T, AttemptError>) -> Result<T> {
        let mut tries = 0u32;
        loop {
            match attempt() {
                Ok(v) => return Ok(v),
                Err(e) if tries + 1 < MAX_ATTEMPTS && e.is_transient() => {
                    tries += 1;
                    warn!("[lethean-cli] {label}: transient error, retrying (attempt {tries}/{MAX_ATTEMPTS})");
                    std::thread::sleep(backoff_delay(tries));
                }
                Err(e) => return Err(e.into_anyhow(label)),
            }
        }
    }
}

use retry::AttemptError;

impl ApiClient {
    pub fn new(base_url: String) -> Result<Self> {
        check_server_url(&base_url)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent: build_agent(Some(Duration::from_secs(180))),
            stream_agent: build_agent(None),
            quick_agent: ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(4)).timeout(Duration::from_secs(6)).build(),
            vault_id: RwLock::new(None),
            access_token: RwLock::new(None),
            range_support: AtomicU8::new(RANGE_UNKNOWN),
        })
    }

    pub fn supports_ranges(&self, probe_file_id: &str) -> Result<bool> {
        match self.range_support.load(Ordering::Acquire) {
            RANGE_YES => return Ok(true),
            RANGE_NO => return Ok(false),
            _ => {}
        }
        assert_safe_id(probe_file_id)?;
        let supported = retry::run("Download failed", || {
            let req = self.with_auth(self.agent.get(&self.url(&format!("/files/{probe_file_id}/blob"))), None).set("Range", "bytes=0-0");
            let resp = req.call().map_err(AttemptError::from)?;
            Ok(resp.status() == 206 && resp.header("Content-Range").and_then(parse_content_range).is_some())
        })?;
        self.range_support.store(if supported { RANGE_YES } else { RANGE_NO }, Ordering::Release);
        Ok(supported)
    }

    pub fn open_blob_range(&self, file_id: &str, start: u64, end: u64) -> Result<(Box<dyn Read + Send + Sync + 'static>, u64)> {
        assert_safe_id(file_id)?;
        if end < start {
            bail!("invalid byte range {start}-{end}");
        }
        let range = format!("bytes={start}-{end}");
        let (resp, total) = retry::run("Download failed", || {
            let req = self.with_auth(self.stream_agent.get(&self.url(&format!("/files/{file_id}/blob"))), None).set("Range", &range);
            let resp = req.call().map_err(AttemptError::from)?;
            let parsed = resp.header("Content-Range").and_then(parse_content_range);
            Ok((resp, parsed))
        })?;
        if resp.status() != 206 {
            self.range_support.store(RANGE_NO, Ordering::Release);
            bail!("Download failed: the server ignored the byte-range request");
        }
        match total {
            Some((a, b, total)) if a == start && b == end => Ok((Box::new(resp.into_reader().take(end - start + 1)), total)),
            Some((a, b, total)) => bail!("Download failed: asked for bytes {start}-{end}, server sent {a}-{b}/{total}"),
            None => bail!("Download failed: partial response without a valid Content-Range"),
        }
    }

    pub fn set_vault_id(&self, id: Option<String>) {
        let mut old = std::mem::replace(&mut *self.vault_id.write().unwrap(), id);
        if let Some(s) = old.as_mut() {
            s.zeroize();
        }
    }

    pub fn set_access_token(&self, token: Option<String>) {
        let mut old = std::mem::replace(&mut *self.access_token.write().unwrap(), token.filter(|t| !t.is_empty()));
        if let Some(s) = old.as_mut() {
            s.zeroize();
        }
    }

    pub fn vault_id(&self) -> Option<String> {
        self.vault_id.read().unwrap().clone()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn with_auth(&self, req: ureq::Request, vault_id_override: Option<&str>) -> ureq::Request {
        match vault_id_override.map(|s| s.to_string()).or_else(|| self.vault_id.read().unwrap().clone()) {
            Some(id) => req.set("Authorization", &format!("Bearer {id}")),
            None => req,
        }
    }

    pub fn upload_file(&self, encrypted: &EncryptedFilePayload, vault_id_override: Option<&str>, access_token_override: Option<&str>) -> Result<FileRecord> {
        let body: &[u8] = &encrypted.ciphertext;
        self.upload_stream(&encrypted.header(), body.len() as u64, || Ok(Box::new(Cursor::new(body)) as Box<dyn Read + '_>), vault_id_override, access_token_override)
    }

    pub fn upload_stream<'a, F>(&self, header: &EncryptedHeader, body_len: u64, mut make_body: F, vault_id_override: Option<&str>, access_token_override: Option<&str>) -> Result<FileRecord>
    where
        F: FnMut() -> io::Result<Box<dyn Read + 'a>>,
    {
        let token = access_token_override.map(|s| s.to_string()).or_else(|| self.access_token.read().unwrap().clone());

        let boundary = multipart_boundary();
        let head = multipart_head(&boundary, &header_fields(header), "blob", "blob");
        let tail = multipart_tail(&boundary);
        let total_len = head.len() as u64 + body_len + tail.len() as u64;
        let content_type = format!("multipart/form-data; boundary={boundary}");

        let mut attempted = false;
        retry::run("Upload failed", || {
            if std::mem::replace(&mut attempted, true) {
                if let Some(record) = self.find_landed_upload(header, vault_id_override) {
                    return Ok(record);
                }
            }
            let body = make_body().map_err(AttemptError::from)?;
            let reader = Cursor::new(&head[..]).chain(body).chain(Cursor::new(&tail[..]));
            let mut req = self.stream_agent.post(&self.url("/files")).set("Content-Type", &content_type).set("Content-Length", &total_len.to_string());
            req = self.with_auth(req, vault_id_override);
            if let Some(t) = &token {
                req = req.set("X-Access-Token", t);
            }
            let resp = req.send(reader).map_err(AttemptError::from)?;
            resp.into_json::<FileRecord>().map_err(AttemptError::from)
        })
    }

    fn find_landed_upload(&self, header: &EncryptedHeader, vault_id_override: Option<&str>) -> Option<FileRecord> {
        const PAGE: u64 = 200;
        let mut offset = 0u64;
        loop {
            let mut req = self.agent.get(&self.url("/files")).query("limit", &PAGE.to_string());
            if offset != 0 {
                req = req.query("offset", &offset.to_string());
            }
            let page: Vec<FileRecord> = self.with_auth(req, vault_id_override).call().ok()?.into_json().ok()?;
            let n = page.len() as u64;
            if let Some(found) = page.into_iter().find(|r| r.metadata_iv == header.metadata_iv && r.encrypted_metadata == header.encrypted_metadata && r.content_iv == header.content_iv && r.wrapped_file_key == header.wrapped_file_key && r.wrap_iv == header.wrap_iv) {
                warn!("[lethean-cli] an upload that looked failed had reached the server; not sending it twice");
                return Some(found);
            }
            if n < PAGE {
                return None;
            }
            offset += n;
        }
    }

    fn token_or(&self, token_override: Option<&str>) -> Option<String> {
        token_override.map(|s| s.to_string()).or_else(|| self.access_token.read().unwrap().clone())
    }

    pub fn upload_in_parts<'a, F>(&self, header: &EncryptedHeader, total_len: u64, mut make_body: F, vault_id_override: Option<&str>, access_token_override: Option<&str>) -> Result<FileRecord>
    where
        F: FnMut() -> io::Result<Box<dyn Read + 'a>>,
    {
        if total_len <= SINGLE_REQUEST_MAX_BYTES {
            return self.upload_stream(header, total_len, make_body, vault_id_override, access_token_override);
        }
        let token = self.token_or(access_token_override);
        let part_size = MULTIPART_PART_BYTES;
        let part_count = total_len.div_ceil(part_size);

        let upload_id = match self.start_upload(header, part_count, part_size, total_len, vault_id_override, token.as_deref()) {
            Ok(id) => id,
            Err(e) if is_missing_endpoint(&e) => return self.upload_stream(header, total_len, make_body, vault_id_override, access_token_override),
            Err(e) => return Err(e),
        };

        let result = (|| -> Result<FileRecord> {
            let mut body = make_body().map_err(|e| anyhow!("Upload failed: {e}"))?;
            let put_part = |index: u64, part: &[u8]| -> Result<()> {
                retry::run("Upload failed", || {
                    let mut req = self.with_auth(self.stream_agent.put(&self.url(&format!("/files/uploads/{upload_id}/parts/{index}"))), vault_id_override).set("Content-Type", "application/octet-stream");
                    if let Some(t) = &token {
                        req = req.set("X-Access-Token", t);
                    }
                    req.send_bytes(part).map_err(AttemptError::from)?;
                    Ok(())
                })
            };
            std::thread::scope(|scope| -> Result<()> {
                let mut in_flight: std::collections::VecDeque<std::thread::ScopedJoinHandle<'_, Result<()>>> = std::collections::VecDeque::new();
                let join = |h: std::thread::ScopedJoinHandle<'_, Result<()>>| -> Result<()> { h.join().unwrap_or_else(|_| Err(anyhow!("Upload failed: internal error in an upload worker"))) };
                let mut outcome = Ok(());
                for index in 0..part_count {
                    if in_flight.len() >= PARALLEL_PARTS {
                        outcome = join(in_flight.pop_front().expect("non-empty"));
                        if outcome.is_err() {
                            break;
                        }
                    }
                    let len = if index == part_count - 1 { total_len - index * part_size } else { part_size };
                    let mut part = vec![0u8; len as usize];
                    if let Err(e) = body.read_exact(&mut part) {
                        outcome = Err(anyhow!("Upload failed: {e}"));
                        break;
                    }
                    let put_part = &put_part;
                    in_flight.push_back(scope.spawn(move || put_part(index, &part)));
                }
                for h in in_flight {
                    let r = join(h);
                    if outcome.is_ok() {
                        outcome = r;
                    }
                }
                outcome
            })?;
            let mut attempted = false;
            retry::run("Upload failed", || {
                if std::mem::replace(&mut attempted, true) {
                    if let Some(record) = self.find_landed_upload(header, vault_id_override) {
                        return Ok(record);
                    }
                }
                let mut req = self.with_auth(self.agent.post(&self.url(&format!("/files/uploads/{upload_id}/complete"))), vault_id_override);
                if let Some(t) = &token {
                    req = req.set("X-Access-Token", t);
                }
                let resp = req.call().map_err(AttemptError::from)?;
                resp.into_json::<FileRecord>().map_err(AttemptError::from)
            })
        })();
        if result.is_err() {
            let _ = self.with_auth(self.agent.delete(&self.url(&format!("/files/uploads/{upload_id}"))), vault_id_override).call();
        }
        result
    }

    fn start_upload(&self, header: &EncryptedHeader, part_count: u64, part_size: u64, total_size: u64, vault_id_override: Option<&str>, token: Option<&str>) -> Result<String> {
        #[derive(Deserialize)]
        struct Started {
            upload_id: String,
        }
        let body = serde_json::json!({
            "content_iv": header.content_iv,
            "encrypted_metadata": header.encrypted_metadata,
            "metadata_iv": header.metadata_iv,
            "wrapped_file_key": header.wrapped_file_key,
            "wrap_iv": header.wrap_iv,
            "part_count": part_count,
            "part_size": part_size,
            "total_size": total_size,
        });
        let started: Started = retry::run("Upload failed", || {
            let mut req = self.with_auth(self.agent.post(&self.url("/files/uploads")), vault_id_override);
            if let Some(t) = token {
                req = req.set("X-Access-Token", t);
            }
            let resp = req.send_json(body.clone()).map_err(AttemptError::from)?;
            resp.into_json::<Started>().map_err(AttemptError::from)
        })?;
        assert_safe_id(&started.upload_id)?;
        Ok(started.upload_id)
    }

    pub fn get_duress(&self, token: &str, vault_id: Option<&str>) -> Result<RemoteDuress> {
        let mut req = self.quick_agent.get(&self.url("/duress")).set("X-Access-Token", token);
        if let Some(v) = vault_id {
            req = req.set("Authorization", &format!("Bearer {v}"));
        }
        let resp = finish("Could not load duress settings", req.call())?;
        Ok(resp.into_json::<RemoteDuress>()?)
    }

    pub fn put_duress(&self, blob: &str, shred_hash: Option<&str>, vault_id: &str, token: &str) -> Result<()> {
        retry::run("Could not save duress settings", || {
            let req = self.agent.put(&self.url("/duress")).set("Authorization", &format!("Bearer {vault_id}")).set("X-Access-Token", token);
            req.send_json(serde_json::json!({ "blob": blob, "shred_hash": shred_hash })).map_err(AttemptError::from)?;
            Ok(())
        })
    }

    pub fn shred_by_secret(&self, secret_b64: &str) -> Result<()> {
        retry::run("Shred signal failed", || {
            self.agent.post(&self.url("/vault/shred")).send_json(serde_json::json!({ "secret": secret_b64 })).map_err(AttemptError::from)?;
            Ok(())
        })
    }

    pub fn list_files(&self, offset: u64, limit: Option<u64>) -> Result<Vec<FileRecord>> {
        retry::run("Could not load files", || {
            let mut req = self.agent.get(&self.url("/files"));
            if offset != 0 {
                req = req.query("offset", &offset.to_string());
            }
            if let Some(l) = limit {
                req = req.query("limit", &l.to_string());
            }
            req = self.with_auth(req, None);
            let resp = req.call().map_err(AttemptError::from)?;
            resp.into_json::<Vec<FileRecord>>().map_err(AttemptError::from)
        })
    }

    pub fn get_usage(&self, vault_id_override: Option<&str>) -> Result<UsageResponse> {
        retry::run("Could not load usage", || {
            let req = self.with_auth(self.agent.get(&self.url("/usage")), vault_id_override);
            let resp = req.call().map_err(AttemptError::from)?;
            resp.into_json::<UsageResponse>().map_err(AttemptError::from)
        })
    }

    pub fn download_content(&self, file_id: &str) -> Result<Vec<u8>> {
        assert_safe_id(file_id)?;
        retry::run("Download failed", || {
            let req = self.with_auth(self.agent.get(&self.url(&format!("/files/{file_id}/blob"))), None);
            let resp = req.call().map_err(AttemptError::from)?;
            Ok(read_body_bytes(resp)?)
        })
    }

    pub fn open_blob(&self, file_id: &str) -> Result<(Box<dyn Read + Send + Sync + 'static>, Option<u64>)> {
        assert_safe_id(file_id)?;
        retry::run("Download failed", || {
            let req = self.with_auth(self.stream_agent.get(&self.url(&format!("/files/{file_id}/blob"))), None);
            let resp = req.call().map_err(AttemptError::from)?;
            let len = resp.header("Content-Length").and_then(|v| v.trim().parse::<u64>().ok());
            Ok((resp.into_reader(), len))
        })
    }

    pub fn delete_file(&self, file_id: &str, vault_id_override: Option<&str>) -> Result<()> {
        assert_safe_id(file_id)?;
        retry::run("Delete failed", || {
            let req = self.with_auth(self.agent.delete(&self.url(&format!("/files/{file_id}"))), vault_id_override);
            req.call().map_err(AttemptError::from)?;
            Ok(())
        })
    }

    pub fn rotate_vault(&self, new_vault_id: &str, rewraps: &[RewrapEntry]) -> Result<VaultRotateResult> {
        #[derive(serde::Serialize)]
        struct RewrapWire<'a> {
            file_id: &'a str,
            wrapped_file_key: &'a str,
            wrap_iv: &'a str,
        }
        #[derive(serde::Serialize)]
        struct Body<'a> {
            new_vault_id: &'a str,
            rewraps: Vec<RewrapWire<'a>>,
        }
        #[derive(Deserialize)]
        struct Wire {
            files_moved: u64,
            tokens_rebound: u64,
        }

        let body = Body {
            new_vault_id,
            rewraps: rewraps.iter().map(|r| RewrapWire { file_id: &r.file_id, wrapped_file_key: &r.wrapped_file_key, wrap_iv: &r.wrap_iv }).collect(),
        };
        let json_body = serde_json::to_value(&body)?;

        let data: Wire = retry::run("Couldn't change vault password", || {
            let mut req = self.with_auth(self.agent.post(&self.url("/vault/rotate")), None);
            if let Some(t) = self.access_token.read().unwrap().as_deref() {
                req = req.set("X-Access-Token", t);
            }
            let resp = req.send_json(json_body.clone()).map_err(AttemptError::from)?;
            resp.into_json::<Wire>().map_err(AttemptError::from)
        })?;
        Ok(VaultRotateResult { files_moved: data.files_moved, tokens_rebound: data.tokens_rebound })
    }

    pub fn send_shred_signal(&self, target_vault_id: &str) -> Result<()> {
        retry::run("Shred signal failed", || {
            let req = self.agent.delete(&self.url("/vault")).set("Authorization", &format!("Bearer {target_vault_id}"));
            req.call().map_err(AttemptError::from)?;
            Ok(())
        })
    }

    pub fn create_file_share(&self, file_id: &str, opts: &CreateShareOptions) -> Result<ShareCreateResponse> {
        assert_safe_id(file_id)?;
        retry::run("Could not create share link", || {
            let mut req = self.agent.post(&self.url(&format!("/files/{file_id}/share")));
            if let Some(m) = opts.max_downloads {
                req = req.query("max_downloads", &m.to_string());
            }
            if let Some(e) = opts.expires_in_seconds {
                req = req.query("expires_in", &e.to_string());
            }
            req = req.query("allow_delete", &opts.allow_delete.to_string());
            req = self.with_auth(req, None);
            let resp = req.call().map_err(AttemptError::from)?;
            resp.into_json::<ShareCreateResponse>().map_err(AttemptError::from)
        })
    }

    pub fn revoke_file_share(&self, file_id: &str) -> Result<()> {
        assert_safe_id(file_id)?;
        retry::run("Could not revoke share link", || {
            let req = self.with_auth(self.agent.delete(&self.url(&format!("/files/{file_id}/share"))), None);
            req.call().map_err(AttemptError::from)?;
            Ok(())
        })
    }

    pub fn get_share_record(&self, share_token: &str) -> Result<ShareRecord> {
        assert_safe_share_token(share_token)?;
        retry::run("This link is invalid or has expired", || {
            let resp = self.agent.get(&self.url(&format!("/share/{share_token}"))).call().map_err(AttemptError::from)?;
            resp.into_json::<ShareRecord>().map_err(AttemptError::from)
        })
    }

    pub fn download_share_content(&self, share_token: &str) -> Result<Vec<u8>> {
        assert_safe_share_token(share_token)?;
        retry::run("This link is invalid, has expired, or has no downloads left", || {
            let resp = self.agent.get(&self.url(&format!("/share/{share_token}/blob"))).call().map_err(AttemptError::from)?;
            Ok(read_body_bytes(resp)?)
        })
    }

    pub fn delete_shared_file(&self, share_token: &str) -> Result<()> {
        assert_safe_share_token(share_token)?;
        retry::run("Couldn't delete this file", || {
            self.agent.delete(&self.url(&format!("/share/{share_token}"))).call().map_err(AttemptError::from)?;
            Ok(())
        })
    }
}

impl Drop for ApiClient {
    fn drop(&mut self) {
        if let Ok(mut id) = self.vault_id.write() {
            if let Some(s) = id.as_mut() {
                s.zeroize();
            }
        }
        if let Ok(mut token) = self.access_token.write() {
            if let Some(s) = token.as_mut() {
                s.zeroize();
            }
        }
    }
}

pub const SINGLE_REQUEST_MAX_BYTES: u64 = 32 * 1024 * 1024 + 1024;
pub const MULTIPART_PART_BYTES: u64 = 32 * 1024 * 1024 + 16;
pub const PARALLEL_PARTS: usize = 3;

#[derive(Debug, Deserialize)]
pub struct RemoteDuress {
    pub blob: String,
    #[serde(default)]
    pub written: Option<bool>,
}

pub struct RewrapEntry {
    pub file_id: String,
    pub wrapped_file_key: String,
    pub wrap_iv: String,
}

pub struct VaultRotateResult {
    pub files_moved: u64,
    #[allow(dead_code)]
    pub tokens_rebound: u64,
}

#[derive(Default)]
pub struct CreateShareOptions {
    pub max_downloads: Option<u64>,
    pub expires_in_seconds: Option<u64>,
    pub allow_delete: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareCreateResponse {
    pub share_token: String,
    #[serde(default)]
    pub delete_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    pub max_downloads: u64,
}

#[derive(Debug, Deserialize)]
pub struct ShareRecord {
    pub content_iv: String,
    pub encrypted_metadata: String,
    pub metadata_iv: String,
    pub downloads_used: u64,
    pub max_downloads: u64,
    pub expires_at: String,
    pub deletable: bool,
}
