
use std::io::{Read, Write as _};
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use log::warn;
use rand::RngCore;
use serde::Deserialize;
use zeroize::Zeroize;

use crate::types::{EncryptedFilePayload, FileRecord, UsageResponse};

pub struct ApiClient {
    base_url: String,
    agent: ureq::Agent,
    vault_id: RwLock<Option<String>>,
    access_token: RwLock<Option<String>>,
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

fn finish(label: &str, result: std::result::Result<ureq::Response, ureq::Error>) -> Result<ureq::Response> {
    match result {
        Ok(resp) => Ok(resp),
        Err(ureq::Error::Status(code, resp)) => {
            let status_text = resp.status_text().to_string();
            let body_text = resp.into_string().unwrap_or_default();
            let detail = serde_json::from_str::<ErrorDetailBody>(&body_text).ok().and_then(|b| b.detail).unwrap_or(status_text.clone());
            Err(anyhow!("{label}: {detail} ({code})"))
        }
        Err(ureq::Error::Transport(t)) => Err(anyhow!("{label}: network error ({t})")),
    }
}

fn read_body_bytes(resp: ureq::Response) -> std::io::Result<Vec<u8>> {
    let content_length = resp.header("Content-Length").and_then(|v| v.parse::<usize>().ok());
    let mut out = match content_length {
        Some(len) => Vec::with_capacity(len),
        None => Vec::new(),
    };
    resp.into_reader().read_to_end(&mut out)?;
    Ok(out)
}

fn multipart_boundary() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    format!("----vaultcli{}", hex::encode(buf))
}

fn build_multipart(text_fields: &[(&str, &str)], file_field: &str, file_name: &str, file_bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = multipart_boundary();

    let estimated_len = text_fields.iter().map(|(k, v)| k.len() + v.len() + 64).sum::<usize>() + file_field.len() + file_name.len() + file_bytes.len() + 128;
    let mut body = Vec::with_capacity(estimated_len);

    for (name, value) in text_fields {
        let _ = write!(body, "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n");
    }
    let _ = write!(body, "--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(file_bytes);
    body.extend_from_slice(b"\r\n");
    let _ = write!(body, "--{boundary}--\r\n");
    (boundary, body)
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
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(90))
            .timeout_write(Duration::from_secs(90))
            .timeout(Duration::from_secs(180))
            .build();
        Ok(Self { base_url: base_url.trim_end_matches('/').to_string(), agent, vault_id: RwLock::new(None), access_token: RwLock::new(None) })
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
        let token = access_token_override.map(|s| s.to_string()).or_else(|| self.access_token.read().unwrap().clone());

        let (boundary, body) = build_multipart(
            &[
                ("content_iv", &encrypted.content_iv),
                ("encrypted_metadata", &encrypted.encrypted_metadata),
                ("metadata_iv", &encrypted.metadata_iv),
                ("wrapped_file_key", &encrypted.wrapped_file_key),
                ("wrap_iv", &encrypted.wrap_iv),
            ],
            "blob",
            "blob",
            &encrypted.ciphertext,
        );

        retry::run("Upload failed", || {
            let mut req = self.agent.post(&self.url("/files")).set("Content-Type", &format!("multipart/form-data; boundary={boundary}"));
            req = self.with_auth(req, vault_id_override);
            if let Some(t) = &token {
                req = req.set("X-Access-Token", t);
            }
            let resp = req.send_bytes(&body).map_err(AttemptError::from)?;
            resp.into_json::<FileRecord>().map_err(AttemptError::from)
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
