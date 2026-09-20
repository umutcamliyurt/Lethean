
use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde::Deserialize;

use crate::types::{EncryptedFilePayload, FileRecord, UsageResponse};

pub struct ApiClient {
    base_url: String,
    agent: ureq::Agent,
    vault_id: Option<String>,
    access_token: Option<String>,
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

/// Turns a `ureq` result into ours, extracting `{"detail": "..."}` out of
/// error bodies the way `checkOk` does in api.ts.
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

fn read_body_bytes(resp: ureq::Response) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    resp.into_reader().read_to_end(&mut out)?;
    Ok(out)
}

fn multipart_boundary() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    format!("----vaultcli{}", hex::encode(buf))
}

/// Hand-rolled `multipart/form-data` body: `ureq` has no built-in form
/// encoder, and this keeps the dependency tree small.
fn build_multipart(text_fields: &[(&str, &str)], file_field: &str, file_name: &str, file_bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = multipart_boundary();
    let mut body = Vec::new();
    for (name, value) in text_fields {
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
    }
    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
    body.extend_from_slice(file_bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

impl ApiClient {
    pub fn new(base_url: String) -> Result<Self> {
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(15)).timeout(Duration::from_secs(120)).build();
        Ok(Self { base_url: base_url.trim_end_matches('/').to_string(), agent, vault_id: None, access_token: None })
    }

    pub fn set_vault_id(&mut self, id: Option<String>) {
        self.vault_id = id;
    }

    pub fn set_access_token(&mut self, token: Option<String>) {
        self.access_token = token.filter(|t| !t.is_empty());
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn with_auth(&self, req: ureq::Request, vault_id_override: Option<&str>) -> ureq::Request {
        match vault_id_override.map(|s| s.to_string()).or_else(|| self.vault_id.clone()) {
            Some(id) => req.set("Authorization", &format!("Bearer {id}")),
            None => req,
        }
    }

    pub fn upload_file(&self, encrypted: &EncryptedFilePayload, vault_id_override: Option<&str>, access_token_override: Option<&str>) -> Result<FileRecord> {
        let token = access_token_override.map(|s| s.to_string()).or_else(|| self.access_token.clone());

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

        let mut req = self.agent.post(&self.url("/files")).set("Content-Type", &format!("multipart/form-data; boundary={boundary}"));
        req = self.with_auth(req, vault_id_override);
        if let Some(t) = &token {
            req = req.set("X-Access-Token", t);
        }
        let resp = finish("Upload failed", req.send_bytes(&body))?;
        Ok(resp.into_json::<FileRecord>()?)
    }

    pub fn list_files(&self, offset: u64, limit: Option<u64>) -> Result<Vec<FileRecord>> {
        let mut req = self.agent.get(&self.url("/files"));
        if offset != 0 {
            req = req.query("offset", &offset.to_string());
        }
        if let Some(l) = limit {
            req = req.query("limit", &l.to_string());
        }
        req = self.with_auth(req, None);
        let resp = finish("Could not load files", req.call())?;
        Ok(resp.into_json::<Vec<FileRecord>>()?)
    }

    pub fn get_usage(&self, vault_id_override: Option<&str>) -> Result<UsageResponse> {
        let req = self.with_auth(self.agent.get(&self.url("/usage")), vault_id_override);
        let resp = finish("Could not load usage", req.call())?;
        Ok(resp.into_json::<UsageResponse>()?)
    }

    pub fn download_content(&self, file_id: &str) -> Result<Vec<u8>> {
        assert_safe_id(file_id)?;
        let req = self.with_auth(self.agent.get(&self.url(&format!("/files/{file_id}/blob"))), None);
        let resp = finish("Download failed", req.call())?;
        read_body_bytes(resp)
    }

    pub fn delete_file(&self, file_id: &str, vault_id_override: Option<&str>) -> Result<()> {
        assert_safe_id(file_id)?;
        let req = self.with_auth(self.agent.delete(&self.url(&format!("/files/{file_id}"))), vault_id_override);
        finish("Delete failed", req.call())?;
        Ok(())
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

        let mut req = self.with_auth(self.agent.post(&self.url("/vault/rotate")), None);
        if let Some(t) = &self.access_token {
            req = req.set("X-Access-Token", t);
        }
        let resp = finish("Couldn't change vault password", req.send_json(serde_json::to_value(&body)?))?;
        let data: Wire = resp.into_json()?;
        Ok(VaultRotateResult { files_moved: data.files_moved, tokens_rebound: data.tokens_rebound })
    }

    pub fn send_shred_signal(&self, target_vault_id: &str) -> Result<()> {
        let req = self.agent.delete(&self.url("/vault")).set("Authorization", &format!("Bearer {target_vault_id}"));
        finish("Shred signal failed", req.call())?;
        Ok(())
    }

    pub fn create_file_share(&self, file_id: &str, opts: &CreateShareOptions) -> Result<ShareCreateResponse> {
        assert_safe_id(file_id)?;
        let mut req = self.agent.post(&self.url(&format!("/files/{file_id}/share")));
        if let Some(m) = opts.max_downloads {
            req = req.query("max_downloads", &m.to_string());
        }
        if let Some(e) = opts.expires_in_seconds {
            req = req.query("expires_in", &e.to_string());
        }
        req = req.query("allow_delete", &opts.allow_delete.to_string());
        req = self.with_auth(req, None);
        let resp = finish("Could not create share link", req.call())?;
        Ok(resp.into_json::<ShareCreateResponse>()?)
    }

    pub fn revoke_file_share(&self, file_id: &str) -> Result<()> {
        assert_safe_id(file_id)?;
        let req = self.with_auth(self.agent.delete(&self.url(&format!("/files/{file_id}/share"))), None);
        finish("Could not revoke share link", req.call())?;
        Ok(())
    }

    pub fn get_share_record(&self, share_token: &str) -> Result<ShareRecord> {
        assert_safe_share_token(share_token)?;
        let resp = finish("This link is invalid or has expired", self.agent.get(&self.url(&format!("/share/{share_token}"))).call())?;
        Ok(resp.into_json::<ShareRecord>()?)
    }

    pub fn download_share_content(&self, share_token: &str) -> Result<Vec<u8>> {
        assert_safe_share_token(share_token)?;
        let resp = finish("This link is invalid, has expired, or has no downloads left", self.agent.get(&self.url(&format!("/share/{share_token}/blob"))).call())?;
        read_body_bytes(resp)
    }

    pub fn delete_shared_file(&self, share_token: &str) -> Result<()> {
        assert_safe_share_token(share_token)?;
        finish("Couldn't delete this file", self.agent.delete(&self.url(&format!("/share/{share_token}"))).call())?;
        Ok(())
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
