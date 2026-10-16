#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use lethean_fuse_lib::api::ApiClient;
use lethean_fuse_lib::vault::Vault;

pub type Generator = Arc<dyn Fn() -> Box<dyn Read + Send> + Send + Sync>;

#[derive(Clone)]
pub struct Stored {
    pub generator: Option<Generator>,
    pub fields: HashMap<String, String>,
    pub blob: Vec<u8>,
    pub blob_len: u64,
}

pub struct Server {
    pub addr: std::net::SocketAddr,
    pub files: Arc<Mutex<Vec<(String, Stored)>>>,
    pub uploads_seen: Arc<AtomicUsize>,
    pub range_gets: Arc<AtomicUsize>,
    pub full_gets: Arc<AtomicUsize>,
    pub bytes_served: Arc<AtomicUsize>,
    pub rotation: Arc<Mutex<Option<String>>>,
    pub parts_seen: Arc<AtomicUsize>,
    pub peak_parts_in_flight: Arc<AtomicUsize>,
}

struct PendingUpload {
    fields: HashMap<String, String>,
    part_count: usize,
    parts: HashMap<usize, Vec<u8>>,
}

pub struct ServerOpts {
    pub support_range: bool,
    pub fail_first_upload: bool,
    pub discard_blobs: bool,
}

fn read_line(r: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = String::new();
    match r.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end().to_string()),
    }
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_fields(head: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(head);
    let mut out = HashMap::new();
    for part in text.split("\r\n--").skip(0) {
        if let Some(i) = part.find("name=\"") {
            let rest = &part[i + 6..];
            if let Some(j) = rest.find('"') {
                let name = rest[..j].to_string();
                if let Some(k) = part.find("\r\n\r\n") {
                    let value = part[k + 4..].trim_end_matches("\r\n").to_string();
                    if name != "blob" {
                        out.insert(name, value);
                    }
                }
            }
        }
    }
    out
}

pub fn start_server(opts: ServerOpts) -> Server {
    start_server_ext(opts, false)
}

pub fn start_multipart_server(opts: ServerOpts) -> Server {
    start_server_ext(opts, true)
}

fn start_server_ext(opts: ServerOpts, multipart: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let files: Arc<Mutex<Vec<(String, Stored)>>> = Arc::default();
    let uploads_seen = Arc::new(AtomicUsize::new(0));
    let range_gets = Arc::new(AtomicUsize::new(0));
    let full_gets = Arc::new(AtomicUsize::new(0));
    let bytes_served = Arc::new(AtomicUsize::new(0));
    let rotation: Arc<Mutex<Option<String>>> = Arc::default();
    let failed_once = Arc::new(AtomicBool::new(false));
    let opts = Arc::new(opts);
    let parts_seen = Arc::new(AtomicUsize::new(0));
    let peak_parts_in_flight = Arc::new(AtomicUsize::new(0));
    let parts_in_flight = Arc::new(AtomicUsize::new(0));
    let pending: Arc<Mutex<HashMap<String, PendingUpload>>> = Arc::default();

    let server = Server { addr, files: Arc::clone(&files), uploads_seen: Arc::clone(&uploads_seen), range_gets: Arc::clone(&range_gets), full_gets: Arc::clone(&full_gets), bytes_served: Arc::clone(&bytes_served), rotation: Arc::clone(&rotation), parts_seen: Arc::clone(&parts_seen), peak_parts_in_flight: Arc::clone(&peak_parts_in_flight) };

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let _ = stream.set_nodelay(true);
            let files = Arc::clone(&files);
            let uploads_seen = Arc::clone(&uploads_seen);
            let range_gets = Arc::clone(&range_gets);
            let full_gets = Arc::clone(&full_gets);
            let bytes_served = Arc::clone(&bytes_served);
            let rotation = Arc::clone(&rotation);
            let failed_once = Arc::clone(&failed_once);
            let opts = Arc::clone(&opts);
            let parts_seen = Arc::clone(&parts_seen);
            let peak_parts_in_flight = Arc::clone(&peak_parts_in_flight);
            let parts_in_flight = Arc::clone(&parts_in_flight);
            let pending = Arc::clone(&pending);
            thread::spawn(move || {
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::with_capacity(64 * 1024, stream);
                loop {
                    let Some(request_line) = read_line(&mut reader) else { return };
                    if request_line.is_empty() {
                        return;
                    }
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let mut content_length = 0u64;
                    let mut content_type = String::new();
                    let mut range: Option<String> = None;
                    while let Some(h) = read_line(&mut reader) {
                        if h.is_empty() {
                            break;
                        }
                        let lower = h.to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            content_length = v.trim().parse().unwrap_or(0);
                        } else if lower.starts_with("content-type:") {
                            content_type = h[13..].trim().to_string();
                        } else if let Some(v) = lower.strip_prefix("range:") {
                            range = Some(v.trim().to_string());
                        }
                    }

                    let respond = |w: &mut TcpStream, status: &str, extra: &str, body: &[u8]| -> io::Result<()> {
                        write!(w, "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{extra}\r\n", body.len())?;
                        w.write_all(body)?;
                        w.flush()
                    };

                    if multipart && path.starts_with("/files/uploads") {
                        let mut body = vec![0u8; content_length as usize];
                        if reader.read_exact(&mut body).is_err() {
                            return;
                        }
                        let rest = path.trim_start_matches("/files/uploads").trim_start_matches('/');
                        let segs: Vec<&str> = rest.split('/').collect();
                        let reply = if method == "POST" && rest.is_empty() {
                            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                            let mut fields = HashMap::new();
                            for k in ["content_iv", "encrypted_metadata", "metadata_iv", "wrapped_file_key", "wrap_iv"] {
                                fields.insert(k.to_string(), v[k].as_str().unwrap().to_string());
                            }
                            let id = format!("up{:030}", uploads_seen.fetch_add(1, Ordering::SeqCst));
                            pending.lock().unwrap().insert(id.clone(), PendingUpload { fields, part_count: v["part_count"].as_u64().unwrap() as usize, parts: HashMap::new() });
                            ("200 OK", format!(r#"{{"upload_id":"{id}"}}"#))
                        } else if method == "PUT" && segs.len() == 3 && segs[1] == "parts" {
                            let now = parts_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                            peak_parts_in_flight.fetch_max(now, Ordering::SeqCst);
                            thread::sleep(std::time::Duration::from_millis(150));
                            parts_in_flight.fetch_sub(1, Ordering::SeqCst);
                            parts_seen.fetch_add(1, Ordering::SeqCst);
                            let n: usize = segs[2].parse().unwrap();
                            if let Some(u) = pending.lock().unwrap().get_mut(segs[0]) {
                                u.parts.insert(n, body);
                            }
                            ("200 OK", "{}".to_string())
                        } else if method == "POST" && segs.len() == 2 && segs[1] == "complete" {
                            let u = pending.lock().unwrap().remove(segs[0]).unwrap();
                            assert_eq!(u.parts.len(), u.part_count, "every part must arrive before complete");
                            let mut blob = Vec::new();
                            for i in 0..u.part_count {
                                blob.extend_from_slice(&u.parts[&i]);
                            }
                            let blob_len = blob.len() as u64;
                            let id = format!("file{:028}", uploads_seen.fetch_add(1, Ordering::SeqCst) + 1);
                            let f = &u.fields;
                            let json = format!(
                                r#"{{"id":"{id}","content_iv":"{}","encrypted_metadata":"{}","metadata_iv":"{}","wrapped_file_key":"{}","wrap_iv":"{}","size":{blob_len}}}"#,
                                f["content_iv"], f["encrypted_metadata"], f["metadata_iv"], f["wrapped_file_key"], f["wrap_iv"]
                            );
                            files.lock().unwrap().push((id, Stored { generator: None, fields: u.fields, blob, blob_len }));
                            ("200 OK", json)
                        } else if method == "DELETE" {
                            pending.lock().unwrap().remove(segs[0]);
                            ("200 OK", "{}".to_string())
                        } else {
                            ("404 Not Found", String::new())
                        };
                        if respond(&mut writer, reply.0, "", reply.1.as_bytes()).is_err() {
                            return;
                        }
                    } else if method == "POST" && path == "/files" {
                        let n = uploads_seen.fetch_add(1, Ordering::SeqCst);
                        let boundary = content_type.split("boundary=").nth(1).unwrap_or("").to_string();
                        let tail_len = format!("\r\n--{boundary}--\r\n").len() as u64;

                        let mut head = Vec::new();
                        let mut consumed = 0u64;
                        let mut byte = [0u8; 1];
                        loop {
                            if reader.read_exact(&mut byte).is_err() {
                                return;
                            }
                            head.push(byte[0]);
                            consumed += 1;
                            if let Some(i) = find(&head, b"name=\"blob\"") {
                                if find(&head[i..], b"\r\n\r\n").is_some() {
                                    break;
                                }
                            }
                        }
                        let fields = parse_fields(&head);
                        let blob_len = content_length - consumed - tail_len;

                        if opts.fail_first_upload && n == 0 && !failed_once.swap(true, Ordering::SeqCst) {
                            let mut sink = vec![0u8; (blob_len / 2) as usize];
                            let _ = reader.read_exact(&mut sink);
                            return;
                        }

                        let mut blob = Vec::new();
                        let mut remaining = blob_len;
                        let mut chunk = vec![0u8; 64 * 1024];
                        while remaining > 0 {
                            let take = remaining.min(chunk.len() as u64) as usize;
                            if reader.read_exact(&mut chunk[..take]).is_err() {
                                return;
                            }
                            if !opts.discard_blobs {
                                blob.extend_from_slice(&chunk[..take]);
                            }
                            remaining -= take as u64;
                        }
                        let mut tail = vec![0u8; tail_len as usize];
                        if reader.read_exact(&mut tail).is_err() {
                            return;
                        }

                        let id = format!("file{:028}", uploads_seen.load(Ordering::SeqCst));
                        let json = format!(
                            r#"{{"id":"{id}","content_iv":"{}","encrypted_metadata":"{}","metadata_iv":"{}","wrapped_file_key":"{}","wrap_iv":"{}","size":{blob_len}}}"#,
                            fields["content_iv"], fields["encrypted_metadata"], fields["metadata_iv"], fields["wrapped_file_key"], fields["wrap_iv"]
                        );
                        files.lock().unwrap().push((id, Stored { generator: None, fields, blob, blob_len }));
                        if respond(&mut writer, "200 OK", "", json.as_bytes()).is_err() {
                            return;
                        }
                    } else if method == "GET" && path.starts_with("/files") && path.ends_with("/blob") {
                        if let Some(ms) = std::env::var("MOCK_BLOB_DELAY_MS").ok().and_then(|v| v.parse::<u64>().ok()) {
                            thread::sleep(std::time::Duration::from_millis(ms));
                        }
                        let id = path.trim_start_matches("/files/").trim_end_matches("/blob").to_string();
                        let ranged = range.as_deref().and_then(|r| r.strip_prefix("bytes=")).and_then(|r| {
                            let (a, b) = r.split_once('-')?;
                            Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                        });
                        enum Plan {
                            Missing,
                            Virtual(Generator, u64),
                            Partial(Vec<u8>, usize, usize, usize),
                            Full(Vec<u8>),
                        }
                        let plan = {
                            let files = files.lock().unwrap();
                            match files.iter().find(|(i, _)| *i == id).map(|(_, s)| s) {
                                None => Plan::Missing,
                                Some(s) if s.generator.is_some() => Plan::Virtual(s.generator.clone().unwrap(), s.blob_len),
                                Some(s) => match ranged {
                                    Some((a, b)) if opts.support_range && a < s.blob.len() => {
                                        let b = b.min(s.blob.len() - 1);
                                        Plan::Partial(s.blob[a..=b].to_vec(), a, b, s.blob.len())
                                    }
                                    _ => Plan::Full(s.blob.clone()),
                                },
                            }
                        };
                        let result = match plan {
                            Plan::Missing => {
                                let _ = respond(&mut writer, "404 Not Found", "", b"");
                                continue;
                            }
                            Plan::Virtual(gen, blob_len) => {
                                full_gets.fetch_add(1, Ordering::SeqCst);
                                if write!(writer, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {blob_len}\r\n\r\n").is_err() {
                                    return;
                                }
                                let mut src = gen();
                                let mut buf = vec![0u8; 64 * 1024];
                                loop {
                                    let n = match src.read(&mut buf) {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => n,
                                    };
                                    if writer.write_all(&buf[..n]).is_err() {
                                        return;
                                    }
                                    bytes_served.fetch_add(n, Ordering::SeqCst);
                                }
                                let _ = writer.flush();
                                continue;
                            }
                            Plan::Partial(body, a, b, total) => {
                                range_gets.fetch_add(1, Ordering::SeqCst);
                                bytes_served.fetch_add(body.len(), Ordering::SeqCst);
                                respond(&mut writer, "206 Partial Content", &format!("Content-Range: bytes {a}-{b}/{total}\r\n"), &body)
                            }
                            Plan::Full(blob) => {
                                full_gets.fetch_add(1, Ordering::SeqCst);
                                bytes_served.fetch_add(blob.len(), Ordering::SeqCst);
                                respond(&mut writer, "200 OK", "", &blob)
                            }
                        };
                        if result.is_err() {
                            return;
                        }
                    } else if method == "DELETE" && path.starts_with("/files/") {
                        let id = path.trim_start_matches("/files/").to_string();
                        files.lock().unwrap().retain(|(i, _)| *i != id);
                        if respond(&mut writer, "200 OK", "", b"{}").is_err() {
                            return;
                        }
                    } else if method == "GET" && path.starts_with("/files") {
                        let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
                        let param = |k: &str| query.split('&').find_map(|kv| kv.strip_prefix(k).and_then(|v| v.strip_prefix('='))).and_then(|v| v.parse::<usize>().ok());
                        let (offset, limit) = (param("offset").unwrap_or(0), param("limit").unwrap_or(usize::MAX));
                        let list = files.lock().unwrap();
                        let items: Vec<String> = list
                            .iter()
                            .skip(offset)
                            .take(limit)
                            .map(|(id, s)| {
                                format!(
                                    r#"{{"id":"{id}","content_iv":"{}","encrypted_metadata":"{}","metadata_iv":"{}","wrapped_file_key":"{}","wrap_iv":"{}","size":{}}}"#,
                                    s.fields["content_iv"], s.fields["encrypted_metadata"], s.fields["metadata_iv"], s.fields["wrapped_file_key"], s.fields["wrap_iv"], s.blob_len
                                )
                            })
                            .collect();
                        let body = format!("[{}]", items.join(","));
                        drop(list);
                        if respond(&mut writer, "200 OK", "", body.as_bytes()).is_err() {
                            return;
                        }
                    } else if method == "POST" && path == "/vault/rotate" {
                        let mut body = vec![0u8; content_length as usize];
                        if reader.read_exact(&mut body).is_err() {
                            return;
                        }
                        let text = String::from_utf8_lossy(&body).to_string();
                        let n = text.matches("\"file_id\"").count();
                        *rotation.lock().unwrap() = Some(text);
                        let json = format!(r#"{{"files_moved":{n},"tokens_rebound":0}}"#);
                        if respond(&mut writer, "200 OK", "", json.as_bytes()).is_err() {
                            return;
                        }
                    } else {
                        if content_length > 0 && content_length < 1 << 20 {
                            let mut sink = vec![0u8; content_length as usize];
                            let _ = reader.read_exact(&mut sink);
                        }
                        let _ = respond(&mut writer, "404 Not Found", "", b"");
                    }
                }
            });
        }
    });
    server
}

pub fn pattern_byte(i: u64) -> u8 {
    let x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (x >> 56) as u8 ^ (i as u8)
}

pub struct PatternReader {
    pos: u64,
    len: u64,
    started: Arc<AtomicUsize>,
}

impl PatternReader {
    pub fn new(len: u64, started: Arc<AtomicUsize>) -> Self {
        started.fetch_add(1, Ordering::SeqCst);
        Self { pos: 0, len, started }
    }
}

impl Read for PatternReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let _ = &self.started;
        let n = out.len().min((self.len - self.pos) as usize);
        for (k, b) in out[..n].iter_mut().enumerate() {
            *b = pattern_byte(self.pos + k as u64);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

pub fn new_vault(addr: std::net::SocketAddr, key: &[u8]) -> Vault {
    let api = ApiClient::new(format!("http://{addr}")).expect("client");
    api.set_vault_id(Some("test-vault".to_string()));
    Vault::new(api, key.to_vec())
}

pub fn expected(offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64).map(|k| pattern_byte(offset + k)).collect()
}


pub fn inject(server: &Server, fields: [(&str, String); 5], blob: Vec<u8>) -> String {
    let mut map = HashMap::new();
    for (k, v) in fields {
        map.insert(k.to_string(), v);
    }
    let mut files = server.files.lock().unwrap();
    let id = format!("inj{:029}", files.len() + 1000);
    let blob_len = blob.len() as u64;
    files.push((id.clone(), Stored { generator: None, fields: map, blob, blob_len }));
    id
}

pub fn inject_virtual(server: &Server, fields: [(&str, String); 5], blob_len: u64, generator: Generator) -> String {
    let mut map = HashMap::new();
    for (k, v) in fields {
        map.insert(k.to_string(), v);
    }
    let mut files = server.files.lock().unwrap();
    let id = format!("vir{:029}", files.len() + 2000);
    files.push((id.clone(), Stored { generator: Some(generator), fields: map, blob: Vec::new(), blob_len }));
    id
}
