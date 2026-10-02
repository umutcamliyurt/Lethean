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
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let files: Arc<Mutex<Vec<(String, Stored)>>> = Arc::default();
    let uploads_seen = Arc::new(AtomicUsize::new(0));
    let range_gets = Arc::new(AtomicUsize::new(0));
    let full_gets = Arc::new(AtomicUsize::new(0));
    let bytes_served = Arc::new(AtomicUsize::new(0));
    let failed_once = Arc::new(AtomicBool::new(false));
    let opts = Arc::new(opts);

    let server = Server { addr, files: Arc::clone(&files), uploads_seen: Arc::clone(&uploads_seen), range_gets: Arc::clone(&range_gets), full_gets: Arc::clone(&full_gets), bytes_served: Arc::clone(&bytes_served) };

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let files = Arc::clone(&files);
            let uploads_seen = Arc::clone(&uploads_seen);
            let range_gets = Arc::clone(&range_gets);
            let full_gets = Arc::clone(&full_gets);
            let bytes_served = Arc::clone(&bytes_served);
            let failed_once = Arc::clone(&failed_once);
            let opts = Arc::clone(&opts);
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

                    if method == "POST" && path == "/files" {
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
                        let id = path.trim_start_matches("/files/").trim_end_matches("/blob").to_string();
                        let stored = files.lock().unwrap().iter().find(|(i, _)| *i == id).map(|(_, s)| (s.blob.clone(), s.generator.clone(), s.blob_len));
                        let Some((blob, generator, blob_len)) = stored else {
                            let _ = respond(&mut writer, "404 Not Found", "", b"");
                            continue;
                        };
                        if let Some(gen) = generator {
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
                        let ranged = range.as_deref().and_then(|r| r.strip_prefix("bytes=")).and_then(|r| {
                            let (a, b) = r.split_once('-')?;
                            Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                        });
                        let result = match ranged {
                            Some((a, b)) if opts.support_range => {
                                range_gets.fetch_add(1, Ordering::SeqCst);
                                let b = b.min(blob.len() - 1);
                                let body = &blob[a..=b];
                                bytes_served.fetch_add(body.len(), Ordering::SeqCst);
                                respond(&mut writer, "206 Partial Content", &format!("Content-Range: bytes {a}-{b}/{}\r\n", blob.len()), body)
                            }
                            _ => {
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
                        let list = files.lock().unwrap();
                        let items: Vec<String> = list
                            .iter()
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
                    } else {
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
