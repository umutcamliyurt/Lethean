
use std::io::{self, Read, Write};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Result};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{aes_gcm_encrypt, pad_metadata_bytes, random_bytes, to_base64};
use crate::crypto::gcm_stream::{GcmDecryptReader, AUTH_FAILED};
use crate::types::{EncryptedHeader, FileMeta};

pub const CHUNK_SIZE: u64 = 32 * 1024 * 1024;
pub const TAG_LEN: u64 = 16;
pub const SEALED_CHUNK: u64 = CHUNK_SIZE + TAG_LEN;
pub const PREFIX_LEN: usize = 8;

pub const MIN_CHUNK: u64 = 1024;
pub const MAX_CHUNK: u64 = 256 * 1024 * 1024;

pub fn chunk_count(true_size: u64, chunk_size: u64) -> u64 {
    true_size.div_ceil(chunk_size).max(1)
}

pub fn sealed_len(true_size: u64, chunk_size: u64) -> u64 {
    chunk_count(true_size, chunk_size) * (chunk_size + TAG_LEN)
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm> {
    if key.len() != 32 {
        bail!("AES-256 key must be 32 bytes, got {}", key.len());
    }
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
}

pub fn nonce_for(prefix: &[u8], index: u64) -> io::Result<[u8; 12]> {
    if prefix.len() != PREFIX_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("chunked file has a {}-byte nonce prefix, expected {PREFIX_LEN}", prefix.len())));
    }
    let index = u32::try_from(index).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many chunks"))?;
    let mut n = [0u8; 12];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    Ok(n)
}

pub fn aad_for(index: u64, last: bool) -> [u8; 5] {
    let mut a = [0u8; 5];
    a[..4].copy_from_slice(&(index as u32).to_be_bytes());
    a[4] = last as u8;
    a
}

pub fn seal_chunk(key: &[u8], prefix: &[u8], index: u64, last: bool, buf: &mut Vec<u8>) -> io::Result<()> {
    let c = cipher(key).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let nonce = nonce_for(prefix, index)?;
    c.encrypt_in_place(Nonce::from_slice(&nonce), &aad_for(index, last), buf)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "AES-GCM encryption failed"))
}

pub fn open_chunk(key: &[u8], prefix: &[u8], index: u64, last: bool, buf: &mut Vec<u8>) -> io::Result<()> {
    let c = cipher(key).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let nonce = nonce_for(prefix, index)?;
    c.decrypt_in_place(Nonce::from_slice(&nonce), &aad_for(index, last), buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED))
}

pub struct ChunkedUploadPlan {
    pub file_key: Zeroizing<Vec<u8>>,
    pub prefix: Vec<u8>,
    pub plain_len: u64,
    pub header: EncryptedHeader,
}

impl ChunkedUploadPlan {
    pub fn body_len(&self) -> u64 {
        sealed_len(self.plain_len, CHUNK_SIZE)
    }
}

pub fn plan_chunked_upload(wrapping_key_raw: &[u8], name: &str, mime: &str, plain_size: u64, parent_id: Option<&str>) -> Result<ChunkedUploadPlan> {
    let file_key = Zeroizing::new(random_bytes(32));
    let prefix = random_bytes(PREFIX_LEN);

    let mut meta = FileMeta::new_file(name.to_string(), mime.to_string(), false, plain_size, parent_id.map(|s| s.to_string()));
    meta.chunk_size = Some(CHUNK_SIZE);
    let mut metadata_json = serde_json::to_vec(&meta)?;
    let mut metadata_bytes = pad_metadata_bytes(&metadata_json);
    metadata_json.zeroize();
    let meta_enc = aes_gcm_encrypt(&file_key, &metadata_bytes)?;
    metadata_bytes.zeroize();
    let key_wrap = aes_gcm_encrypt(wrapping_key_raw, &file_key)?;

    Ok(ChunkedUploadPlan {
        header: EncryptedHeader {
            content_iv: to_base64(&prefix),
            encrypted_metadata: to_base64(&meta_enc.ciphertext),
            metadata_iv: to_base64(&meta_enc.iv),
            wrapped_file_key: to_base64(&key_wrap.ciphertext),
            wrap_iv: to_base64(&key_wrap.iv),
        },
        file_key,
        prefix,
        plain_len: plain_size,
    })
}

pub struct ChunkedEncryptReader<R: Read> {
    source: R,
    key: Zeroizing<Vec<u8>>,
    prefix: Vec<u8>,
    plain_len: u64,
    count: u64,
    index: u64,
    buf: Zeroizing<Vec<u8>>,
    pos: usize,
}

impl<R: Read> ChunkedEncryptReader<R> {
    pub fn new(source: R, key: &[u8], prefix: &[u8], plain_len: u64) -> Self {
        Self { source, key: Zeroizing::new(key.to_vec()), prefix: prefix.to_vec(), plain_len, count: chunk_count(plain_len, CHUNK_SIZE), index: 0, buf: Zeroizing::new(Vec::new()), pos: 0 }
    }

    fn next_chunk(&mut self) -> io::Result<()> {
        let start = self.index * CHUNK_SIZE;
        let real = self.plain_len.saturating_sub(start).min(CHUNK_SIZE) as usize;
        self.buf.clear();
        self.buf.resize(CHUNK_SIZE as usize, 0);
        let mut got = 0;
        while got < real {
            match self.source.read(&mut self.buf[got..real]) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("the source ended after {} of {} bytes (the file changed while it was being uploaded?)", start + got as u64, self.plain_len)));
                }
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let last = self.index == self.count - 1;
        seal_chunk(&self.key, &self.prefix, self.index, last, &mut self.buf)?;
        self.index += 1;
        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for ChunkedEncryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.buf.len() {
            if self.index >= self.count {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

pub fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

pub fn decrypt_chunked<R: Read>(mut source: R, key: &[u8], prefix: &[u8], chunk_size: u64, true_size: u64, w: &mut dyn Write) -> io::Result<u64> {
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported chunk size {chunk_size}")));
    }
    let count = chunk_count(true_size, chunk_size);
    let sealed = chunk_size + TAG_LEN;
    let mut buf = Zeroizing::new(vec![0u8; 256 * 1024]);
    let mut written = 0u64;
    for index in 0..count {
        let nonce = nonce_for(prefix, index)?;
        let aad = aad_for(index, index == count - 1);
        let mut dec = GcmDecryptReader::with_aad((&mut source).take(sealed), key, &nonce, &aad).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let take = (true_size - written).min(chunk_size);
        let mut got = 0u64;
        loop {
            let n = read_full(&mut dec, &mut buf)?;
            if n == 0 {
                break;
            }
            let keep = (take.saturating_sub(got)).min(n as u64) as usize;
            if keep > 0 {
                w.write_all(&buf[..keep])?;
            }
            got += n as u64;
        }
        if got != chunk_size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "encrypted file ended in the middle of a chunk"));
        }
        written += take;
    }
    let mut probe = [0u8; 1];
    loop {
        match source.read(&mut probe) {
            Ok(0) => break,
            Ok(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const KEY: [u8; 32] = [3u8; 32];
    const PREFIX: [u8; 8] = [5u8; 8];
    const SMALL: u64 = 4096;

    fn seal_all(plain: &[u8], chunk: u64) -> Vec<u8> {
        let n = chunk_count(plain.len() as u64, chunk);
        let mut out = Vec::new();
        for i in 0..n {
            let s = (i * chunk) as usize;
            let mut b = plain[s.min(plain.len())..((i + 1) * chunk).min(plain.len() as u64) as usize].to_vec();
            b.resize(chunk as usize, 0);
            seal_chunk(&KEY, &PREFIX, i, i == n - 1, &mut b).unwrap();
            out.extend_from_slice(&b);
        }
        out
    }

    fn open_all(ct: &[u8], chunk: u64, size: u64) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt_chunked(Cursor::new(ct), &KEY, &PREFIX, chunk, size, &mut out)?;
        Ok(out)
    }

    #[test]
    fn round_trips_and_rejects_every_kind_of_tampering() {
        let plain: Vec<u8> = (0..(3 * SMALL + 77)).map(|i| (i * 7 % 251) as u8).collect();
        let ct = seal_all(&plain, SMALL);
        assert_eq!(ct.len() as u64, sealed_len(plain.len() as u64, SMALL));
        assert_eq!(open_all(&ct, SMALL, plain.len() as u64).unwrap(), plain);

        let s = (SMALL + TAG_LEN) as usize;
        let mut flipped = ct.clone();
        flipped[s + 10] ^= 1;
        let mut swapped = ct.clone();
        swapped[..s].copy_from_slice(&ct[s..2 * s]);
        swapped[s..2 * s].copy_from_slice(&ct[..s]);
        let dropped_last = ct[..3 * s].to_vec();
        let mut extended = ct.clone();
        extended.push(0);
        let mut dup = ct[..s].to_vec();
        dup.extend_from_slice(&ct[..s]);
        dup.extend_from_slice(&ct[2 * s..]);
        for (name, bad, size) in [("flip", &flipped, plain.len() as u64), ("swap", &swapped, plain.len() as u64), ("extend", &extended, plain.len() as u64), ("dup", &dup, plain.len() as u64)] {
            assert!(open_all(bad, SMALL, size).is_err(), "{name} accepted");
        }
        assert!(open_all(&dropped_last, SMALL, plain.len() as u64).is_err(), "truncation accepted");
        assert!(open_all(&dropped_last, SMALL, 3 * SMALL).is_err(), "dropping the last chunk and lying about the size accepted");
    }

    #[test]
    fn encrypt_reader_matches_chunk_by_chunk_sealing_and_is_deterministic() {
        let size = CHUNK_SIZE + 12345;
        let plain: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
        let read = || {
            let mut out = Vec::new();
            ChunkedEncryptReader::new(Cursor::new(&plain), &KEY, &PREFIX, size).read_to_end(&mut out).unwrap();
            out
        };
        let a = read();
        assert_eq!(a.len() as u64, sealed_len(size, CHUNK_SIZE));
        assert_eq!(a, read(), "retries must reproduce identical ciphertext");
        let mut back = Vec::new();
        decrypt_chunked(Cursor::new(&a), &KEY, &PREFIX, CHUNK_SIZE, size, &mut back).unwrap();
        assert!(back == plain);
    }

    #[test]
    fn a_short_source_is_an_error() {
        let mut r = ChunkedEncryptReader::new(Cursor::new(vec![1u8; 10]), &KEY, &PREFIX, 100);
        assert_eq!(r.read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn hostile_chunk_sizes_are_refused() {
        for cs in [0u64, 1, MAX_CHUNK + 1, u64::MAX] {
            assert!(decrypt_chunked(Cursor::new(Vec::<u8>::new()), &KEY, &PREFIX, cs, 10, &mut Vec::new()).is_err());
        }
    }
}
