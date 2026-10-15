
use std::io::{self, Read, Write};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Result};
use zeroize::Zeroizing;

use crate::crypto::aead::{encrypt_metadata, random_bytes, to_base64, wrap_file_key};
use crate::crypto::format::{ContentKey, FileFormat, FileKey, ParentRef, AAD_CHUNK_V2};
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

pub fn aad_for(format: FileFormat, index: u64, last: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_CHUNK_V2.len() + 5);
    if format == FileFormat::V2 {
        a.extend_from_slice(AAD_CHUNK_V2);
    }
    a.extend_from_slice(&(index as u32).to_be_bytes());
    a.push(last as u8);
    a
}

pub fn seal_chunk(key: &[u8], format: FileFormat, prefix: &[u8], index: u64, last: bool, buf: &mut Vec<u8>) -> io::Result<()> {
    let c = cipher(key).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let nonce = nonce_for(prefix, index)?;
    c.encrypt_in_place(Nonce::from_slice(&nonce), &aad_for(format, index, last), buf)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "AES-GCM encryption failed"))
}

pub fn open_chunk(key: &[u8], format: FileFormat, prefix: &[u8], index: u64, last: bool, buf: &mut Vec<u8>) -> io::Result<()> {
    let c = cipher(key).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let nonce = nonce_for(prefix, index)?;
    c.decrypt_in_place(Nonce::from_slice(&nonce), &aad_for(format, index, last), buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED))
}

pub fn check_filler(format: FileFormat, filler: &[u8]) -> io::Result<()> {
    if format == FileFormat::V2 && filler.iter().any(|&b| b != 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File is corrupt (padding)"));
    }
    Ok(())
}

pub struct ChunkedUploadPlan {
    pub content_key: ContentKey,
    pub prefix: Vec<u8>,
    pub plain_len: u64,
    pub header: EncryptedHeader,
}

impl ChunkedUploadPlan {
    pub fn body_len(&self) -> u64 {
        sealed_len(self.plain_len, CHUNK_SIZE)
    }
}

pub fn plan_chunked_upload(wrapping_key_raw: &[u8], name: &str, mime: &str, plain_size: u64, parent: Option<&ParentRef>, from: Option<&str>) -> Result<ChunkedUploadPlan> {
    if chunk_count(plain_size, CHUNK_SIZE) > u32::MAX as u64 {
        bail!("File is too large");
    }
    let file_key = FileKey::new_v2();
    let prefix = random_bytes(PREFIX_LEN);

    let mime = if mime.is_empty() || mime.encode_utf16().count() > 255 { "application/octet-stream" } else { mime };
    let name = if name.is_empty() { "Untitled" } else { name };
    let mut meta = FileMeta::new_file(name.to_string(), mime.to_string(), false, plain_size, parent);
    meta.chunk_size = Some(CHUNK_SIZE);
    meta.size = Some(plain_size);
    meta.from = from.map(|s| s.to_string());
    let (encrypted_metadata, metadata_iv) = encrypt_metadata(&file_key, &meta)?;
    let (wrapped_file_key, wrap_iv) = wrap_file_key(wrapping_key_raw, &file_key)?;

    Ok(ChunkedUploadPlan {
        header: EncryptedHeader { content_iv: to_base64(&prefix), encrypted_metadata, metadata_iv, wrapped_file_key, wrap_iv },
        content_key: file_key.content_key(),
        prefix,
        plain_len: plain_size,
    })
}

pub struct ChunkedEncryptReader<R: Read> {
    source: R,
    key: Zeroizing<Vec<u8>>,
    format: FileFormat,
    prefix: Vec<u8>,
    plain_len: u64,
    count: u64,
    index: u64,
    buf: Zeroizing<Vec<u8>>,
    pos: usize,
}

impl<R: Read> ChunkedEncryptReader<R> {
    pub fn new(source: R, key: &ContentKey, prefix: &[u8], plain_len: u64) -> Self {
        Self { source, key: key.key.clone(), format: key.format, prefix: prefix.to_vec(), plain_len, count: chunk_count(plain_len, CHUNK_SIZE), index: 0, buf: Zeroizing::new(Vec::new()), pos: 0 }
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
        seal_chunk(&self.key, self.format, &self.prefix, self.index, last, &mut self.buf)?;
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

pub fn decrypt_chunked<R: Read>(mut source: R, ck: &ContentKey, prefix: &[u8], chunk_size: u64, true_size: u64, w: &mut dyn Write) -> io::Result<u64> {
    let key: &[u8] = &ck.key;
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported chunk size {chunk_size}")));
    }
    let count = chunk_count(true_size, chunk_size);
    let sealed = chunk_size + TAG_LEN;
    let mut buf = Zeroizing::new(vec![0u8; 256 * 1024]);
    let mut written = 0u64;
    for index in 0..count {
        let nonce = nonce_for(prefix, index)?;
        let aad = aad_for(ck.format, index, index == count - 1);
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
            check_filler(ck.format, &buf[keep..n])?;
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

    fn ck(format: FileFormat) -> ContentKey {
        ContentKey { key: Zeroizing::new(KEY.to_vec()), format }
    }
    const PREFIX: [u8; 8] = [5u8; 8];
    const SMALL: u64 = 4096;

    fn seal_all(plain: &[u8], chunk: u64) -> Vec<u8> {
        let n = chunk_count(plain.len() as u64, chunk);
        let mut out = Vec::new();
        for i in 0..n {
            let s = (i * chunk) as usize;
            let mut b = plain[s.min(plain.len())..((i + 1) * chunk).min(plain.len() as u64) as usize].to_vec();
            b.resize(chunk as usize, 0);
            seal_chunk(&KEY, FileFormat::Legacy, &PREFIX, i, i == n - 1, &mut b).unwrap();
            out.extend_from_slice(&b);
        }
        out
    }

    fn open_all(ct: &[u8], chunk: u64, size: u64) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt_chunked(Cursor::new(ct), &ck(FileFormat::Legacy), &PREFIX, chunk, size, &mut out)?;
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
            ChunkedEncryptReader::new(Cursor::new(&plain), &ck(FileFormat::V2), &PREFIX, size).read_to_end(&mut out).unwrap();
            out
        };
        let a = read();
        assert_eq!(a.len() as u64, sealed_len(size, CHUNK_SIZE));
        assert_eq!(a, read(), "retries must reproduce identical ciphertext");
        let mut back = Vec::new();
        decrypt_chunked(Cursor::new(&a), &ck(FileFormat::V2), &PREFIX, CHUNK_SIZE, size, &mut back).unwrap();
        assert!(back == plain);
        assert!(decrypt_chunked(Cursor::new(&a), &ck(FileFormat::Legacy), &PREFIX, CHUNK_SIZE, size, &mut Vec::new()).is_err(), "v2 chunks must not open as legacy");
    }

    #[test]
    fn a_short_source_is_an_error() {
        let mut r = ChunkedEncryptReader::new(Cursor::new(vec![1u8; 10]), &ck(FileFormat::V2), &PREFIX, 100);
        assert_eq!(r.read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn v2_filler_must_be_zero() {
        let size = 100u64;
        let mut chunk = vec![0u8; SMALL as usize];
        chunk[size as usize..].fill(0);
        chunk[SMALL as usize - 1] = 7;
        seal_chunk(&KEY, FileFormat::V2, &PREFIX, 0, true, &mut chunk).unwrap();
        assert!(decrypt_chunked(Cursor::new(&chunk), &ck(FileFormat::V2), &PREFIX, SMALL, size, &mut Vec::new()).is_err());
    }

    #[test]
    fn hostile_chunk_sizes_are_refused() {
        for cs in [0u64, 1, MAX_CHUNK + 1, u64::MAX] {
            assert!(decrypt_chunked(Cursor::new(Vec::<u8>::new()), &ck(FileFormat::Legacy), &PREFIX, cs, 10, &mut Vec::new()).is_err());
        }
    }
}
