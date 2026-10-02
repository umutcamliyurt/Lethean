
use std::io::{self, Read};

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::Aes256;
use anyhow::{bail, Result};
use ctr::Ctr32BE;
use ghash::universal_hash::UniversalHash;
use ghash::GHash;
use zeroize::Zeroize;

pub const TAG_LEN: usize = 16;
pub const IV_LEN: usize = 12;

pub const STREAM_THRESHOLD: u64 = 4 * 1024 * 1024;

const IO_BUF: usize = 64 * 1024;

pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - len.leading_zeros() as u64;
    let s = 64 - e.leading_zeros() as u64;
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    (len + mask) & !mask
}

struct GcmState {
    ctr: Ctr32BE<Aes256>,
    ghash: GHash,
    tag_mask: [u8; 16],
    pending: [u8; 16],
    pending_len: usize,
    ct_len: u64,
}

impl GcmState {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            bail!("AES-256 key must be 32 bytes, got {}", key.len());
        }
        if iv.len() != IV_LEN {
            bail!("invalid AES-GCM nonce: expected {IV_LEN} bytes, got {}", iv.len());
        }
        let cipher = Aes256::new(key.into());

        let mut h = [0u8; 16];
        cipher.encrypt_block((&mut h).into());

        let mut j0 = [0u8; 16];
        j0[..IV_LEN].copy_from_slice(iv);
        j0[15] = 1;
        let mut tag_mask = j0;
        cipher.encrypt_block((&mut tag_mask).into());

        let mut first = j0;
        first[15] = 2;
        let ctr = Ctr32BE::<Aes256>::new(key.into(), (&first).into());

        let ghash = GHash::new((&h).into());
        h.zeroize();
        Ok(Self { ctr, ghash, tag_mask, pending: [0; 16], pending_len: 0, ct_len: 0 })
    }

    fn absorb(&mut self, mut ct: &[u8]) {
        self.ct_len += ct.len() as u64;
        if self.pending_len > 0 {
            let take = (16 - self.pending_len).min(ct.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&ct[..take]);
            self.pending_len += take;
            ct = &ct[take..];
            if self.pending_len == 16 {
                let block = self.pending;
                self.ghash.update_padded(&block);
                self.pending_len = 0;
            } else {
                return;
            }
        }
        let whole = ct.len() / 16 * 16;
        if whole > 0 {
            self.ghash.update_padded(&ct[..whole]);
        }
        let rest = &ct[whole..];
        self.pending[..rest.len()].copy_from_slice(rest);
        self.pending_len = rest.len();
    }

    fn finish(mut self) -> [u8; 16] {
        if self.pending_len > 0 {
            let n = self.pending_len;
            let block = self.pending;
            self.ghash.update_padded(&block[..n]);
        }
        let mut lens = [0u8; 16];
        lens[8..].copy_from_slice(&(self.ct_len * 8).to_be_bytes());
        self.ghash.update_padded(&lens);
        let g = self.ghash.finalize();
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = g[i] ^ self.tag_mask[i];
        }
        self.tag_mask.zeroize();
        tag
    }
}

pub struct GcmEncryptReader<R: Read> {
    source: R,
    state: Option<GcmState>,
    plain_len: u64,
    padded_len: u64,
    consumed: u64,
    out: Vec<u8>,
    out_pos: usize,
    tag: Option<[u8; 16]>,
    tag_pos: usize,
}

impl<R: Read> GcmEncryptReader<R> {
    pub fn new(source: R, key: &[u8], iv: &[u8], plain_len: u64, padded_len: u64) -> Result<Self> {
        if padded_len < plain_len {
            bail!("padded length is smaller than the plaintext");
        }
        Ok(Self { source, state: Some(GcmState::new(key, iv)?), plain_len, padded_len, consumed: 0, out: Vec::new(), out_pos: 0, tag: None, tag_pos: 0 })
    }

    pub fn encrypted_len(padded_len: u64) -> u64 {
        padded_len + TAG_LEN as u64
    }

    fn refill(&mut self) -> io::Result<()> {
        let state = self.state.as_mut().expect("state present until the tag is produced");
        let want = (self.padded_len - self.consumed).min(IO_BUF as u64) as usize;
        self.out.clear();
        self.out.resize(want, 0);
        self.out_pos = 0;

        let real = (self.plain_len.saturating_sub(self.consumed)).min(want as u64) as usize;
        let mut got = 0;
        while got < real {
            match self.source.read(&mut self.out[got..real]) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("the source ended after {} of {} bytes (the file changed while it was being uploaded?)", self.consumed + got as u64, self.plain_len)));
                }
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        state.ctr.apply_keystream(&mut self.out);
        state.absorb(&self.out);
        self.consumed += want as u64;
        Ok(())
    }
}

impl<R: Read> Read for GcmEncryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.out_pos < self.out.len() {
                let n = (self.out.len() - self.out_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }
            if self.consumed < self.padded_len {
                self.refill()?;
                continue;
            }
            if self.tag.is_none() {
                self.tag = Some(self.state.take().expect("state present").finish());
            }
            let tag = self.tag.as_ref().unwrap();
            if self.tag_pos >= TAG_LEN {
                return Ok(0);
            }
            let n = (TAG_LEN - self.tag_pos).min(buf.len());
            buf[..n].copy_from_slice(&tag[self.tag_pos..self.tag_pos + n]);
            self.tag_pos += n;
            return Ok(n);
        }
    }
}

pub struct GcmDecryptReader<R: Read> {
    source: R,
    state: Option<GcmState>,
    held: Vec<u8>,
    ready: Vec<u8>,
    ready_pos: usize,
    eof: bool,
    done: bool,
    failed: bool,
}

pub const AUTH_FAILED: &str = "AES-GCM decryption failed (wrong key, or corrupted/tampered data)";

impl<R: Read> GcmDecryptReader<R> {
    pub fn new(source: R, key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self { source, state: Some(GcmState::new(key, iv)?), held: Vec::with_capacity(IO_BUF + TAG_LEN), ready: Vec::new(), ready_pos: 0, eof: false, done: false, failed: false })
    }

    fn fill(&mut self) -> io::Result<()> {
        if !self.eof {
            let mut tmp = [0u8; IO_BUF];
            loop {
                match self.source.read(&mut tmp) {
                    Ok(0) => self.eof = true,
                    Ok(n) => self.held.extend_from_slice(&tmp[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                break;
            }
        }
        if self.held.len() > TAG_LEN {
            let n = self.held.len() - TAG_LEN;
            self.ready.clear();
            self.ready.extend_from_slice(&self.held[..n]);
            self.held.drain(..n);
            let state = self.state.as_mut().expect("state present until verified");
            state.absorb(&self.ready);
            state.ctr.apply_keystream(&mut self.ready);
            self.ready_pos = 0;
        } else if self.eof {
            self.ready.clear();
            self.ready_pos = 0;
            self.verify()?;
        }
        Ok(())
    }

    fn verify(&mut self) -> io::Result<()> {
        if self.held.len() != TAG_LEN {
            self.failed = true;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "encrypted data is too short to contain an authentication tag"));
        }
        let expected = self.state.take().expect("state present").finish();
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(self.held.iter()) {
            diff |= a ^ b;
        }
        self.done = true;
        if diff != 0 {
            self.failed = true;
            return Err(io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED));
        }
        Ok(())
    }
}

impl<R: Read> Read for GcmDecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.ready_pos < self.ready.len() {
                let n = (self.ready.len() - self.ready_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.ready[self.ready_pos..self.ready_pos + n]);
                self.ready_pos += n;
                return Ok(n);
            }
            if self.failed {
                return Err(io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED));
            }
            if self.done {
                return Ok(0);
            }
            self.fill()?;
            if self.done && self.ready_pos >= self.ready.len() {
                return Ok(0);
            }
        }
    }
}

impl<R: Read> Drop for GcmDecryptReader<R> {
    fn drop(&mut self) {
        self.ready.zeroize();
        self.held.zeroize();
    }
}

impl<R: Read> Drop for GcmEncryptReader<R> {
    fn drop(&mut self) {
        self.out.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use std::io::Cursor;

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) ^ (i >> 7)) as u8).collect()
    }

    struct Dribble<R: Read>(R, usize);
    impl<R: Read> Read for Dribble<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.1 = self.1 % 13 + 1;
            let n = buf.len().min(self.1);
            self.0.read(&mut buf[..n])
        }
    }

    const KEY: [u8; 32] = [7u8; 32];
    const IV: [u8; 12] = [9u8; 12];

    fn reference_encrypt(plain_padded: &[u8]) -> Vec<u8> {
        Aes256Gcm::new((&KEY).into()).encrypt(Nonce::from_slice(&IV), Payload { msg: plain_padded, aad: &[] }).unwrap()
    }

    #[test]
    fn padme_matches_the_reference_and_never_shrinks() {
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(9), 10);
        assert_eq!(padme(1000), 1024);
        for n in [2u64, 3, 100, 4_194_304, 4_194_305, 9_437_307, 1 << 40] {
            let p = padme(n);
            assert!(p >= n);
            assert!((p - n) as f64 <= 0.125 * n as f64, "padme({n}) = {p} overshoots 12.5%");
        }
    }

    #[test]
    fn encrypt_matches_the_aes_gcm_crate_byte_for_byte() {
        for &(plain, padded) in &[(0usize, 0usize), (1, 1), (15, 16), (16, 16), (17, 40), (1000, 1000), (65_535, 65_536), (65_536, 65_537), (200_001, 262_144)] {
            let mut full = data(plain);
            full.resize(padded, 0);
            let want = reference_encrypt(&full);

            let src = Dribble(Cursor::new(data(plain)), 0);
            let mut enc = GcmEncryptReader::new(src, &KEY, &IV, plain as u64, padded as u64).unwrap();
            let mut got = Vec::new();
            enc.read_to_end(&mut got).unwrap();
            assert_eq!(got.len() as u64, GcmEncryptReader::<Cursor<Vec<u8>>>::encrypted_len(padded as u64));
            assert_eq!(got, want, "plain {plain} padded {padded}");
        }
    }

    #[test]
    fn decrypt_reads_what_the_aes_gcm_crate_wrote() {
        for &n in &[0usize, 1, 15, 16, 17, 31, 32, 33, 4095, 4096, 4097, 70_000, 300_001] {
            let ct = reference_encrypt(&data(n));
            let mut dec = GcmDecryptReader::new(Dribble(Cursor::new(ct), 3), &KEY, &IV).unwrap();
            let mut got = Vec::new();
            dec.read_to_end(&mut got).unwrap();
            assert_eq!(got, data(n), "len {n}");
        }
    }

    #[test]
    fn tampering_truncation_and_wrong_key_are_detected_at_eof() {
        let ct = reference_encrypt(&data(100_000));

        let mut bad = ct.clone();
        bad[50_000] ^= 1;
        let mut dec = GcmDecryptReader::new(Cursor::new(bad), &KEY, &IV).unwrap();
        assert_eq!(dec.read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::InvalidData);

        let mut bad_tag = ct.clone();
        *bad_tag.last_mut().unwrap() ^= 0x80;
        let mut dec = GcmDecryptReader::new(Cursor::new(bad_tag), &KEY, &IV).unwrap();
        assert!(dec.read_to_end(&mut Vec::new()).is_err());

        let truncated = ct[..ct.len() - 1].to_vec();
        let mut dec = GcmDecryptReader::new(Cursor::new(truncated), &KEY, &IV).unwrap();
        assert!(dec.read_to_end(&mut Vec::new()).is_err());

        let mut dec = GcmDecryptReader::new(Cursor::new(ct.clone()), &[8u8; 32], &IV).unwrap();
        assert!(dec.read_to_end(&mut Vec::new()).is_err());

        let mut dec = GcmDecryptReader::new(Cursor::new(vec![1u8; 10]), &KEY, &IV).unwrap();
        assert!(dec.read_to_end(&mut Vec::new()).is_err(), "shorter than a tag");

        let mut bad_again = ct.clone();
        bad_again[3] ^= 1;
        let mut dec = GcmDecryptReader::new(Cursor::new(bad_again), &KEY, &IV).unwrap();
        assert!(dec.read_to_end(&mut Vec::new()).is_err());
        assert!(dec.read(&mut [0u8; 8]).is_err());

        let mut ok = GcmDecryptReader::new(Cursor::new(ct), &KEY, &IV).unwrap();
        ok.read_to_end(&mut Vec::new()).unwrap();
        assert_eq!(ok.read(&mut [0u8; 8]).unwrap(), 0);
    }

    #[test]
    fn our_ciphertext_opens_with_the_aes_gcm_crate() {
        let plain = data(150_000);
        let padded = padme(plain.len() as u64);
        let mut enc = GcmEncryptReader::new(Cursor::new(plain.clone()), &KEY, &IV, plain.len() as u64, padded).unwrap();
        let mut ct = Vec::new();
        enc.read_to_end(&mut ct).unwrap();
        let opened = Aes256Gcm::new((&KEY).into()).decrypt(Nonce::from_slice(&IV), Payload { msg: &ct, aad: &[] }).unwrap();
        assert_eq!(&opened[..plain.len()], &plain[..]);
        assert!(opened[plain.len()..].iter().all(|&b| b == 0));
        assert_eq!(opened.len() as u64, padded);
    }

    #[test]
    fn a_short_source_is_an_error_not_silent_padding() {
        let mut enc = GcmEncryptReader::new(Cursor::new(data(50)), &KEY, &IV, 100, 128).unwrap();
        assert_eq!(enc.read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn restarting_from_a_fresh_reader_gives_identical_bytes() {
        let run = || {
            let mut e = GcmEncryptReader::new(Cursor::new(data(90_000)), &KEY, &IV, 90_000, padme(90_000)).unwrap();
            let mut v = Vec::new();
            e.read_to_end(&mut v).unwrap();
            v
        };
        assert_eq!(run(), run());
    }
}
