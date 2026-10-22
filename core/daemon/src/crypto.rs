//! Cryptographic core: a Noise_IK handshake (X25519 + ChaCha20-Poly1305 +
//! BLAKE2s) implemented from the Noise Protocol Framework specification,
//! plus the transport session with replay protection.
//!
//! Protocol name: Noise_IK_25519_ChaChaPoly_Blake2s
//!   IK pattern:  -> e, es, s, ss
//!                <- e, ee, se
//! The initiator must know the responder's static public key in advance
//! (in KronosMesh it comes from the control plane's peer list).

use anyhow::{anyhow, Context, Result};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub const HASH_LEN: usize = 32;
const BLOCK_LEN: usize = 64; // BLAKE2s block size
const PROTOCOL_NAME: &str = "Noise_IK_25519_ChaChaPoly_Blake2s";

// ---------------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------------

pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex string has odd length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16)
            .with_context(|| format!("invalid hex at offset {i}"))?);
    }
    Ok(out)
}

/// Node identity fingerprint: BLAKE2b-256 of the X25519 public key.
/// Computed identically by the Go control plane (x/crypto/blake2b).
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(public_key);
    hex_encode(&hasher.finalize())
}

fn hash256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

// ---------------------------------------------------------------------------
// HMAC-BLAKE2s + HKDF-BLAKE2s (RFC 2104 / RFC 5869 constructions)
// ---------------------------------------------------------------------------

pub fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let hashed = hash256(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

pub fn hkdf_blake2s(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let zero_salt = [0u8; 32];
    let salt = if salt.is_empty() { &zero_salt } else { salt };
    let prk = hmac_blake2s(salt, ikm);
    let mut okm = Vec::with_capacity(okm_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < okm_len {
        let mut msg = t.clone();
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_blake2s(&prk, &msg).to_vec();
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(okm_len);
    okm
}

// ---------------------------------------------------------------------------
// Noise symmetric state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    k: Option<[u8; 32]>,
    n: u64,
}

impl SymmetricState {
    fn initialize(protocol_name: &str) -> Self {
        let h = if protocol_name.len() <= HASH_LEN {
            let mut buf = [0u8; 32];
            buf[..protocol_name.len()].copy_from_slice(protocol_name.as_bytes());
            buf
        } else {
            hash256(protocol_name.as_bytes())
        };
        Self { ck: h, h, k: None, n: 0 }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        let out = hasher.finalize();
        self.h.copy_from_slice(&out);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let out = hkdf_blake2s(&self.ck, ikm, &[], 64);
        self.ck.copy_from_slice(&out[..32]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&out[32..64]);
        self.k = Some(key);
        self.n = 0;
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = match self.k {
            Some(key) => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
                let mut nonce = [0u8; 12];
                nonce[4..].copy_from_slice(&self.n.to_le_bytes());
                let ct = cipher
                    .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &self.h })
                    .map_err(|_| anyhow!("handshake encryption failed"))?;
                self.n += 1;
                ct
            }
            None => plaintext.to_vec(),
        };
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = match self.k {
            Some(key) => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
                let mut nonce = [0u8; 12];
                nonce[4..].copy_from_slice(&self.n.to_le_bytes());
                let pt = cipher
                    .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &self.h })
                    .map_err(|_| anyhow!("handshake decryption failed (bad key or tampered message)"))?;
                self.n += 1;
                pt
            }
            None => ciphertext.to_vec(),
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(&self) -> ([u8; 32], [u8; 32]) {
        let out = hkdf_blake2s(&self.ck, &[], &[], 64);
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&out[..32]);
        k2.copy_from_slice(&out[32..64]);
        (k1, k2)
    }
}

// ---------------------------------------------------------------------------
// Noise_IK handshake
// ---------------------------------------------------------------------------

pub struct HandshakeInitiator {
    state: SymmetricState,
    ephemeral: StaticSecret,
    static_secret: StaticSecret,
    remote_static: PublicKey,
}

pub struct HandshakeResponder {
    state: SymmetricState,
    static_secret: StaticSecret,
    remote_ephemeral: Option<PublicKey>,
    remote_static: Option<PublicKey>,
}

fn init_state(remote_static: &PublicKey) -> SymmetricState {
    let mut state = SymmetricState::initialize(PROTOCOL_NAME);
    state.mix_hash(&[]); // empty prologue
    state.mix_hash(remote_static.as_bytes()); // pre-message: responder static
    state
}

impl HandshakeInitiator {
    pub fn new(static_secret: StaticSecret, remote_static: PublicKey) -> Self {
        Self {
            state: init_state(&remote_static),
            ephemeral: StaticSecret::random_from_rng(rand_core::OsRng),
            static_secret,
            remote_static,
        }
    }

    /// Message 1: e || enc(s) || enc(payload). 32 + 48 + payload+16 bytes.
    pub fn write_message1(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let e_pub = PublicKey::from(&self.ephemeral);
        let mut msg = Vec::with_capacity(32 + 48 + payload.len() + 16);
        msg.extend_from_slice(e_pub.as_bytes());
        self.state.mix_hash(e_pub.as_bytes());
        let es: SharedSecret = self.ephemeral.diffie_hellman(&self.remote_static);
        self.state.mix_key(es.as_bytes());
        let s_pub = PublicKey::from(&self.static_secret);
        let enc_s = self.state.encrypt_and_hash(s_pub.as_bytes())?;
        msg.extend_from_slice(&enc_s);
        let ss: SharedSecret = self.static_secret.diffie_hellman(&self.remote_static);
        self.state.mix_key(ss.as_bytes());
        let enc_payload = self.state.encrypt_and_hash(payload)?;
        msg.extend_from_slice(&enc_payload);
        Ok(msg)
    }

    /// Consumes the handshake; returns the established transport session.
    pub fn read_message2(mut self, msg: &[u8]) -> Result<Session> {
        if msg.len() < 32 + 16 {
            return Err(anyhow!("handshake message 2 too short"));
        }
        let e_pub_bytes: [u8; 32] = msg[..32].try_into().unwrap();
        let remote_eph = PublicKey::from(e_pub_bytes);
        self.state.mix_hash(&e_pub_bytes);
        let ee: SharedSecret = self.ephemeral.diffie_hellman(&remote_eph);
        self.state.mix_key(ee.as_bytes());
        let se: SharedSecret = self.static_secret.diffie_hellman(&remote_eph);
        self.state.mix_key(se.as_bytes());
        let _payload = self.state.decrypt_and_hash(&msg[32..])?;
        let (k1, k2) = self.state.split();
        Ok(Session::new(k1, k2, true))
    }
}

impl HandshakeResponder {
    pub fn new(static_secret: StaticSecret) -> Self {
        let remote_static = PublicKey::from(&static_secret);
        Self {
            state: init_state(&remote_static),
            static_secret,
            remote_ephemeral: None,
            remote_static: None,
        }
    }

    /// Reads message 1; returns (payload, initiator static public key).
    pub fn read_message1(&mut self, msg: &[u8]) -> Result<(Vec<u8>, PublicKey)> {
        if msg.len() < 32 + 48 + 16 {
            return Err(anyhow!("handshake message 1 too short"));
        }
        let e_pub_bytes: [u8; 32] = msg[..32].try_into().unwrap();
        let remote_eph = PublicKey::from(e_pub_bytes);
        self.remote_ephemeral = Some(remote_eph);
        self.state.mix_hash(&e_pub_bytes);
        let es: SharedSecret = self.static_secret.diffie_hellman(&remote_eph);
        self.state.mix_key(es.as_bytes());
        let s_bytes = self.state.decrypt_and_hash(&msg[32..80])?;
        if s_bytes.len() != 32 {
            return Err(anyhow!("decrypted static key has wrong length"));
        }
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_bytes);
        let remote_static = PublicKey::from(s_arr);
        self.remote_static = Some(remote_static);
        let ss: SharedSecret = self.static_secret.diffie_hellman(&remote_static);
        self.state.mix_key(ss.as_bytes());
        let payload = self.state.decrypt_and_hash(&msg[80..])?;
        Ok((payload, remote_static))
    }

    /// Message 2: e || enc(empty). Returns (message, session).
    pub fn write_message2(mut self, payload: &[u8]) -> Result<(Vec<u8>, Session)> {
        let remote_eph = self.remote_ephemeral.ok_or_else(|| anyhow!("message 1 not read"))?;
        let remote_static = self.remote_static.ok_or_else(|| anyhow!("message 1 not read"))?;
        let ephemeral = StaticSecret::random_from_rng(rand_core::OsRng);
        let e_pub = PublicKey::from(&ephemeral);
        let mut msg = Vec::with_capacity(32 + payload.len() + 16);
        msg.extend_from_slice(e_pub.as_bytes());
        self.state.mix_hash(e_pub.as_bytes());
        let ee: SharedSecret = ephemeral.diffie_hellman(&remote_eph);
        self.state.mix_key(ee.as_bytes());
        let se: SharedSecret = ephemeral.diffie_hellman(&remote_static);
        self.state.mix_key(se.as_bytes());
        let enc_payload = self.state.encrypt_and_hash(payload)?;
        msg.extend_from_slice(&enc_payload);
        let (k1, k2) = self.state.split();
        // Responder sends with k2 and receives with k1.
        Ok((msg, Session::new(k2, k1, false)))
    }
}

// ---------------------------------------------------------------------------
// Transport session: AEAD with counter nonces + sliding replay window
// ---------------------------------------------------------------------------

const REPLAY_WINDOW: u64 = 2048;

pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    recv_highest: Option<u64>,
    recv_bitmap: Vec<u64>, // REPLAY_WINDOW bits
    pub initiator: bool,
}

impl Session {
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32], initiator: bool) -> Self {
        Self {
            send_key,
            recv_key,
            send_counter: 0,
            recv_highest: None,
            recv_bitmap: vec![0u64; (REPLAY_WINDOW / 64) as usize],
            initiator,
        }
    }

    fn cipher(key: &[u8; 32], counter: u64) -> (ChaCha20Poly1305, [u8; 12]) {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        (ChaCha20Poly1305::new(Key::from_slice(key)), nonce)
    }

    /// Seals a packet; returns (counter, ciphertext).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>)> {
        let counter = self.send_counter;
        let (cipher, nonce) = Self::cipher(&self.send_key, counter);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &[] })
            .map_err(|_| anyhow!("packet seal failed"))?;
        self.send_counter += 1;
        Ok((counter, ct))
    }

    fn check_and_mark_replay(&mut self, counter: u64) -> bool {
        match self.recv_highest {
            None => {
                self.recv_highest = Some(counter);
                self.recv_bitmap[(counter % REPLAY_WINDOW) as usize / 64] |=
                    1u64 << (counter % 64);
                true
            }
            Some(highest) => {
                if counter > highest {
                    let shift = counter - highest;
                    if shift >= REPLAY_WINDOW {
                        for b in self.recv_bitmap.iter_mut() {
                            *b = 0;
                        }
                    } else {
                        // clear bits for the counters we slide past
                        for c in (highest + 1)..=counter {
                            let idx = (c % REPLAY_WINDOW) as usize;
                            self.recv_bitmap[idx / 64] &= !(1u64 << (c % 64));
                        }
                    }
                    self.recv_highest = Some(counter);
                    let idx = (counter % REPLAY_WINDOW) as usize;
                    self.recv_bitmap[idx / 64] |= 1u64 << (counter % 64);
                    true
                } else {
                    if highest - counter >= REPLAY_WINDOW {
                        return false; // too old
                    }
                    let idx = (counter % REPLAY_WINDOW) as usize;
                    let bit = 1u64 << (counter % 64);
                    if self.recv_bitmap[idx / 64] & bit != 0 {
                        return false; // replay
                    }
                    self.recv_bitmap[idx / 64] |= bit;
                    true
                }
            }
        }
    }

    /// Opens a packet sealed by the peer. Rejects replays and tampering.
    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.check_and_mark_replay(counter) {
            return Err(anyhow!("replay or out-of-window counter {counter}"));
        }
        let (cipher, nonce) = Self::cipher(&self.recv_key, counter);
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &[] })
            .map_err(|_| anyhow!("packet authentication failed"))
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_blake2s_matches_reference_vector() {
        // Cross-checked against Python hashlib/hmac (RFC 4231 style case).
        let key = [0x0bu8; 20];
        let out = hmac_blake2s(&key, b"Hi There");
        assert_eq!(
            hex_encode(&out),
            "65a8b7c5cc9136d424e82c37e2707e74e913c0655b99c75f40edf387453a3260"
        );
    }

    #[test]
    fn hkdf_blake2s_matches_reference_vector() {
        // RFC 5869 construction, vector computed with Python hashlib.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..0x0d).collect();
        let info: Vec<u8> = (0xf0u8..0xfa).collect();
        let okm = hkdf_blake2s(&salt, &ikm, &info, 42);
        assert_eq!(
            hex_encode(&okm),
            "1472c31f2ff768c71b19f8803683ee3b13c1a5fb3ea59c0c3bf0d44a4a40dcd4329d9\
             cd85bbe35a1b3e7"
        );
    }

    #[test]
    fn fingerprint_matches_blake2b_reference() {
        // Computed with Python hashlib.blake2b(digest_size=32).
        assert_eq!(
            fingerprint(&[0u8; 32]),
            "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3"
        );
        let range: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            fingerprint(&range),
            "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6"
        );
    }

    fn keypair() -> StaticSecret {
        StaticSecret::random_from_rng(rand_core::OsRng)
    }

    #[test]
    fn noise_ik_handshake_and_transport_roundtrip() {
        let resp_static = keypair();
        let resp_pub = PublicKey::from(&resp_static);
        let init_static = keypair();
        let init_pub = PublicKey::from(&init_static);

        let mut initiator = HandshakeInitiator::new(init_static, resp_pub);
        let msg1 = initiator.write_message1(b"1700000000").unwrap();
        assert_eq!(msg1.len(), 32 + 48 + 10 + 16);

        let mut responder = HandshakeResponder::new(resp_static);
        let (payload, seen_static) = responder.read_message1(&msg1).unwrap();
        assert_eq!(payload, b"1700000000");
        assert_eq!(seen_static.as_bytes(), init_pub.as_bytes());

        let (msg2, mut resp_session) = responder.write_message2(&[]).unwrap();
        let mut init_session = initiator.read_message2(&msg2).unwrap();

        // initiator -> responder
        let (c, ct) = init_session.seal(b"hello mesh").unwrap();
        assert_eq!(resp_session.open(c, &ct).unwrap(), b"hello mesh");
        // responder -> initiator
        let (c2, ct2) = resp_session.seal(b"hello back").unwrap();
        assert_eq!(init_session.open(c2, &ct2).unwrap(), b"hello back");
    }

    #[test]
    fn wrong_responder_key_fails_handshake() {
        let resp_static = keypair();
        let other_static = keypair();
        let other_pub = PublicKey::from(&other_static);
        let init_static = keypair();
        let mut initiator = HandshakeInitiator::new(init_static, other_pub);
        let msg1 = initiator.write_message1(b"ts").unwrap();
        let mut responder = HandshakeResponder::new(resp_static);
        assert!(responder.read_message1(&msg1).is_err());
    }

    #[test]
    fn replayed_packet_is_rejected() {
        let resp_static = keypair();
        let resp_pub = PublicKey::from(&resp_static);
        let init_static = keypair();
        let mut initiator = HandshakeInitiator::new(init_static, resp_pub);
        let msg1 = initiator.write_message1(b"").unwrap();
        let mut responder = HandshakeResponder::new(resp_static);
        responder.read_message1(&msg1).unwrap();
        let (msg2, mut resp_session) = responder.write_message2(&[]).unwrap();
        let mut init_session = initiator.read_message2(&msg2).unwrap();
        let (c, ct) = init_session.seal(b"once").unwrap();
        assert!(resp_session.open(c, &ct).is_ok());
        assert!(resp_session.open(c, &ct).is_err());
    }

    #[test]
    fn tampered_packet_is_rejected() {
        let a = Session::new([7u8; 32], [7u8; 32], true);
        let b = Session::new([7u8; 32], [7u8; 32], false);
        let mut a = a;
        let mut b = b;
        let (c, mut ct) = a.seal(b"data").unwrap();
        ct[0] ^= 0xff;
        assert!(b.open(c, &ct).is_err());
    }
}
