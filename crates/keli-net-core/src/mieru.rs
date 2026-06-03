use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use keli_protocol::Endpoint;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::direct::{DirectTcpConnector, OutboundConnection, OutboundTarget, OwnedRelayStream};

const NONCE_LEN: usize = 24;
const METADATA_LEN: usize = 32;
const TAG_LEN: usize = 16;
const ENCRYPTED_METADATA_LEN: usize = METADATA_LEN + TAG_LEN;
const MAX_TCP_FRAGMENT_LEN: usize = 32 * 1024;
const MAX_SESSION_PAYLOAD_LEN: usize = 1024;
const KEY_WINDOW_SECS: i64 = 120;
const OPEN_SESSION_REQUEST: u8 = 2;
const OPEN_SESSION_RESPONSE: u8 = 3;
const CLOSE_SESSION_REQUEST: u8 = 4;
const CLOSE_SESSION_RESPONSE: u8 = 5;
const DATA_CLIENT_TO_SERVER: u8 = 6;
const DATA_SERVER_TO_CLIENT: u8 = 7;
const ACK_CLIENT_TO_SERVER: u8 = 8;
const ACK_SERVER_TO_CLIENT: u8 = 9;
const STATUS_OK: u8 = 0;
const SOCKS_VERSION: u8 = 5;
const SOCKS_CMD_CONNECT: u8 = 1;
const SOCKS_CONNECT_SUCCESS: [u8; 10] = [SOCKS_VERSION, 0, 0, 1, 0, 0, 0, 0, 0, 0];
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruTcpOutbound {
    server: Endpoint,
    username: String,
    password: String,
}

impl MieruTcpOutbound {
    pub fn new(server: Endpoint, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            server,
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn server(&self) -> &Endpoint {
        &self.server
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let stream = MieruTcpStream::connect(stream, &self.username, &self.password, &target)?;
        stream.inner.set_read_timeout(None)?;
        stream.inner.set_write_timeout(None)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug)]
pub struct MieruTcpStream {
    inner: TcpStream,
    key: [u8; 32],
    read_nonce: Option<[u8; NONCE_LEN]>,
    write_nonce: [u8; NONCE_LEN],
    session_id: u32,
    write_sequence: u32,
    read_buffer: Vec<u8>,
    pending: VecDeque<u8>,
    closed: bool,
}

impl MieruTcpStream {
    pub fn connect(
        inner: TcpStream,
        username: &str,
        password: &str,
        target: &Endpoint,
    ) -> io::Result<Self> {
        let key = derive_mieru_key(username, password, rounded_unix_time(now_unix_secs()));
        let mut write_nonce = [0; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut write_nonce);
        apply_nonce_user_hint(&mut write_nonce, username);
        let session_id = rand::thread_rng().next_u32();
        let mut stream = Self {
            inner,
            key,
            read_nonce: None,
            write_nonce,
            session_id,
            write_sequence: 0,
            read_buffer: Vec::new(),
            pending: VecDeque::new(),
            closed: false,
        };
        let request = socks_connect_request(target)?;
        stream.write_segment(OPEN_SESSION_REQUEST, &request)?;
        let response = stream.read_next_segment()?;
        if response.metadata.protocol_type != OPEN_SESSION_RESPONSE
            || response.metadata.status_code != STATUS_OK
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Mieru open session response",
            ));
        }
        let mut socks_reply = [0; SOCKS_CONNECT_SUCCESS.len()];
        stream.read_exact(&mut socks_reply)?;
        if socks_reply != SOCKS_CONNECT_SUCCESS {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Mieru SOCKS CONNECT request was rejected",
            ));
        }
        Ok(stream)
    }

    fn read_next_segment(&mut self) -> io::Result<MieruSegment> {
        loop {
            let has_nonce = self.read_nonce.is_none();
            let nonce = if has_nonce {
                if self.read_buffer.len() < NONCE_LEN {
                    None
                } else {
                    let mut nonce = [0; NONCE_LEN];
                    nonce.copy_from_slice(&self.read_buffer[..NONCE_LEN]);
                    Some(nonce)
                }
            } else {
                self.read_nonce
            };
            if let Some(nonce) = nonce {
                match try_decode_segment(&self.read_buffer, has_nonce, &self.key, nonce) {
                    SegmentAttempt::Complete {
                        segment,
                        consumed,
                        next_nonce,
                    } => {
                        self.read_buffer.drain(..consumed);
                        self.read_nonce = Some(next_nonce);
                        return Ok(segment);
                    }
                    SegmentAttempt::NeedMore => {}
                    SegmentAttempt::Invalid => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Mieru segment",
                        ))
                    }
                }
            }

            let mut temp = [0; 4096];
            let read = self.inner.read(&mut temp)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Mieru stream closed before next segment",
                ));
            }
            self.read_buffer.extend_from_slice(&temp[..read]);
        }
    }

    fn write_segment(&mut self, protocol_type: u8, payload: &[u8]) -> io::Result<()> {
        let metadata = MieruMetadata {
            protocol_type,
            session_id: self.session_id,
            sequence: self.write_sequence,
            status_code: STATUS_OK,
            payload_len: payload.len(),
            prefix_len: 0,
            suffix_len: 0,
        };
        self.write_sequence = self.write_sequence.saturating_add(1);
        let mut segment = Vec::new();
        if self.write_sequence == 1 {
            segment.extend_from_slice(&self.write_nonce);
        }
        encode_segment_body(
            &mut segment,
            &self.key,
            &mut self.write_nonce,
            &metadata,
            payload,
        )?;
        self.inner.write_all(&segment)
    }
}

impl Read for MieruTcpStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() && !self.closed {
            let segment = match self.read_next_segment() {
                Ok(segment) => segment,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    self.closed = true;
                    break;
                }
                Err(error) => return Err(error),
            };
            match segment.metadata.protocol_type {
                DATA_SERVER_TO_CLIENT | DATA_CLIENT_TO_SERVER => {
                    self.pending.extend(segment.payload);
                }
                CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                    self.closed = true;
                }
                ACK_CLIENT_TO_SERVER
                | ACK_SERVER_TO_CLIENT
                | OPEN_SESSION_REQUEST
                | OPEN_SESSION_RESPONSE => {}
                _ => {}
            }
        }

        let mut written = 0;
        while written < output.len() {
            let Some(byte) = self.pending.pop_front() else {
                break;
            };
            output[written] = byte;
            written += 1;
        }
        Ok(written)
    }
}

impl Write for MieruTcpStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        for chunk in input.chunks(MAX_TCP_FRAGMENT_LEN) {
            self.write_segment(DATA_CLIENT_TO_SERVER, chunk)?;
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl OwnedRelayStream for MieruTcpStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        let _ = self.write_segment(CLOSE_SESSION_REQUEST, &[]);
        self.inner.shutdown(Shutdown::Write)
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        let _ = self.write_segment(CLOSE_SESSION_REQUEST, &[]);
        self.inner.shutdown(Shutdown::Both)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MieruMetadata {
    protocol_type: u8,
    session_id: u32,
    sequence: u32,
    status_code: u8,
    payload_len: usize,
    prefix_len: usize,
    suffix_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MieruSegment {
    metadata: MieruMetadata,
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum SegmentAttempt {
    Complete {
        segment: MieruSegment,
        consumed: usize,
        next_nonce: [u8; NONCE_LEN],
    },
    NeedMore,
    Invalid,
}

fn try_decode_segment(
    input: &[u8],
    has_nonce: bool,
    key: &[u8; 32],
    nonce: [u8; NONCE_LEN],
) -> SegmentAttempt {
    let metadata_offset = if has_nonce {
        if input.len() < NONCE_LEN {
            return SegmentAttempt::NeedMore;
        }
        NONCE_LEN
    } else {
        0
    };
    if input.len() < metadata_offset + ENCRYPTED_METADATA_LEN {
        return SegmentAttempt::NeedMore;
    }

    let metadata_bytes = match decrypt_aead(
        key,
        &nonce,
        &input[metadata_offset..metadata_offset + ENCRYPTED_METADATA_LEN],
    ) {
        Ok(bytes) => bytes,
        Err(_) => return SegmentAttempt::Invalid,
    };
    let Some(metadata) = parse_metadata(&metadata_bytes) else {
        return SegmentAttempt::Invalid;
    };
    let mut next_nonce = nonce;
    increment_nonce(&mut next_nonce);

    let payload_offset = metadata_offset + ENCRYPTED_METADATA_LEN + metadata.prefix_len;
    let encrypted_payload_len = if metadata.payload_len == 0 {
        0
    } else {
        metadata.payload_len + TAG_LEN
    };
    let consumed = payload_offset + encrypted_payload_len + metadata.suffix_len;
    if input.len() < consumed {
        return SegmentAttempt::NeedMore;
    }
    let payload = if metadata.payload_len == 0 {
        Vec::new()
    } else {
        let payload = match decrypt_aead(
            key,
            &next_nonce,
            &input[payload_offset..payload_offset + encrypted_payload_len],
        ) {
            Ok(bytes) => bytes,
            Err(_) => return SegmentAttempt::Invalid,
        };
        if payload.len() != metadata.payload_len {
            return SegmentAttempt::Invalid;
        }
        increment_nonce(&mut next_nonce);
        payload
    };

    SegmentAttempt::Complete {
        segment: MieruSegment { metadata, payload },
        consumed,
        next_nonce,
    }
}

fn encode_segment_body(
    output: &mut Vec<u8>,
    key: &[u8; 32],
    nonce: &mut [u8; NONCE_LEN],
    metadata: &MieruMetadata,
    payload: &[u8],
) -> io::Result<()> {
    let metadata_bytes = encode_metadata(metadata)?;
    output.extend(encrypt_aead(key, nonce, &metadata_bytes)?);
    increment_nonce(nonce);
    if !payload.is_empty() {
        output.extend(encrypt_aead(key, nonce, payload)?);
        increment_nonce(nonce);
    }
    Ok(())
}

fn parse_metadata(input: &[u8]) -> Option<MieruMetadata> {
    if input.len() != METADATA_LEN {
        return None;
    }
    let protocol_type = input[0];
    if !matches!(
        protocol_type,
        OPEN_SESSION_REQUEST
            | OPEN_SESSION_RESPONSE
            | CLOSE_SESSION_REQUEST
            | CLOSE_SESSION_RESPONSE
            | DATA_CLIENT_TO_SERVER
            | DATA_SERVER_TO_CLIENT
            | ACK_CLIENT_TO_SERVER
            | ACK_SERVER_TO_CLIENT
    ) {
        return None;
    }
    let timestamp = u32::from_be_bytes([input[2], input[3], input[4], input[5]]);
    if !timestamp_is_close(timestamp) {
        return None;
    }

    let session_id = u32::from_be_bytes([input[6], input[7], input[8], input[9]]);
    let sequence = u32::from_be_bytes([input[10], input[11], input[12], input[13]]);
    match protocol_type {
        OPEN_SESSION_REQUEST
        | OPEN_SESSION_RESPONSE
        | CLOSE_SESSION_REQUEST
        | CLOSE_SESSION_RESPONSE => {
            let payload_len = u16::from_be_bytes([input[15], input[16]]) as usize;
            if payload_len > MAX_SESSION_PAYLOAD_LEN {
                return None;
            }
            Some(MieruMetadata {
                protocol_type,
                session_id,
                sequence,
                status_code: input[14],
                payload_len,
                prefix_len: 0,
                suffix_len: input[17] as usize,
            })
        }
        DATA_CLIENT_TO_SERVER
        | DATA_SERVER_TO_CLIENT
        | ACK_CLIENT_TO_SERVER
        | ACK_SERVER_TO_CLIENT => {
            let payload_len = u16::from_be_bytes([input[22], input[23]]) as usize;
            if payload_len > MAX_TCP_FRAGMENT_LEN {
                return None;
            }
            Some(MieruMetadata {
                protocol_type,
                session_id,
                sequence,
                status_code: STATUS_OK,
                payload_len,
                prefix_len: input[21] as usize,
                suffix_len: input[24] as usize,
            })
        }
        _ => None,
    }
}

fn encode_metadata(metadata: &MieruMetadata) -> io::Result<[u8; METADATA_LEN]> {
    if metadata.payload_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mieru payload too large",
        ));
    }
    let mut output = [0; METADATA_LEN];
    output[0] = metadata.protocol_type;
    output[2..6].copy_from_slice(&((now_unix_secs() / 60) as u32).to_be_bytes());
    output[6..10].copy_from_slice(&metadata.session_id.to_be_bytes());
    output[10..14].copy_from_slice(&metadata.sequence.to_be_bytes());
    match metadata.protocol_type {
        OPEN_SESSION_REQUEST
        | OPEN_SESSION_RESPONSE
        | CLOSE_SESSION_REQUEST
        | CLOSE_SESSION_RESPONSE => {
            output[14] = metadata.status_code;
            output[15..17].copy_from_slice(&(metadata.payload_len as u16).to_be_bytes());
            output[17] = metadata.suffix_len as u8;
        }
        DATA_CLIENT_TO_SERVER
        | DATA_SERVER_TO_CLIENT
        | ACK_CLIENT_TO_SERVER
        | ACK_SERVER_TO_CLIENT => {
            output[18..20].copy_from_slice(&(64u16).to_be_bytes());
            output[21] = metadata.prefix_len as u8;
            output[22..24].copy_from_slice(&(metadata.payload_len as u16).to_be_bytes());
            output[24] = metadata.suffix_len as u8;
        }
        _ => {}
    }
    Ok(output)
}

fn socks_connect_request(target: &Endpoint) -> io::Result<Vec<u8>> {
    let mut request = vec![SOCKS_VERSION, SOCKS_CMD_CONNECT, 0];
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                request.push(ATYP_IPV4);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(ATYP_IPV6);
                request.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mieru target domain is too long",
            ));
        }
        request.push(ATYP_DOMAIN);
        request.push(host.len() as u8);
        request.extend_from_slice(host);
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    Ok(request)
}

fn encrypt_aead(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mieru encrypt failed"))
}

fn decrypt_aead(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mieru decrypt failed"))
}

fn derive_mieru_key(username: &str, password: &str, rounded_unix: i64) -> [u8; 32] {
    let mut password_hasher = Sha256::new();
    password_hasher.update(password.as_bytes());
    password_hasher.update([0]);
    password_hasher.update(username.as_bytes());
    let hashed_password = password_hasher.finalize();

    let mut time_hasher = Sha256::new();
    time_hasher.update((rounded_unix as u64).to_be_bytes());
    let time_salt = time_hasher.finalize();

    let mut key = [0; 32];
    pbkdf2_hmac_sha256(&hashed_password, &time_salt, 64, &mut key);
    key
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let mut block_index = 1u32;
    let mut offset = 0usize;
    while offset < output.len() {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(password).expect("hmac accepts any key length");
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut block = u.clone();
        for _ in 1..iterations {
            let mut mac =
                <HmacSha256 as Mac>::new_from_slice(password).expect("hmac accepts any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (left, right) in block.iter_mut().zip(&u) {
                *left ^= *right;
            }
        }

        let take = (output.len() - offset).min(block.len());
        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        block_index = block_index.saturating_add(1);
    }
}

fn apply_nonce_user_hint(nonce: &mut [u8; NONCE_LEN], username: &str) {
    let hint = nonce_user_hint(&nonce[..16], username);
    nonce[20..24].copy_from_slice(&hint);
}

fn nonce_user_hint(nonce_prefix: &[u8], username: &str) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(nonce_prefix);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn rounded_unix_time(unix_secs: i64) -> i64 {
    ((unix_secs + KEY_WINDOW_SECS / 2) / KEY_WINDOW_SECS) * KEY_WINDOW_SECS
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn timestamp_is_close(minutes: u32) -> bool {
    let now = (now_unix_secs() / 60) as i64;
    (now - i64::from(minutes)).abs() <= 10
}
