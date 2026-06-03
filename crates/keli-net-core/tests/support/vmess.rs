use std::io::{Read, Write};

use aes::cipher::{BlockDecrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesGcmNonce};
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha2Digest, Sha256};

const VMESS_KDF_ROOT: &[u8] = b"VMess AEAD KDF";
const VMESS_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const VMESS_HEADER_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_HEADER_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const VMESS_RESPONSE_HEADER_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const VMESS_RESPONSE_HEADER_LENGTH_IV: &[u8] = b"AEAD Resp Header Len IV";
const VMESS_RESPONSE_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const VMESS_RESPONSE_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const VMESS_CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

#[derive(Debug)]
pub struct VmessRequestForTest {
    pub target_host: String,
    pub target_port: u16,
    pub command: u8,
    pub security: u8,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_header: u8,
}

pub fn read_vmess_aead_request(stream: &mut impl Read, uuid: &str) -> VmessRequestForTest {
    let uuid = parse_uuid_bytes_for_vmess_test(uuid);
    let cmd_key = vmess_cmd_key_for_test(&uuid);
    let mut auth_id = [0; 16];
    let mut encrypted_len = [0; 18];
    let mut nonce = [0; 8];
    stream.read_exact(&mut auth_id).expect("read auth id");
    assert!(vmess_auth_id_is_valid_for_test(&cmd_key, &auth_id));
    stream
        .read_exact(&mut encrypted_len)
        .expect("read header length");
    stream.read_exact(&mut nonce).expect("read nonce");

    let len_key = vmess_kdf16_for_test(&cmd_key, &[VMESS_HEADER_LENGTH_KEY, &auth_id, &nonce]);
    let len_nonce = first_12_for_test(&vmess_kdf_for_test(
        &cmd_key,
        &[VMESS_HEADER_LENGTH_NONCE, &auth_id, &nonce],
    ));
    let len_plain = vmess_aes_gcm_open_for_test(&len_key, &len_nonce, &encrypted_len, &auth_id);
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_header = vec![0; header_len + 16];
    stream
        .read_exact(&mut encrypted_header)
        .expect("read request header");
    let payload_key = vmess_kdf16_for_test(&cmd_key, &[VMESS_HEADER_PAYLOAD_KEY, &auth_id, &nonce]);
    let payload_nonce = first_12_for_test(&vmess_kdf_for_test(
        &cmd_key,
        &[VMESS_HEADER_PAYLOAD_NONCE, &auth_id, &nonce],
    ));
    let header =
        vmess_aes_gcm_open_for_test(&payload_key, &payload_nonce, &encrypted_header, &auth_id);

    assert_eq!(header[0], 0x01);
    let request_body_iv = header[1..17].try_into().expect("request iv");
    let request_body_key = header[17..33].try_into().expect("request key");
    let response_header = header[33];
    let security = header[35] & 0x0f;
    let command = header[37];
    let target_port = u16::from_be_bytes([header[38], header[39]]);
    assert_eq!(header[40], 0x02, "test only expects a domain target");
    let domain_len = header[41] as usize;
    let target_host =
        String::from_utf8(header[42..42 + domain_len].to_vec()).expect("domain target");

    VmessRequestForTest {
        target_host,
        target_port,
        command,
        security,
        request_body_key,
        request_body_iv,
        response_header,
    }
}

pub fn write_vmess_aead_response_header(stream: &mut impl Write, request: &VmessRequestForTest) {
    let response_key = first_16_sha256_for_test(&request.request_body_key);
    let response_iv = first_16_sha256_for_test(&request.request_body_iv);
    let header = [request.response_header, 0x00, 0x00, 0x00];
    let len_key = vmess_kdf16_for_test(&response_key, &[VMESS_RESPONSE_HEADER_LENGTH_KEY]);
    let len_nonce = first_12_for_test(&vmess_kdf_for_test(
        &response_iv,
        &[VMESS_RESPONSE_HEADER_LENGTH_IV],
    ));
    let payload_key = vmess_kdf16_for_test(&response_key, &[VMESS_RESPONSE_HEADER_PAYLOAD_KEY]);
    let payload_nonce = first_12_for_test(&vmess_kdf_for_test(
        &response_iv,
        &[VMESS_RESPONSE_HEADER_PAYLOAD_IV],
    ));
    let encrypted_len = vmess_aes_gcm_seal_for_test(
        &len_key,
        &len_nonce,
        &(header.len() as u16).to_be_bytes(),
        &[],
    );
    let encrypted_payload = vmess_aes_gcm_seal_for_test(&payload_key, &payload_nonce, &header, &[]);
    stream
        .write_all(&encrypted_len)
        .expect("write response len");
    stream
        .write_all(&encrypted_payload)
        .expect("write response payload");
}

fn parse_uuid_bytes_for_vmess_test(value: &str) -> [u8; 16] {
    let compact: String = value.chars().filter(|value| *value != '-').collect();
    let mut output = [0; 16];
    for (index, chunk) in compact.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).expect("uuid hex");
        output[index] = u8::from_str_radix(hex, 16).expect("uuid byte");
    }
    output
}

fn vmess_cmd_key_for_test(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, uuid);
    Md5Digest::update(&mut hasher, VMESS_CMD_KEY_SALT);
    hasher.finalize().into()
}

fn vmess_auth_id_is_valid_for_test(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> bool {
    let key = vmess_kdf16_for_test(cmd_key, &[VMESS_AUTH_ID_KEY]);
    let cipher = aes::Aes128::new_from_slice(&key).expect("auth key");
    let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(auth_id);
    cipher.decrypt_block(&mut block);
    let crc = u32::from_be_bytes(block[12..16].try_into().expect("crc bytes"));
    crc == crc32fast::hash(&block[..12])
}

fn first_16_sha256_for_test(input: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, input);
    let digest = hasher.finalize();
    digest[..16].try_into().expect("sha256 first 16")
}

fn first_12_for_test(input: &[u8; 32]) -> [u8; 12] {
    input[..12].try_into().expect("first 12")
}

fn vmess_kdf16_for_test(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    vmess_kdf_for_test(key, path)[..16]
        .try_into()
        .expect("kdf16")
}

fn vmess_kdf_for_test(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    if path.is_empty() {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(VMESS_KDF_ROOT).expect("hmac key");
        Mac::update(&mut mac, key);
        return mac.finalize().into_bytes().into();
    }
    let tail = path[path.len() - 1];
    vmess_hmac_with_hash_for_test(
        |input| vmess_kdf_for_test(input, &path[..path.len() - 1]),
        tail,
        key,
    )
}

fn vmess_hmac_with_hash_for_test<H>(hash: H, key: &[u8], message: &[u8]) -> [u8; 32]
where
    H: Fn(&[u8]) -> [u8; 32],
{
    let mut normalized_key = if key.len() > 64 {
        hash(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(64, 0);
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, key_byte) in normalized_key.iter().enumerate() {
        inner[index] ^= key_byte;
        outer[index] ^= key_byte;
    }
    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(message);
    let inner_hash = hash(&inner_input);
    let mut outer_input = Vec::with_capacity(64 + inner_hash.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    hash(&outer_input)
}

fn vmess_aes_gcm_open_for_test(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    Aes128Gcm::new_from_slice(key)
        .expect("aes-gcm key")
        .decrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .expect("open vmess aes-gcm")
}

fn vmess_aes_gcm_seal_for_test(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    Aes128Gcm::new_from_slice(key)
        .expect("aes-gcm key")
        .encrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .expect("seal vmess aes-gcm")
}
