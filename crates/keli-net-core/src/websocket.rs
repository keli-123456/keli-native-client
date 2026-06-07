use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha1::{Digest, Sha1};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

#[derive(Debug)]
pub struct WebSocketClientStream {
    reader: TcpStream,
    writer: TcpStream,
    read_buffer: VecDeque<u8>,
}

#[derive(Debug)]
pub struct OwnedWebSocketClientStream<S> {
    stream: S,
    read_buffer: VecDeque<u8>,
}

impl<S: Read + Write> OwnedWebSocketClientStream<S> {
    pub fn connect(stream: S, host: &str, path: &str) -> io::Result<Self> {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let key = STANDARD.encode(nonce);
        Self::connect_with_key(stream, host, path, &key)
    }

    pub fn connect_with_key(mut stream: S, host: &str, path: &str, key: &str) -> io::Result<Self> {
        write_handshake_request(&mut stream, host, path, key)?;
        stream.flush()?;
        let response = read_http_response(&mut stream)?;
        validate_handshake_response(&response, key)?;
        Ok(Self {
            stream,
            read_buffer: VecDeque::new(),
        })
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S: Read + Write> Read for OwnedWebSocketClientStream<S> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.read_buffer.is_empty() {
            let payload = match read_frame_payload(&mut self.stream) {
                Ok(payload) => payload,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(error) => return Err(error),
            };
            self.read_buffer.extend(payload);
        }
        let mut read = 0;
        while read < output.len() {
            let Some(byte) = self.read_buffer.pop_front() else {
                break;
            };
            output[read] = byte;
            read += 1;
        }
        Ok(read)
    }
}

impl<S: Read + Write> Write for OwnedWebSocketClientStream<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        write_masked_binary_frame(&mut self.stream, buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl WebSocketClientStream {
    pub fn connect(stream: TcpStream, host: &str, path: &str) -> io::Result<Self> {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let key = STANDARD.encode(nonce);
        Self::connect_with_key(stream, host, path, &key)
    }

    pub fn connect_with_key(
        mut stream: TcpStream,
        host: &str,
        path: &str,
        key: &str,
    ) -> io::Result<Self> {
        write_handshake_request(&mut stream, host, path, key)?;
        stream.flush()?;
        let response = read_http_response(&mut stream)?;
        validate_handshake_response(&response, key)?;
        let reader = stream.try_clone()?;
        Ok(Self {
            reader,
            writer: stream,
            read_buffer: VecDeque::new(),
        })
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            reader: self.reader.try_clone()?,
            writer: self.writer.try_clone()?,
            read_buffer: VecDeque::new(),
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.set_read_timeout(timeout)
    }

    pub fn set_nonblocking_mode(&self, nonblocking: bool) -> io::Result<()> {
        self.reader.set_nonblocking(nonblocking)?;
        self.writer.set_nonblocking(nonblocking)
    }

    pub fn shutdown_write(&self) -> io::Result<()> {
        self.writer.shutdown(Shutdown::Write)
    }

    pub fn shutdown_both(&self) -> io::Result<()> {
        self.reader.shutdown(Shutdown::Both).ok();
        self.writer.shutdown(Shutdown::Both)
    }
}

impl Read for WebSocketClientStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.read_buffer.is_empty() {
            let payload = match read_frame_payload(&mut self.reader) {
                Ok(payload) => payload,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(error) => return Err(error),
            };
            self.read_buffer.extend(payload);
        }
        let mut read = 0;
        while read < output.len() {
            let Some(byte) = self.read_buffer.pop_front() else {
                break;
            };
            output[read] = byte;
            read += 1;
        }
        Ok(read)
    }
}

impl Write for WebSocketClientStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        write_masked_binary_frame(&mut self.writer, buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub fn websocket_accept_for_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    STANDARD.encode(hasher.finalize())
}

fn write_handshake_request(
    stream: &mut impl Write,
    host: &str,
    path: &str,
    key: &str,
) -> io::Result<()> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes())
}

fn read_http_response(stream: &mut impl Read) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket response header is too large",
            ));
        }
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn validate_handshake_response(response: &str, key: &str) -> io::Result<()> {
    let mut lines = response.lines();
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket server did not switch protocols",
        ));
    }
    let expected_accept = websocket_accept_for_key(key);
    let mut saw_upgrade = false;
    let mut saw_connection = false;
    let mut saw_accept = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Upgrade") && value.eq_ignore_ascii_case("websocket") {
            saw_upgrade = true;
        } else if name.eq_ignore_ascii_case("Connection")
            && value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("upgrade"))
        {
            saw_connection = true;
        } else if name.eq_ignore_ascii_case("Sec-WebSocket-Accept") && value == expected_accept {
            saw_accept = true;
        }
    }
    if saw_upgrade && saw_connection && saw_accept {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket handshake response is invalid",
        ))
    }
}

fn write_masked_binary_frame(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(2 + 8 + 4 + payload.len());
    frame.write_all(&[0x80 | OPCODE_BINARY])?;
    write_payload_len(&mut frame, payload.len(), true)?;
    let mut mask = [0; 4];
    OsRng.fill_bytes(&mut mask);
    frame.write_all(&mask)?;
    for (index, byte) in payload.iter().enumerate() {
        frame.write_all(&[*byte ^ mask[index % 4]])?;
    }
    stream.write_all(&frame)?;
    stream.flush()
}

fn write_payload_len(stream: &mut impl Write, len: usize, masked: bool) -> io::Result<()> {
    let mask_bit = if masked { 0x80 } else { 0x00 };
    if len <= 125 {
        stream.write_all(&[mask_bit | len as u8])
    } else if len <= u16::MAX as usize {
        stream.write_all(&[mask_bit | 126])?;
        stream.write_all(&(len as u16).to_be_bytes())
    } else {
        stream.write_all(&[mask_bit | 127])?;
        stream.write_all(&(len as u64).to_be_bytes())
    }
}

fn read_frame_payload(stream: &mut (impl Read + Write)) -> io::Result<Vec<u8>> {
    loop {
        let mut header = [0; 2];
        stream.read_exact(&mut header)?;
        let fin = header[0] & 0x80 != 0;
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let len = read_payload_len(stream, header[1] & 0x7f)?;
        let mut mask = [0; 4];
        if masked {
            stream.read_exact(&mut mask)?;
        }
        let mut payload = vec![0; len];
        stream.read_exact(&mut payload)?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        match opcode {
            OPCODE_TEXT | OPCODE_BINARY if fin => return Ok(payload),
            OPCODE_CLOSE => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "websocket peer closed",
                ));
            }
            OPCODE_PING => write_control_frame(stream, OPCODE_PONG, &payload)?,
            OPCODE_PONG => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported websocket frame",
                ));
            }
        }
    }
}

fn read_payload_len(stream: &mut impl Read, first_len: u8) -> io::Result<usize> {
    match first_len {
        len @ 0..=125 => Ok(usize::from(len)),
        126 => {
            let mut bytes = [0; 2];
            stream.read_exact(&mut bytes)?;
            Ok(usize::from(u16::from_be_bytes(bytes)))
        }
        127 => {
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes)?;
            let len = u64::from_be_bytes(bytes);
            usize::try_from(len)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))
        }
        _ => unreachable!(),
    }
}

fn write_control_frame(stream: &mut impl Write, opcode: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > 125 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket control frame is too large",
        ));
    }
    stream.write_all(&[0x80 | opcode])?;
    write_payload_len(stream, payload.len(), true)?;
    let mut mask = [0; 4];
    OsRng.fill_bytes(&mut mask);
    stream.write_all(&mask)?;
    for (index, byte) in payload.iter().enumerate() {
        stream.write_all(&[*byte ^ mask[index % 4]])?;
    }
    Ok(())
}
