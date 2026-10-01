// Added for maki (a fork of Xous: github.com/KaraZajac/maki-firmware) in 2026, under its crate's license.

//! Google Authenticator's export. "Transfer accounts" shows QR codes that say
//! `otpauth-migration://offline?data=…`: base64 of a protobuf `MigrationPayload`, every code's
//! secret, name, issuer, algorithm, digits, type and counter, a batch of them per QR code. Read
//! here without a protobuf library: the message is small and fixed (google_auth.proto, as Aegis
//! and other importers have it), and nothing in it is trusted further than a code scanned one at
//! a time would be.

/// One code, as the export has it.
#[derive(Debug, PartialEq, Eq)]
pub struct Code {
    /// the secret, as base32 (RFC 4648, no padding), as an `otpauth://` code gives it
    pub secret: String,
    /// "issuer:account" when the export gives an issuer, as an `otpauth://` label would
    pub name: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub hotp: bool,
    /// HOTP's counter
    pub counter: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// One QR code's worth.
#[derive(Debug, PartialEq, Eq)]
pub struct Batch {
    pub codes: Vec<Code>,
    /// codes maki can't use (MD5, or no secret)
    pub skipped: usize,
    /// which QR code of how many this was (1 of 1 for an export that fits in one)
    pub index: u32,
    pub size: u32,
}

/// More codes than this in one QR code is no export of Google Authenticator's.
const MAX_CODES: usize = 100;
const MAX_SECRET: usize = 128;
const MAX_TEXT: usize = 128;

/// Reads what follows `otpauth-migration://`.
pub fn parse(rest: &str) -> Result<Batch, &'static str> {
    let query = rest.split_once('?').map(|(_, q)| q).ok_or("no query")?;
    let data = query.split('&').find_map(|kv| kv.strip_prefix("data=")).ok_or("no data")?;
    let bytes = base64_decode(&percent_decode(data)?)?;
    let mut batch = Batch { codes: Vec::new(), skipped: 0, index: 0, size: 1 };
    let mut r = Reader { b: &bytes, at: 0 };
    while let Some((field, value)) = r.field()? {
        match (field, value) {
            (1, Value::Bytes(code)) => {
                if batch.codes.len() + batch.skipped >= MAX_CODES {
                    return Err("too many codes");
                }
                match code_from(code)? {
                    Some(c) => batch.codes.push(c),
                    None => batch.skipped += 1,
                }
            }
            (3, Value::Int(n)) => batch.size = (n as u32).max(1),
            (4, Value::Int(n)) => batch.index = n as u32,
            _ => {} // the version, the batch's ID, and anything newer
        }
    }
    Ok(Batch { index: batch.index + 1, ..batch })
}

fn code_from(bytes: &[u8]) -> Result<Option<Code>, &'static str> {
    let (mut secret, mut name, mut issuer) = (&[][..], String::new(), String::new());
    let (mut algorithm, mut digits, mut kind, mut counter) = (0u64, 0u64, 0u64, 0u64);
    let mut r = Reader { b: bytes, at: 0 };
    while let Some((field, value)) = r.field()? {
        match (field, value) {
            (1, Value::Bytes(b)) => secret = b,
            (2, Value::Bytes(b)) => name = text(b)?,
            (3, Value::Bytes(b)) => issuer = text(b)?,
            (4, Value::Int(n)) => algorithm = n,
            (5, Value::Int(n)) => digits = n,
            (6, Value::Int(n)) => kind = n,
            (7, Value::Int(n)) => counter = n,
            _ => {}
        }
    }
    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return Ok(None), // MD5, which no code generator here has
    };
    if secret.is_empty() || secret.len() > MAX_SECRET {
        return Ok(None);
    }
    let name = match (issuer.is_empty(), name.is_empty()) {
        (false, true) => issuer.clone(),
        (false, false) if !name.starts_with(&format!("{issuer}:")) => format!("{issuer}:{name}"),
        _ => name,
    };
    Ok(Some(Code {
        secret: base32(secret),
        name,
        issuer,
        algorithm,
        digits: if digits == 2 { 8 } else { 6 },
        hotp: kind == 1,
        counter,
    }))
}

fn text(b: &[u8]) -> Result<String, &'static str> {
    let s = core::str::from_utf8(b).map_err(|_| "a name isn't text")?;
    // what fits a line on maki's screen, and nothing that breaks the record's own format
    Ok(s.chars().filter(|c| !c.is_control()).take(MAX_TEXT).collect())
}

enum Value<'a> {
    Int(u64),
    Bytes(&'a [u8]),
    Other,
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, &'static str> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.b.get(self.at).ok_or("cut short")?;
            self.at += 1;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("a number too long")
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("cut short")?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    /// The next field: its number and value, or None at the end.
    fn field(&mut self) -> Result<Option<(u64, Value<'a>)>, &'static str> {
        if self.at == self.b.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let value = match key & 7 {
            0 => Value::Int(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Other
            }
            2 => {
                let n = self.varint()?;
                Value::Bytes(self.take(usize::try_from(n).map_err(|_| "cut short")?)?)
            }
            5 => {
                self.take(4)?;
                Value::Other
            }
            _ => return Err("not a protobuf this reads"),
        };
        Ok(Some((key >> 3, value)))
    }
}

fn percent_decode(s: &str) -> Result<String, &'static str> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3).ok_or("a bad escape")?;
            let hex = core::str::from_utf8(hex).map_err(|_| "a bad escape")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "a bad escape")?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "a bad escape")
}

/// Standard base64, padded or not (spaces, which a `+` that wasn't escaped becomes, read as `+`).
fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b' ' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return Err("not base64"),
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// RFC 4648 base32, upper case, no padding: how vault2 keeps a code's secret.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = acc << 8 | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(acc >> bits) as usize & 31] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[(acc << (5 - bits)) as usize & 31] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // a protobuf field, for building exports here
    fn key(field: u64, wire: u64) -> Vec<u8> { varint(field << 3 | wire) }
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }
    fn bytes_field(field: u64, b: &[u8]) -> Vec<u8> {
        [key(field, 2), varint(b.len() as u64), b.to_vec()].concat()
    }
    fn int_field(field: u64, v: u64) -> Vec<u8> { [key(field, 0), varint(v)].concat() }
    fn base64(b: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in b.chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |n, (i, &c)| n | (c as u32) << (16 - 8 * i));
            for i in 0..4 {
                out.push(if i <= chunk.len() { A[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
            }
        }
        out
    }

    #[test]
    fn base32_as_rfc_4648_says() {
        for (input, want) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), want);
        }
        assert_eq!(base32(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn reads_a_batch_of_codes_as_google_authenticator_writes_it() {
        let github = [
            bytes_field(1, b"Hello!\xde\xad\xbe\xef"),
            bytes_field(2, b"alice@example.com"),
            bytes_field(3, b"GitHub"),
            int_field(4, 1),
            int_field(5, 1),
            int_field(6, 2),
        ]
        .concat();
        let bank = [
            bytes_field(1, &[7u8; 32]),
            bytes_field(2, b"Bank:alice"),
            bytes_field(3, b"Bank"),
            int_field(4, 2),
            int_field(5, 2),
            int_field(6, 2),
        ]
        .concat();
        let hotp = [
            bytes_field(1, b"12345678901234567890"),
            bytes_field(2, b"vpn"),
            int_field(6, 1),
            int_field(7, 42),
        ]
        .concat();
        let md5 = [bytes_field(1, b"x"), bytes_field(2, b"old"), int_field(4, 4)].concat();
        let payload = [
            bytes_field(1, &github),
            bytes_field(1, &bank),
            bytes_field(1, &hotp),
            bytes_field(1, &md5),
            int_field(2, 1),
            int_field(3, 2),
            int_field(4, 1),
            int_field(5, 0x1234),
        ]
        .concat();
        // as the QR code has it: base64, with + / = escaped
        let data = base64(&payload).replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
        let batch = parse(&format!("offline?data={data}")).unwrap();
        assert_eq!((batch.index, batch.size, batch.skipped), (2, 2, 1));
        assert_eq!(
            batch.codes[0],
            Code {
                secret: "JBSWY3DPEHPK3PXP".into(),
                name: "GitHub:alice@example.com".into(),
                issuer: "GitHub".into(),
                algorithm: Algorithm::Sha1,
                digits: 6,
                hotp: false,
                counter: 0,
            }
        );
        assert_eq!(
            (batch.codes[1].name.as_str(), batch.codes[1].algorithm, batch.codes[1].digits),
            ("Bank:alice", Algorithm::Sha256, 8),
            "an issuer already in the name isn't put there twice"
        );
        assert_eq!(batch.codes[1].secret.len(), 52);
        assert_eq!(
            (
                batch.codes[2].name.as_str(),
                batch.codes[2].hotp,
                batch.codes[2].counter,
                batch.codes[2].digits
            ),
            ("vpn", true, 42, 6)
        );
        assert_eq!(batch.codes[2].secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    // dim13/otpauth's example export (its README), and the code it decodes it to:
    // otpauth://totp/Example:alice@google.com?issuer=Example&secret=JBSWY3DPEHPK3PXP
    #[test]
    fn reads_another_decoders_example_as_it_does() {
        let batch =
            parse("offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC")
                .unwrap();
        assert_eq!((batch.index, batch.size, batch.skipped), (1, 1, 0));
        assert_eq!(
            batch.codes,
            vec![Code {
                secret: "JBSWY3DPEHPK3PXP".into(),
                name: "Example:alice@google.com".into(),
                issuer: "Example".into(),
                algorithm: Algorithm::Sha1,
                digits: 6,
                hotp: false,
                counter: 0,
            }]
        );
    }

    #[test]
    fn unescaped_base64_and_no_padding_read_too() {
        let payload = bytes_field(1, &[bytes_field(1, b"\xff\xfe\xfd"), bytes_field(2, b"x")].concat());
        let raw = base64(&payload);
        assert!(raw.contains('/') || raw.contains('+') || raw.contains('='));
        for data in [raw.clone(), raw.trim_end_matches('=').to_string(), raw.replace('+', " ")] {
            let batch = parse(&format!("offline?data={data}")).unwrap();
            assert_eq!(batch.codes.len(), 1);
            assert_eq!(batch.codes[0].secret, "777P2");
        }
    }

    #[test]
    fn refuses_what_isnt_an_export() {
        assert!(parse("offline").is_err());
        assert!(parse("offline?other=1").is_err());
        assert!(parse("offline?data=!!!").is_err());
        // a length running past the end
        assert!(parse(&format!("offline?data={}", base64(&[0x0a, 0x7f, 0x01]))).is_err());
        // a wire type it doesn't read
        assert!(parse(&format!("offline?data={}", base64(&[0x0b]))).is_err());
        // too many codes
        let one = bytes_field(1, &[bytes_field(1, b"k"), bytes_field(2, b"n")].concat());
        let many = one.repeat(MAX_CODES + 1);
        assert_eq!(parse(&format!("offline?data={}", base64(&many))), Err("too many codes"));
        // names lose what isn't printable
        let tricky = bytes_field(1, &[bytes_field(1, b"k"), bytes_field(2, b"a\nb:c\td")].concat());
        assert_eq!(parse(&format!("offline?data={}", base64(&tricky))).unwrap().codes[0].name, "ab:cd");
    }
}
