//! JSON, strictly (RFC 8259) and within bounds: the typed data a site asks maki to sign (EIP-712)
//! comes as JSON, and maki reads it itself rather than take the computer's word for what it says.

use alloc::string::String;
use alloc::vec::Vec;

/// How deep arrays and objects may nest.
pub const MAX_DEPTH: usize = 32;
/// The most digits a number may have: a 256-bit number has 78.
const MAX_DIGITS: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A whole number, as written: an optional minus, then digits without leading zeros.
    /// Fractions and exponents aren't taken: typed data has no use for them, and they'd lose
    /// precision.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// In the order written, no name twice.
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(fields) => Some(fields),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Where the text stopped making sense, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub at: usize,
    pub what: &'static str,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.what, self.at)
    }
}

/// One JSON value, and nothing after it but white space.
pub fn parse(text: &str) -> Result<Value, Error> {
    let mut p = Parser { b: text.as_bytes(), at: 0 };
    p.space();
    let value = p.value(0)?;
    p.space();
    if p.at != p.b.len() {
        return Err(p.error("more after the end"));
    }
    Ok(value)
}

struct Parser<'a> {
    b: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn error(&self, what: &'static str) -> Error { Error { at: self.at, what } }

    fn peek(&self) -> Option<u8> { self.b.get(self.at).copied() }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.word("true", Value::Bool(true)),
            Some(b'f') => self.word("false", Value::Bool(false)),
            Some(b'n') => self.word("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("not a value")),
        }
    }

    fn word(&mut self, word: &str, value: Value) -> Result<Value, Error> {
        if !self.b[self.at..].starts_with(word.as_bytes()) {
            return Err(self.error("not a value"));
        }
        self.at += word.len();
        Ok(value)
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= MAX_DEPTH {
            return Err(self.error("nested too deep"));
        }
        self.at += 1;
        let mut fields: Vec<(String, Value)> = Vec::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.space();
            if self.peek() != Some(b'"') {
                return Err(self.error("a name expected"));
            }
            let start = self.at;
            let name = self.string()?;
            if fields.iter().any(|(n, _)| *n == name) {
                return Err(Error { at: start, what: "a name given twice" });
            }
            self.space();
            if self.peek() != Some(b':') {
                return Err(self.error("':' expected"));
            }
            self.at += 1;
            self.space();
            let value = self.value(depth + 1)?;
            fields.push((name, value));
            self.space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return Err(self.error("',' or '}' expected")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= MAX_DEPTH {
            return Err(self.error("nested too deep"));
        }
        self.at += 1;
        let mut items = Vec::new();
        self.space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.space();
            items.push(self.value(depth + 1)?);
            self.space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("',' or ']' expected")),
            }
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        self.at += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.peek() else { return Err(self.error("a string that doesn't end")) };
            match c {
                b'"' => {
                    self.at += 1;
                    // what went in was UTF-8, and escapes add whole characters
                    return String::from_utf8(out).map_err(|_| self.error("not UTF-8"));
                }
                b'\\' => {
                    self.at += 1;
                    let Some(e) = self.peek() else { return Err(self.error("a string that doesn't end")) };
                    self.at += 1;
                    let plain = match e {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'u' => {
                            let ch = self.unicode()?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            continue;
                        }
                        _ => return Err(self.error("not an escape")),
                    };
                    out.push(plain);
                }
                0x00..=0x1f => return Err(self.error("a control character in a string")),
                _ => {
                    out.push(c);
                    self.at += 1;
                }
            }
        }
    }

    /// `\uXXXX` (the `\u` read already), a surrogate pair's second half included.
    fn unicode(&mut self) -> Result<char, Error> {
        let first = self.hex4()?;
        let code = match first {
            0xd800..=0xdbff => {
                if !self.b[self.at..].starts_with(b"\\u") {
                    return Err(self.error("half a surrogate pair"));
                }
                self.at += 2;
                let second = self.hex4()?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return Err(self.error("half a surrogate pair"));
                }
                0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
            }
            0xdc00..=0xdfff => return Err(self.error("half a surrogate pair")),
            _ => first,
        };
        char::from_u32(code).ok_or_else(|| self.error("not a character"))
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let digits =
            self.b.get(self.at..self.at + 4).ok_or_else(|| self.error("\\u needs four hex digits"))?;
        let mut n = 0u32;
        for &d in digits {
            let v = (d as char).to_digit(16).ok_or_else(|| self.error("\\u needs four hex digits"))?;
            n = n * 16 + v;
        }
        self.at += 4;
        Ok(n)
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(self.error("not a number")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(self.error("only whole numbers"));
        }
        if matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.error("a number with a leading zero"));
        }
        if self.at - start > MAX_DIGITS {
            return Err(Error { at: start, what: "too long a number" });
        }
        let text = core::str::from_utf8(&self.b[start..self.at]).unwrap();
        if text == "-0" {
            return Err(Error { at: start, what: "-0" });
        }
        Ok(Value::Number(text.into()))
    }
}
