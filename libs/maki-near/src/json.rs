//! JSON, read strictly (RFC 8259, as serde_json reads it, which is how contracts written with
//! near-sdk read their arguments): a call's arguments, to say whether they're JSON, and to read the
//! token transfers maki spells out. Strings come out decoded (escapes, and surrogate pairs as the
//! one character they are). A lone surrogate, a control character left raw in a string, a number
//! written any other way, anything after the value, or nesting deeper than `MAX_DEPTH`, and it isn't
//! JSON to maki.

use alloc::string::String;
use alloc::vec::Vec;

/// The deepest nesting maki follows: arguments of 4 KiB at most need no more.
pub const MAX_DEPTH: usize = 32;

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A number, as it's written.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// An object's members, in order. A name may be there twice: JSON allows it, and readers
    /// differ on which they take, so maki spells nothing out of such an object.
    Object(Vec<(String, Value)>),
}

/// The JSON value `bytes` are, whole: UTF-8, one value, nothing but whitespace around it.
pub fn parse(bytes: &[u8]) -> Option<Value> {
    let text = core::str::from_utf8(bytes).ok()?;
    let mut p = Parser { b: text.as_bytes(), at: 0 };
    p.space();
    let v = p.value(0)?;
    p.space();
    (p.at == p.b.len()).then_some(v)
}

impl Value {
    /// An object's members, if it's an object in which no name is given twice.
    pub fn members(&self) -> Option<&[(String, Value)]> {
        let Value::Object(m) = self else { return None };
        let unique = m.iter().enumerate().all(|(i, (name, _))| m[..i].iter().all(|(other, _)| other != name));
        unique.then_some(m.as_slice())
    }
}

struct Parser<'a> {
    b: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> { self.b.get(self.at).copied() }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.at += 1;
        Some(c)
    }

    fn eat(&mut self, c: u8) -> Option<()> { (self.next()? == c).then_some(()) }

    /// JSON's whitespace: space, tab, newline, carriage return.
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Value::String),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Option<Value> {
        let end = self.at.checked_add(word.len())?;
        (self.b.get(self.at..end)? == word).then(|| {
            self.at = end;
            v
        })
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.eat(b'{')?;
        self.space();
        let mut members = Vec::new();
        if self.peek()? == b'}' {
            self.at += 1;
            return Some(Value::Object(members));
        }
        loop {
            self.space();
            let name = self.string()?;
            self.space();
            self.eat(b':')?;
            self.space();
            let v = self.value(depth)?;
            members.push((name, v));
            self.space();
            match self.next()? {
                b',' => continue,
                b'}' => return Some(Value::Object(members)),
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.eat(b'[')?;
        self.space();
        let mut items = Vec::new();
        if self.peek()? == b']' {
            self.at += 1;
            return Some(Value::Array(items));
        }
        loop {
            self.space();
            items.push(self.value(depth)?);
            self.space();
            match self.next()? {
                b',' => continue,
                b']' => return Some(Value::Array(items)),
                _ => return None,
            }
        }
    }

    /// A number: `-`, an integer part with no zero before it (but zero), then a fraction and an
    /// exponent, each if it's there.
    fn number(&mut self) -> Option<Value> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.next()? {
            b'0' => {}
            b'1'..=b'9' => self.digits(),
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            self.digit()?;
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            self.digit()?;
            self.digits();
        }
        // ASCII, so a string as it stands
        let text = core::str::from_utf8(&self.b[start..self.at]).ok()?;
        Some(Value::Number(String::from(text)))
    }

    fn digit(&mut self) -> Option<()> { self.next().filter(u8::is_ascii_digit).map(|_| ()) }

    fn digits(&mut self) {
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.at += 1;
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut n = 0;
        for _ in 0..4 {
            n = n * 16 + (self.next()? as char).to_digit(16)?;
        }
        Some(n)
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        loop {
            match self.next()? {
                b'"' => break,
                b'\\' => {
                    let c = match self.next()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let high = self.hex4()?;
                            let code = match high {
                                // a surrogate pair: the high half, then the low
                                0xd800..=0xdbff => {
                                    self.eat(b'\\')?;
                                    self.eat(b'u')?;
                                    let low = self.hex4()?;
                                    if !(0xdc00..=0xdfff).contains(&low) {
                                        return None;
                                    }
                                    0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                                }
                                0xdc00..=0xdfff => return None,
                                c => c,
                            };
                            char::from_u32(code)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                // control characters must be escaped
                c if c < 0x20 => return None,
                c => out.push(c),
            }
        }
        // the text was UTF-8, split only at ASCII, and escapes add only characters
        String::from_utf8(out).ok()
    }
}
