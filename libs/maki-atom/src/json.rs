//! JSON as a Cosmos chain writes a sign doc (SIGN_MODE_LEGACY_AMINO_JSON: the SDK's x/tx writes it
//! with Go's `encoding/json`), and as CosmJS's `serializeSignDoc` writes it too: nothing between
//! the parts, no space or line break; each object's names once, in the order of their bytes;
//! `<`, `>` and `&` in strings written `\u003c`, `\u003e` and `\u0026`, as Go writes them; numbers
//! whole. There's one way of writing each document, and maki reads only that: what it read,
//! written again, is the document itself (`parse` checks), so what it shows is what it signs.
//!
//! It refuses what the chain and CosmJS would write differently, rather than guess which the
//! signature will be checked against (U+2028 and U+2029, which Go escapes and JavaScript doesn't;
//! `-0`; numbers a double can't hold, which Go reads a contract's JSON into), and what it couldn't
//! show (control characters, but line breaks).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// How deep arrays and objects may nest. A sign doc's own go five deep; a contract's message in one
/// can go deeper.
pub const MAX_DEPTH: usize = 20;
/// The largest whole number a document may hold: 2^53 - 1, the largest a double holds exactly.
pub const MAX_NUMBER: i64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<Value>),
    /// Its fields, in order: their names' bytes ascending, no name twice.
    Object(Vec<(String, Value)>),
}

/// Where the text stopped being JSON as Cosmos writes it, and why.
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

/// One value, written as Cosmos writes it, and nothing after it.
pub fn parse(bytes: &[u8]) -> Result<Value, Error> {
    let text = core::str::from_utf8(bytes).map_err(|e| Error { at: e.valid_up_to(), what: "not UTF-8" })?;
    let mut p = Parser { text, at: 0 };
    let value = p.value(0)?;
    if p.at != bytes.len() {
        return Err(p.error("more after the end"));
    }
    // the one way of writing it: anything the rules above let through that the chain would write
    // another way stops here
    let again = write(&value);
    if again.as_bytes() != bytes {
        let at = again.bytes().zip(bytes).position(|(a, &b)| a != b).unwrap_or(again.len().min(bytes.len()));
        return Err(Error { at, what: "not written as Cosmos writes it" });
    }
    Ok(value)
}

/// `value` as Cosmos writes it. For a value `parse` read, the very bytes it read.
pub fn write(value: &Value) -> String {
    let mut out = String::new();
    write_into(&mut out, value);
    out
}

fn write_into(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        Value::String(s) => quote(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_into(out, item);
            }
            out.push(']');
        }
        Value::Object(fields) => {
            out.push('{');
            for (i, (name, item)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                quote(out, name);
                out.push(':');
                write_into(out, item);
            }
            out.push('}');
        }
    }
}

/// A string as Go's `encoding/json` writes it (what CosmJS's `escapeCharacters` copies): only what
/// must be escaped, and the three characters HTML gives meaning to.
fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn error(&self, what: &'static str) -> Error { Error { at: self.at, what } }

    fn peek(&self) -> Option<u8> { self.text.as_bytes().get(self.at).copied() }

    /// Why the next byte isn't what should be there.
    fn unexpected(&self, expected: &'static str) -> Error {
        match self.peek() {
            None => self.error("cut short"),
            Some(b' ' | b'\t' | b'\n' | b'\r') => {
                self.error("a space or line break, which Cosmos doesn't write")
            }
            Some(_) => self.error(expected),
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
            _ => Err(self.unexpected("not a value")),
        }
    }

    fn word(&mut self, word: &str, value: Value) -> Result<Value, Error> {
        if !self.text[self.at..].starts_with(word) {
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
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.unexpected("a name expected"));
            }
            let start = self.at;
            let name = self.string()?;
            if let Some((last, _)) = fields.last() {
                if name.as_bytes() <= last.as_bytes() {
                    let what = if name == *last { "a name given twice" } else { "names out of order" };
                    return Err(Error { at: start, what });
                }
            }
            if self.peek() != Some(b':') {
                return Err(self.unexpected("':' expected"));
            }
            self.at += 1;
            let value = self.value(depth + 1)?;
            fields.push((name, value));
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return Err(self.unexpected("',' or '}' expected")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= MAX_DEPTH {
            return Err(self.error("nested too deep"));
        }
        self.at += 1;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.unexpected("',' or ']' expected")),
            }
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        let start = self.at;
        self.at += 1;
        let mut out = String::new();
        loop {
            let plain = self.at;
            while let Some(c) = self.peek() {
                if matches!(c, b'"' | b'\\' | b'<' | b'>' | b'&') || c < 0x20 {
                    break;
                }
                self.at += 1;
            }
            // up to an ASCII byte, so at a character's end
            out.push_str(&self.text[plain..self.at]);
            match self.peek() {
                None => return Err(self.error("a string that doesn't end")),
                Some(b'"') => {
                    self.at += 1;
                    break;
                }
                Some(b'\\') => {
                    let c = match self.text.as_bytes().get(self.at + 1) {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'n') => '\n',
                        Some(b'u') => match self.text.get(self.at + 2..self.at + 6) {
                            Some("0026") => '&',
                            Some("003c") => '<',
                            Some("003e") => '>',
                            _ => return Err(self.error("an escape Cosmos doesn't write")),
                        },
                        _ => return Err(self.error("an escape Cosmos doesn't write")),
                    };
                    self.at += if c == '&' || c == '<' || c == '>' { 6 } else { 2 };
                    out.push(c);
                }
                Some(b'<' | b'>' | b'&') => {
                    return Err(self.error("<, > or & as Cosmos doesn't write them: it escapes them"));
                }
                Some(_) => return Err(self.error("a control character in a string")),
            }
        }
        for c in out.chars() {
            if c == '\u{2028}' || c == '\u{2029}' {
                return Err(Error {
                    at: start,
                    what: "U+2028 or U+2029, which Go and JavaScript write differently",
                });
            }
            if c.is_control() && c != '\n' {
                return Err(Error { at: start, what: "a control character maki can't show" });
            }
        }
        Ok(out)
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        let digits = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        let digits = &self.text[digits..self.at];
        if digits.is_empty() {
            return Err(self.error("not a number"));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(
                self.error("a number that isn't whole, which Go and JavaScript may write differently")
            );
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(Error { at: start, what: "a number with a leading zero" });
        }
        let n = digits.parse::<i64>().ok().filter(|&n| n <= MAX_NUMBER);
        let Some(n) = n else {
            return Err(Error { at: start, what: "a number too big for a double to hold" });
        };
        if negative && n == 0 {
            return Err(Error { at: start, what: "-0, which Go and JavaScript write differently" });
        }
        Ok(Value::Number(if negative { -n } else { n }))
    }
}
