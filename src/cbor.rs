//! Borrowing CBOR (RFC 8949) reader for the WebAuthn structures:
//! attestationObject, attStmt, COSE_Key and authenticator extensions.
//!
//! Byte and text strings are returned as slices of the input, and arrays
//! and maps as lazy views that decode their items on iteration, so
//! reading never copies the input or allocates. Every length is checked
//! against the remaining input before use, so a hostile length prefix
//! cannot trigger a large allocation.
//!
//! Byte and text strings of indefinite length are refused: they cannot be
//! borrowed, and CTAP2 canonical CBOR, which authenticators emit, never
//! uses them. Indefinite-length arrays and maps are read.

use crate::error::{Error, Result};

/// Deepest nesting accepted, as in ciborium. Real WebAuthn structures
/// nest at most four levels.
const MAX_DEPTH: usize = 256;

const BREAK: u8 = 0xff;

/// One CBOR data item, borrowing from the input.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Value<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the integer `-1 - n`.
    Negative(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Seq<'a>),
    Map(Seq<'a>),
    /// Tag number and the encoded tagged item.
    Tag(u64, &'a [u8]),
    /// Major type 7: simple values and floats, by their encoded bytes.
    Simple(&'a [u8]),
}

/// The items of an array, or the alternating keys and values of a map.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Seq<'a> {
    /// Encoded items, without the container head (and without the break
    /// byte for an indefinite-length container).
    body: &'a [u8],
    /// Number of items (twice the pair count for a map).
    items: u64,
}

impl<'a> Value<'a> {
    /// Integer value, or `None` when this is not an integer or does not fit
    /// in `i64` (no truncation: 2^64 - 7 must not read as -7).
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Unsigned(n) => i64::try_from(n).ok(),
            Value::Negative(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    pub(crate) fn as_bytes(&self) -> Option<&'a [u8]> {
        match *self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub(crate) fn as_text(&self) -> Option<&'a str> {
        match *self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Key-value pairs of a map, or `None` when this is not a map.
    pub(crate) fn as_map(&self) -> Option<Entries<'a>> {
        match *self {
            Value::Map(seq) => Some(Entries(seq.iter())),
            _ => None,
        }
    }

    /// Items of an array, or `None` when this is not an array.
    pub(crate) fn as_array(&self) -> Option<Items<'a>> {
        match *self {
            Value::Array(seq) => Some(seq.iter()),
            _ => None,
        }
    }
}

impl<'a> Seq<'a> {
    fn iter(self) -> Items<'a> {
        Items {
            decoder: Decoder::new(self.body),
            remaining: self.items,
        }
    }
}

/// Iterator over the items of an array (or the keys and values of a map).
/// The items were checked for well-formedness when the container was read,
/// so decoding them again cannot fail.
#[derive(Clone)]
pub(crate) struct Items<'a> {
    decoder: Decoder<'a>,
    remaining: u64,
}

impl<'a> Iterator for Items<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Value<'a>> {
        self.remaining = self.remaining.checked_sub(1)?;
        self.decoder.value().ok()
    }
}

/// Iterator over the key-value pairs of a map.
pub(crate) struct Entries<'a>(Items<'a>);

impl<'a> Iterator for Entries<'a> {
    type Item = (Value<'a>, Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        Some((self.0.next()?, self.0.next()?))
    }
}

/// Reads data items from the front of a byte slice.
#[derive(Clone)]
pub(crate) struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

/// Decodes the single data item that fills `data` exactly.
pub(crate) fn decode_exact(data: &[u8]) -> Result<Value<'_>> {
    let mut decoder = Decoder::new(data);
    let value = decoder.value()?;
    if decoder.position() != data.len() {
        return Err(Error::Cbor("trailing bytes after CBOR item".into()));
    }
    Ok(value)
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes consumed so far.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// Reads the next data item. Containers are checked for well-formedness
    /// in full before the lazy view is returned.
    pub(crate) fn value(&mut self) -> Result<Value<'a>> {
        self.item(0)
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>> {
        if depth > MAX_DEPTH {
            return Err(Error::Cbor("CBOR nested too deeply".into()));
        }
        let start = self.pos;
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if major == 7 {
            return self.simple(start, info);
        }
        if info == 31 {
            return match major {
                4 => self.indefinite(depth).map(Value::Array),
                5 => self.indefinite(depth).map(Value::Map),
                2 | 3 => Err(Error::Cbor("indefinite-length CBOR string".into())),
                _ => Err(Error::Cbor("malformed CBOR head".into())),
            };
        }
        let arg = self.argument(info)?;
        match major {
            0 => Ok(Value::Unsigned(arg)),
            1 => Ok(Value::Negative(arg)),
            2 => self.take(arg).map(Value::Bytes),
            3 => {
                let bytes = self.take(arg)?;
                std::str::from_utf8(bytes)
                    .map(Value::Text)
                    .map_err(|_| Error::Cbor("CBOR text is not UTF-8".into()))
            }
            4 => self.definite(arg, depth).map(Value::Array),
            5 => {
                let items = arg
                    .checked_mul(2)
                    .ok_or_else(|| Error::Cbor("CBOR map too long".into()))?;
                self.definite(items, depth).map(Value::Map)
            }
            _ => {
                let inner_start = self.pos;
                self.item(depth + 1)?;
                Ok(Value::Tag(arg, &self.data[inner_start..self.pos]))
            }
        }
    }

    fn simple(&mut self, start: usize, info: u8) -> Result<Value<'a>> {
        match info {
            0..=23 => {}
            24 => {
                // RFC 8949 §3.3: one-byte simple values below 32 are not well-formed.
                if self.byte()? < 32 {
                    return Err(Error::Cbor("malformed CBOR simple value".into()));
                }
            }
            25 => _ = self.take(2)?,
            26 => _ = self.take(4)?,
            27 => _ = self.take(8)?,
            31 => return Err(Error::Cbor("unexpected CBOR break".into())),
            _ => return Err(Error::Cbor("reserved CBOR simple value".into())),
        }
        Ok(Value::Simple(&self.data[start..self.pos]))
    }

    fn definite(&mut self, items: u64, depth: usize) -> Result<Seq<'a>> {
        let start = self.pos;
        for _ in 0..items {
            self.item(depth + 1)?;
        }
        Ok(Seq {
            body: &self.data[start..self.pos],
            items,
        })
    }

    fn indefinite(&mut self, depth: usize) -> Result<Seq<'a>> {
        let start = self.pos;
        let mut items = 0u64;
        while self.peek()? != BREAK {
            self.item(depth + 1)?;
            items += 1;
        }
        let body = &self.data[start..self.pos];
        self.pos += 1; // the break byte
        Ok(Seq { body, items })
    }

    fn argument(&mut self, info: u8) -> Result<u64> {
        let width = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(Error::Cbor("malformed CBOR head".into())),
        };
        Ok(self
            .take(width)?
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8]> {
        let rest = &self.data[self.pos..];
        let len = usize::try_from(len)
            .ok()
            .filter(|&len| len <= rest.len())
            .ok_or_else(|| Error::Cbor("CBOR item runs past the end of the input".into()))?;
        self.pos += len;
        Ok(&rest[..len])
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1).map(|b| b[0])
    }

    fn peek(&self) -> Result<u8> {
        self.data
            .get(self.pos)
            .copied()
            .ok_or_else(|| Error::Cbor("CBOR item runs past the end of the input".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(value: &ciborium::value::Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).unwrap();
        out
    }

    #[test]
    fn reads_scalars() {
        assert_eq!(decode_exact(&[0x17]).unwrap(), Value::Unsigned(23));
        assert_eq!(decode_exact(&[0x18, 0xff]).unwrap(), Value::Unsigned(255));
        assert_eq!(decode_exact(&[0x26]).unwrap().as_i64(), Some(-7));
        assert_eq!(
            decode_exact(&[0x39, 0x01, 0x00]).unwrap().as_i64(),
            Some(-257)
        );
        assert_eq!(
            decode_exact(&[0x43, 1, 2, 3]).unwrap(),
            Value::Bytes(&[1, 2, 3])
        );
        assert_eq!(
            decode_exact(&[0x62, b'h', b'i']).unwrap(),
            Value::Text("hi")
        );
        assert_eq!(decode_exact(&[0xf5]).unwrap(), Value::Simple(&[0xf5]));
        assert_eq!(
            decode_exact(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            Value::Simple(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn integers_outside_i64_do_not_truncate() {
        let max = [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf9];
        assert_eq!(decode_exact(&max).unwrap().as_i64(), None);
        let min = [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode_exact(&min).unwrap().as_i64(), None);
        let lowest = [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode_exact(&lowest).unwrap().as_i64(), Some(i64::MIN));
    }

    #[test]
    fn matches_ciborium_on_nested_maps() {
        use ciborium::value::Value as C;
        let encoded = encode(&C::Map(vec![
            (C::Text("fmt".into()), C::Text("none".into())),
            (
                C::Text("attStmt".into()),
                C::Map(vec![(
                    C::Text("x5c".into()),
                    C::Array(vec![C::Bytes(vec![9; 300])]),
                )]),
            ),
            (
                C::Integer((-3).into()),
                C::Tag(24, Box::new(C::Bytes(vec![1]))),
            ),
        ]));
        let value = decode_exact(&encoded).unwrap();
        let entries: Vec<_> = value.as_map().unwrap().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], (Value::Text("fmt"), Value::Text("none")));
        let (_, stmt) = entries[1];
        let (key, x5c) = stmt.as_map().unwrap().next().unwrap();
        assert_eq!(key.as_text(), Some("x5c"));
        assert_eq!(
            x5c.as_array().unwrap().next().unwrap().as_bytes(),
            Some(&[9u8; 300][..])
        );
        assert!(matches!(entries[2].1, Value::Tag(24, [0x41, 0x01])));
    }

    #[test]
    fn reads_indefinite_containers() {
        // [_ 1, {_ "a": 2}]
        let data = [0x9f, 0x01, 0xbf, 0x61, b'a', 0x02, 0xff, 0xff];
        let value = decode_exact(&data).unwrap();
        let items: Vec<_> = value.as_array().unwrap().collect();
        assert_eq!(items[0], Value::Unsigned(1));
        assert_eq!(
            items[1].as_map().unwrap().next(),
            Some((Value::Text("a"), Value::Unsigned(2)))
        );
    }

    #[test]
    fn refuses_malformed_input() {
        for (data, case) in [
            (&[][..], "empty"),
            (&[0x5f, 0x41, 0x00, 0xff], "indefinite byte string"),
            (&[0x7f, 0x61, b'a', 0xff], "indefinite text string"),
            (&[0x1f], "indefinite integer"),
            (&[0xff], "lone break"),
            (&[0x1c], "reserved additional info"),
            (&[0xf8, 0x10], "two-byte simple below 32"),
            (
                &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "huge byte string",
            ),
            (
                &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "huge array",
            ),
            (&[0xbb, 0x80, 0, 0, 0, 0, 0, 0, 0], "map count overflow"),
            (&[0x62, 0xff, 0xfe], "text not UTF-8"),
            (&[0x9f, 0x01], "unterminated indefinite array"),
            (&[0x01, 0x02], "trailing byte"),
        ] {
            assert!(decode_exact(data).is_err(), "{case}");
        }
    }

    #[test]
    fn refuses_deep_nesting() {
        let ok = [vec![0x81; MAX_DEPTH], vec![0x00]].concat();
        assert!(decode_exact(&ok).is_ok());
        let deep = [vec![0x81; MAX_DEPTH + 1], vec![0x00]].concat();
        assert!(decode_exact(&deep).is_err());
    }
}
