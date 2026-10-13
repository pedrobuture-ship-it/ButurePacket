use std::fmt;

/// Why a layer could not be fully decoded. Parsers never panic: hostile input ends up here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated {
        layer: &'static str,
        needed: usize,
        available: usize,
    },
    Malformed {
        layer: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated {
                layer,
                needed,
                available,
            } => write!(
                f,
                "Truncated {layer} (need {needed} bytes, have {available})"
            ),
            ParseError::Malformed { layer, reason } => write!(f, "Malformed {layer}: {reason}"),
        }
    }
}

impl std::error::Error for ParseError {}

pub(crate) fn need(layer: &'static str, data: &[u8], needed: usize) -> Result<(), ParseError> {
    if data.len() < needed {
        Err(ParseError::Truncated {
            layer,
            needed,
            available: data.len(),
        })
    } else {
        Ok(())
    }
}

pub(crate) fn be16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

pub(crate) fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}
