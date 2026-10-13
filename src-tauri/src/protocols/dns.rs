//! DNS message decoder (A, AAAA, CNAME, PTR answers). Names are untrusted: pointer loops,
//! oversize labels and non-printable bytes are all handled without panicking.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::error::{ParseError, be16, be32, need};

const MAX_NAME_LEN: usize = 255;
const MAX_POINTER_JUMPS: usize = 16;
const MAX_QUESTIONS: usize = 16;
const MAX_RECORDS: usize = 256;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;

pub const RCODE_NOERROR: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    /// Offset of the encoded name within the DNS message, and its length on the wire.
    pub name_offset: usize,
    pub name_wire_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ptr(String),
    /// Record types that are not decoded.
    Other,
}

impl RData {
    pub fn text(&self) -> String {
        match self {
            RData::A(a) => a.to_string(),
            RData::Aaaa(a) => a.to_string(),
            RData::Cname(n) | RData::Ptr(n) => n.clone(),
            RData::Other => "(not decoded)".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    pub id: u16,
    pub flags: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub truncated: bool,
    pub question_count: u16,
    pub answer_count: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    /// True when answer decoding stopped early (truncation, limits or malformed data).
    pub incomplete: bool,
}

pub fn type_name(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_NS => "NS".into(),
        TYPE_CNAME => "CNAME".into(),
        6 => "SOA".into(),
        TYPE_PTR => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        TYPE_AAAA => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        n => format!("TYPE{n}"),
    }
}

pub fn rcode_name(r: u8) -> String {
    match r {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        n => format!("RCODE{n}"),
    }
}

/// Reads a (possibly compressed) name starting at `pos`. Returns the text form and the
/// position just after the name *in the original byte stream* (pointers don't advance it).
fn read_name(msg: &[u8], pos: usize) -> Result<(String, usize), ParseError> {
    let malformed = |reason| ParseError::Malformed {
        layer: "DNS",
        reason,
    };
    let mut out = String::new();
    let mut cursor = pos;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(cursor).ok_or(ParseError::Truncated {
            layer: "DNS name",
            needed: cursor + 1,
            available: msg.len(),
        })?;
        match len {
            0 => {
                cursor += 1;
                break;
            }
            l if l & 0xC0 == 0xC0 => {
                let low = *msg.get(cursor + 1).ok_or(ParseError::Truncated {
                    layer: "DNS name",
                    needed: cursor + 2,
                    available: msg.len(),
                })?;
                end.get_or_insert(cursor + 2);
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(malformed("compression pointer loop"));
                }
                cursor = (usize::from(l & 0x3F) << 8) | usize::from(low);
            }
            l if l & 0xC0 != 0 => return Err(malformed("reserved label type")),
            l => {
                let l = usize::from(l);
                let label = msg
                    .get(cursor + 1..cursor + 1 + l)
                    .ok_or(ParseError::Truncated {
                        layer: "DNS name",
                        needed: cursor + 1 + l,
                        available: msg.len(),
                    })?;
                if !out.is_empty() {
                    out.push('.');
                }
                for &b in label {
                    match b {
                        b'.' | b'\\' => {
                            out.push('\\');
                            out.push(b as char);
                        }
                        0x21..=0x7e => out.push(b as char),
                        _ => out.push_str(&format!("\\{b:03}")),
                    }
                }
                if out.len() > MAX_NAME_LEN * 4 {
                    return Err(malformed("name too long"));
                }
                cursor += 1 + l;
            }
        }
    }
    if out.is_empty() {
        out.push('.');
    }
    Ok((out, end.unwrap_or(cursor)))
}

/// Decodes one DNS message (UDP payload, or TCP payload with the length prefix removed).
pub fn parse(msg: &[u8]) -> Result<Dns, ParseError> {
    need("DNS", msg, 12)?;
    let flags = be16(msg, 2);
    let (qd, an) = (be16(msg, 4), be16(msg, 6));
    if qd == 0 && an == 0 && flags & 0x8000 == 0 {
        return Err(ParseError::Malformed {
            layer: "DNS",
            reason: "message without questions",
        });
    }
    let mut pos = 12;
    let mut questions = Vec::new();
    for _ in 0..usize::from(qd).min(MAX_QUESTIONS) {
        let (name, next) = read_name(msg, pos)?;
        need("DNS question", msg, next + 4)?;
        questions.push(Question {
            name,
            qtype: be16(msg, next),
            name_offset: pos,
            name_wire_len: next - pos,
        });
        pos = next + 4;
    }
    let mut dns = Dns {
        id: be16(msg, 0),
        flags,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0F) as u8,
        rcode: (flags & 0x0F) as u8,
        truncated: flags & 0x0200 != 0,
        question_count: qd,
        answer_count: an,
        questions,
        answers: Vec::new(),
        incomplete: usize::from(qd) > MAX_QUESTIONS || usize::from(an) > MAX_RECORDS,
    };
    for _ in 0..usize::from(an).min(MAX_RECORDS) {
        match read_record(msg, pos) {
            Ok((rec, next)) => {
                dns.answers.push(rec);
                pos = next;
            }
            Err(_) => {
                dns.incomplete = true;
                break;
            }
        }
    }
    Ok(dns)
}

fn read_record(msg: &[u8], pos: usize) -> Result<(Record, usize), ParseError> {
    let (name, next) = read_name(msg, pos)?;
    need("DNS record", msg, next + 10)?;
    let (rtype, ttl, rdlen) = (
        be16(msg, next),
        be32(msg, next + 4),
        usize::from(be16(msg, next + 8)),
    );
    let start = next + 10;
    need("DNS record data", msg, start + rdlen)?;
    let rdata = &msg[start..start + rdlen];
    let data = match rtype {
        TYPE_A if rdlen == 4 => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
        TYPE_AAAA if rdlen == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rdata);
            RData::Aaaa(Ipv6Addr::from(a))
        }
        TYPE_CNAME => RData::Cname(read_name(msg, start)?.0),
        TYPE_PTR => RData::Ptr(read_name(msg, start)?.0),
        _ => RData::Other,
    };
    Ok((
        Record {
            name,
            rtype,
            ttl,
            data,
        },
        start + rdlen,
    ))
}

impl Dns {
    /// One-line summary in the style of "Standard query A api.github.com".
    pub fn describe(&self) -> String {
        let q = self.questions.first();
        let qt = q.map(|q| type_name(q.qtype)).unwrap_or_default();
        let qn = q.map(|q| q.name.as_str()).unwrap_or("");
        if !self.is_response {
            return format!("Standard query {qt} {qn}").trim_end().to_string();
        }
        if self.rcode != RCODE_NOERROR {
            return format!(
                "Standard query response {} {qt} {qn}",
                rcode_name(self.rcode)
            )
            .trim_end()
            .to_string();
        }
        let answers: Vec<String> = self.answers.iter().take(3).map(|a| a.data.text()).collect();
        let more = if self.answers.len() > 3 { ", …" } else { "" };
        if answers.is_empty() {
            format!("Standard query response {qt} {qn} (no answers)")
        } else {
            format!(
                "Standard query response {qt} {} {}{more}",
                qn,
                answers.join(", ")
            )
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn encode_name(name: &str) -> Vec<u8> {
        let mut v = vec![];
        for label in name.split('.').filter(|l| !l.is_empty()) {
            v.push(label.len() as u8);
            v.extend(label.as_bytes());
        }
        v.push(0);
        v
    }

    /// Standard query for `name`.
    pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        m.extend(encode_name(name));
        m.extend([(qtype >> 8) as u8, qtype as u8, 0, 1]);
        m
    }

    /// Response with a CNAME (compressed) followed by A records.
    pub fn response(
        id: u16,
        name: &str,
        cname: Option<&str>,
        addrs: &[[u8; 4]],
        ttl: u32,
        rcode: u8,
    ) -> Vec<u8> {
        let mut m = query(id, name, TYPE_A);
        m[2] = 0x81;
        m[3] = 0x80 | rcode;
        let count = addrs.len() + usize::from(cname.is_some());
        m[6] = (count >> 8) as u8;
        m[7] = count as u8;
        let mut owner: Vec<u8> = vec![0xC0, 12];
        if let Some(c) = cname {
            m.extend(&owner);
            m.extend([0, 5, 0, 1]);
            m.extend(ttl.to_be_bytes());
            let enc = encode_name(c);
            m.extend((enc.len() as u16).to_be_bytes());
            m.extend(&enc);
            // later answers are owned by the CNAME target; point at its position
            let target_pos = m.len() - enc.len();
            owner = vec![0xC0 | (target_pos >> 8) as u8, target_pos as u8];
        }
        for a in addrs {
            m.extend(&owner);
            m.extend([0, 1, 0, 1]);
            m.extend(ttl.to_be_bytes());
            m.extend([0, 4]);
            m.extend(a);
        }
        m
    }

    #[test]
    fn parses_query() {
        let d = parse(&query(0x1a2b, "api.github.com", TYPE_A)).unwrap();
        assert_eq!((d.id, d.is_response, d.rcode), (0x1a2b, false, 0));
        assert_eq!(d.questions[0].name, "api.github.com");
        assert_eq!(d.questions[0].name_offset, 12);
        assert_eq!(d.questions[0].name_wire_len, 16);
        assert_eq!(d.describe(), "Standard query A api.github.com");
    }

    #[test]
    fn parses_response_with_cname_and_compression() {
        let m = response(
            7,
            "api.github.com",
            Some("lb.github.com"),
            &[[140, 82, 121, 5], [140, 82, 121, 6]],
            60,
            0,
        );
        let d = parse(&m).unwrap();
        assert!(d.is_response && !d.incomplete);
        assert_eq!(d.answers.len(), 3);
        assert_eq!(d.answers[0].data, RData::Cname("lb.github.com".into()));
        assert_eq!(d.answers[1].name, "lb.github.com");
        assert_eq!(d.answers[1].data, RData::A(Ipv4Addr::new(140, 82, 121, 5)));
        assert_eq!(d.answers[1].ttl, 60);
        assert_eq!(
            d.describe(),
            "Standard query response A api.github.com lb.github.com, 140.82.121.5, 140.82.121.6"
        );
    }

    #[test]
    fn parses_aaaa_and_ptr() {
        let mut m = query(1, "1.0.0.127.in-addr.arpa", TYPE_PTR);
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 1;
        m.extend([0xC0, 12, 0, 12, 0, 1, 0, 0, 1, 0]);
        let ptr = encode_name("localhost");
        m.extend((ptr.len() as u16).to_be_bytes());
        m.extend(&ptr);
        assert_eq!(
            parse(&m).unwrap().answers[0].data,
            RData::Ptr("localhost".into())
        );

        let mut m = query(2, "v6.example", TYPE_AAAA);
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 1;
        m.extend([0xC0, 12, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        m.extend([
            0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ]);
        assert_eq!(parse(&m).unwrap().answers[0].data.text(), "2606:4700::1111");
    }

    #[test]
    fn error_responses_are_described() {
        let m = response(9, "nope.invalid", None, &[], 0, 3);
        let d = parse(&m).unwrap();
        assert_eq!(d.rcode, 3);
        assert_eq!(
            d.describe(),
            "Standard query response NXDOMAIN A nope.invalid"
        );
    }

    #[test]
    fn pointer_loops_are_rejected() {
        let mut m = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xC0, 12, 0, 1, 0, 1]); // name points at itself
        assert!(matches!(parse(&m), Err(ParseError::Malformed { .. })));
    }

    #[test]
    fn reserved_labels_and_truncation_are_rejected() {
        let mut m = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0x80, 1, 2, 0, 0, 1, 0, 1]);
        assert!(matches!(parse(&m), Err(ParseError::Malformed { .. })));
        let q = query(1, "example.com", 1);
        for n in 0..q.len() {
            assert!(parse(&q[..n]).is_err(), "prefix {n} must not parse");
        }
        assert!(parse(&[0; 5]).is_err());
    }

    #[test]
    fn truncated_answers_keep_what_was_decoded() {
        let m = response(3, "a.example", None, &[[1, 1, 1, 1], [2, 2, 2, 2]], 10, 0);
        let cut = &m[..m.len() - 3];
        let d = parse(cut).unwrap();
        assert!(d.incomplete);
        assert_eq!(d.answers.len(), 1);
    }

    #[test]
    fn hostile_names_are_escaped_not_trusted() {
        let mut m = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([5, b'a', 0x1b, b'[', b'3', b'1', 3, b'c', b'o', b'.', 0]);
        m.extend([0, 1, 0, 1]);
        let d = parse(&m).unwrap();
        assert_eq!(d.questions[0].name, "a\\027[31.co\\.");
        assert!(
            d.questions[0]
                .name
                .bytes()
                .all(|b| (0x21..0x7f).contains(&b))
        );
    }

    #[test]
    fn counts_are_bounded() {
        let mut m = query(1, "x.example", 1);
        m[6] = 0xff;
        m[7] = 0xff; // claims 65535 answers, none present
        let d = parse(&m).unwrap();
        assert!(d.incomplete && d.answers.is_empty());
    }

    #[test]
    fn no_panic_on_mutated_messages() {
        let base = response(
            5,
            "api.github.com",
            Some("lb.github.com"),
            &[[1, 2, 3, 4]],
            5,
            0,
        );
        for i in 0..base.len() {
            for v in [0u8, 0x3f, 0x40, 0xc0, 0xff] {
                let mut m = base.clone();
                m[i] = v;
                let _ = parse(&m);
            }
        }
    }
}
