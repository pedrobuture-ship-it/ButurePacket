//! TLS record/handshake *metadata* decoder. Nothing is decrypted: only what the protocol
//! sends in the clear (ClientHello, ServerHello and, before TLS 1.3, the certificate).
//! Every field is best effort and absent when it cannot be read.

use serde::Serialize;

const CT_CCS: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPDATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;

const EXT_SNI: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

const MAX_STRING: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub supported_versions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub selected_version: Option<u16>,
    pub cipher_suite: u16,
    pub alpn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertMeta {
    pub subject_cn: Option<String>,
    pub subject_org: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub dns_names: Vec<String>,
}

/// What one buffer of TLS bytes revealed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsParse {
    /// Content types of the records seen, in order.
    pub record_types: Vec<u8>,
    /// Handshake message types seen (complete ones only), in order.
    pub handshake_types: Vec<u8>,
    pub client_hello: Option<ClientHello>,
    pub server_hello: Option<ServerHello>,
    pub certificate: Option<CertMeta>,
    /// A change-cipher-spec, alert or application-data record was seen: later records are opaque.
    pub saw_non_handshake: bool,
}

/// Cheap check for "this payload starts with a plausible TLS record header".
pub fn looks_like_tls(p: &[u8]) -> bool {
    p.len() >= 5 && (CT_CCS..=CT_APPDATA).contains(&p[0]) && p[1] == 3 && p[2] <= 4 && {
        let len = usize::from(u16::from_be_bytes([p[3], p[4]]));
        len > 0 && len <= 16_384 + 2048
    }
}

pub fn version_name(v: u16) -> String {
    match v {
        0x0304 => "TLS 1.3".into(),
        0x0303 => "TLS 1.2".into(),
        0x0302 => "TLS 1.1".into(),
        0x0301 => "TLS 1.0".into(),
        0x0300 => "SSL 3.0".into(),
        other => format!("0x{other:04x}"),
    }
}

fn is_grease(v: u16) -> bool {
    v & 0x0F0F == 0x0A0A && (v >> 8) == (v & 0xFF)
}

pub fn cipher_suite_name(id: u16) -> String {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        other => return format!("0x{other:04x}"),
    }
    .to_string()
}

/// Printable-ASCII rendering of untrusted bytes, escaping anything else, bounded in length.
fn safe_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if out.len() >= MAX_STRING {
            out.push('…');
            break;
        }
        match b {
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

struct Cursor<'a> {
    d: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.d.split_at_checked(n)?;
        self.d = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
    fn is_empty(&self) -> bool {
        self.d.is_empty()
    }
}

/// Walks the records in `data`. Handshake record payloads are concatenated (messages may span records).
pub fn parse(data: &[u8]) -> TlsParse {
    let mut out = TlsParse::default();
    let mut handshake = Vec::new();
    let mut c = Cursor { d: data };
    while c.d.len() >= 5 {
        let (ct, major) = (c.d[0], c.d[1]);
        if !(CT_CCS..=CT_APPDATA).contains(&ct) || major != 3 {
            break;
        }
        let len = usize::from(u16::from_be_bytes([c.d[3], c.d[4]]));
        c.take(5);
        let body = c.take(len.min(c.d.len())).unwrap_or(&[]);
        out.record_types.push(ct);
        if ct == CT_HANDSHAKE && !out.saw_non_handshake {
            handshake.extend_from_slice(body);
        } else if ct != CT_HANDSHAKE {
            // Everything after a CCS/alert/app-data record is encrypted: still listed, never decoded.
            out.saw_non_handshake = true;
        }
        if body.len() < len {
            break; // truncated record
        }
    }
    parse_handshakes(&handshake, &mut out);
    out
}

fn parse_handshakes(buf: &[u8], out: &mut TlsParse) {
    let mut c = Cursor { d: buf };
    while !c.is_empty() {
        let (Some(kind), Some(len)) = (c.u8(), c.u24()) else {
            break;
        };
        let Some(body) = c.take(len) else { break }; // message continues in a later segment
        out.handshake_types.push(kind);
        match kind {
            HS_CLIENT_HELLO if out.client_hello.is_none() => {
                out.client_hello = parse_client_hello(body)
            }
            HS_SERVER_HELLO if out.server_hello.is_none() => {
                out.server_hello = parse_server_hello(body)
            }
            HS_CERTIFICATE if out.certificate.is_none() => {
                out.certificate = parse_certificate_message(body)
            }
            _ => {}
        }
    }
}

fn parse_client_hello(body: &[u8]) -> Option<ClientHello> {
    let mut c = Cursor { d: body };
    let mut hello = ClientHello {
        legacy_version: c.u16()?,
        ..Default::default()
    };
    c.take(32)?; // random
    c.vec8()?; // session id
    let mut suites = Cursor { d: c.vec16()? };
    while let Some(id) = suites.u16() {
        if !is_grease(id) {
            hello.cipher_suites.push(id);
        }
    }
    c.vec8()?; // compression methods
    if c.is_empty() {
        return Some(hello); // no extensions
    }
    let mut exts = Cursor { d: c.vec16()? };
    while let (Some(kind), Some(data)) = (exts.u16(), exts.vec16()) {
        let mut e = Cursor { d: data };
        match kind {
            EXT_SNI => {
                let mut list = Cursor {
                    d: e.vec16().unwrap_or(&[]),
                };
                while let (Some(name_type), Some(name)) = (list.u8(), list.vec16()) {
                    if name_type == 0 && hello.sni.is_none() {
                        hello.sni = Some(safe_text(name));
                    }
                }
            }
            EXT_ALPN => {
                let mut list = Cursor {
                    d: e.vec16().unwrap_or(&[]),
                };
                while let Some(proto) = list.vec8() {
                    hello.alpn.push(safe_text(proto));
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut list = Cursor {
                    d: e.vec8().unwrap_or(&[]),
                };
                while let Some(v) = list.u16() {
                    if !is_grease(v) {
                        hello.supported_versions.push(v);
                    }
                }
            }
            _ => {}
        }
    }
    Some(hello)
}

fn parse_server_hello(body: &[u8]) -> Option<ServerHello> {
    let mut c = Cursor { d: body };
    let mut hello = ServerHello {
        legacy_version: c.u16()?,
        ..Default::default()
    };
    c.take(32)?;
    c.vec8()?;
    hello.cipher_suite = c.u16()?;
    c.u8()?; // compression
    if c.is_empty() {
        return Some(hello);
    }
    let mut exts = Cursor { d: c.vec16()? };
    while let (Some(kind), Some(data)) = (exts.u16(), exts.vec16()) {
        match kind {
            EXT_SUPPORTED_VERSIONS if data.len() == 2 => {
                hello.selected_version = Some(u16::from_be_bytes([data[0], data[1]]))
            }
            EXT_ALPN => {
                let mut e = Cursor { d: data };
                let mut list = Cursor {
                    d: e.vec16().unwrap_or(&[]),
                };
                hello.alpn = list.vec8().map(safe_text);
            }
            _ => {}
        }
    }
    Some(hello)
}

fn parse_certificate_message(body: &[u8]) -> Option<CertMeta> {
    let mut c = Cursor { d: body };
    let total = c.u24()?;
    let mut list = Cursor {
        d: c.take(total.min(c.d.len()))?,
    };
    let n = list.u24()?;
    let der = list.take(n)?;
    parse_x509(der)
}

// ---- minimal DER reader for certificate metadata ----

struct Der<'a> {
    d: &'a [u8],
}

impl<'a> Der<'a> {
    /// Next TLV: (tag, content). Rejects indefinite lengths and lengths wider than 4 bytes.
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.d.first()?;
        let first = *self.d.get(1)?;
        let (len, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7F);
            if n == 0 || n > 4 {
                return None;
            }
            let bytes = self.d.get(2..2 + n)?;
            (
                bytes.iter().fold(0usize, |a, b| (a << 8) | usize::from(*b)),
                2 + n,
            )
        };
        let content = self.d.get(header..header.checked_add(len)?)?;
        self.d = &self.d[header + len..];
        Some((tag, content))
    }
}

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_ORG: &[u8] = &[0x55, 0x04, 0x0A];
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];

fn name_attrs(name: &[u8]) -> (Option<String>, Option<String>) {
    let (mut cn, mut org) = (None, None);
    let mut rdns = Der { d: name };
    while let Some((_, set)) = rdns.next() {
        let mut attrs = Der { d: set };
        while let Some((_, atv)) = attrs.next() {
            let mut p = Der { d: atv };
            let (Some((_, oid)), Some((_, value))) = (p.next(), p.next()) else {
                continue;
            };
            if oid == OID_CN && cn.is_none() {
                cn = Some(safe_text(value));
            } else if oid == OID_ORG && org.is_none() {
                org = Some(safe_text(value));
            }
        }
    }
    (cn, org)
}

/// UTCTime `YYMMDDHHMMSSZ` / GeneralizedTime `YYYYMMDDHHMMSSZ` → `YYYY-MM-DD HH:MM:SS UTC`.
fn format_time(tag: u8, v: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(v).ok()?;
    let (year, rest) = match tag {
        0x17 if s.len() >= 12 => {
            let yy: u32 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 if s.len() >= 14 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let digits = |i: usize| {
        rest.get(i..i + 2)
            .filter(|x| x.bytes().all(|b| b.is_ascii_digit()))
    };
    Some(format!(
        "{year:04}-{}-{} {}:{}:{} UTC",
        digits(0)?,
        digits(2)?,
        digits(4)?,
        digits(6)?,
        digits(8)?
    ))
}

fn parse_x509(der: &[u8]) -> Option<CertMeta> {
    let (_, cert) = Der { d: der }.next()?;
    let (_, tbs) = Der { d: cert }.next()?;
    let mut f = Der { d: tbs };
    let (mut tag, mut item) = f.next()?;
    if tag == 0xA0 {
        (tag, item) = f.next()?; // skip explicit version, `item` is now the serial number
    }
    let _ = (tag, item);
    f.next()?; // signature algorithm
    let (_, issuer) = f.next()?;
    let (_, validity) = f.next()?;
    let (_, subject) = f.next()?;
    let mut meta = CertMeta::default();
    (meta.issuer_cn, meta.issuer_org) = name_attrs(issuer);
    (meta.subject_cn, meta.subject_org) = name_attrs(subject);
    let mut v = Der { d: validity };
    if let (Some((t1, nb)), Some((t2, na))) = (v.next(), v.next()) {
        meta.not_before = format_time(t1, nb);
        meta.not_after = format_time(t2, na);
    }
    f.next()?; // subjectPublicKeyInfo
    while let Some((tag, ext_wrapper)) = f.next() {
        if tag != 0xA3 {
            continue;
        }
        let (_, exts) = Der { d: ext_wrapper }.next()?;
        let mut list = Der { d: exts };
        while let Some((_, ext)) = list.next() {
            let mut e = Der { d: ext };
            let Some((_, oid)) = e.next() else { continue };
            if oid != OID_SAN {
                continue;
            }
            // optional `critical` BOOLEAN precedes the OCTET STRING
            let Some((mut t, mut val)) = e.next() else {
                continue;
            };
            if t == 0x01 {
                (t, val) = e.next()?;
            }
            let _ = t;
            let (_, names) = Der { d: val }.next()?;
            let mut gn = Der { d: names };
            while let Some((tag, name)) = gn.next() {
                if tag == 0x82 && meta.dns_names.len() < 10 {
                    meta.dns_names.push(safe_text(name));
                }
            }
        }
    }
    Some(meta)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn u16b(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    fn vec16(d: &[u8]) -> Vec<u8> {
        let mut v = u16b(d.len() as u16).to_vec();
        v.extend(d);
        v
    }

    fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut v = u16b(kind).to_vec();
        v.extend(vec16(data));
        v
    }

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![
            kind,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        v.extend(body);
        v
    }

    pub fn record(ct: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![ct, 3, 1];
        v.extend(u16b(body.len() as u16));
        v.extend(body);
        v
    }

    pub fn client_hello(sni: &str, alpn: &[&str]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7u8; 32]);
        body.push(0); // empty session id
        body.extend(vec16(&[0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f])); // GREASE + 3 suites
        body.extend([1, 0]);
        let mut exts = vec![];
        let mut name = vec![0u8];
        name.extend(vec16(sni.as_bytes()));
        exts.extend(ext(EXT_SNI, &vec16(&name)));
        let mut list = vec![];
        for a in alpn {
            list.push(a.len() as u8);
            list.extend(a.as_bytes());
        }
        exts.extend(ext(EXT_ALPN, &vec16(&list)));
        exts.extend(ext(EXT_SUPPORTED_VERSIONS, &[6, 0x1a, 0x1a, 3, 4, 3, 3]));
        body.extend(vec16(&exts));
        record(CT_HANDSHAKE, &handshake(HS_CLIENT_HELLO, &body))
    }

    pub fn server_hello(version13: bool, cipher: u16, alpn: Option<&str>) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([9u8; 32]);
        body.push(0);
        body.extend(u16b(cipher));
        body.push(0);
        let mut exts = vec![];
        if version13 {
            exts.extend(ext(EXT_SUPPORTED_VERSIONS, &[3, 4]));
        }
        if let Some(a) = alpn {
            let mut l = vec![a.len() as u8];
            l.extend(a.as_bytes());
            exts.extend(ext(EXT_ALPN, &vec16(&l)));
        }
        body.extend(vec16(&exts));
        record(CT_HANDSHAKE, &handshake(HS_SERVER_HELLO, &body))
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if content.len() < 128 {
            v.push(content.len() as u8);
        } else {
            v.extend([0x82, (content.len() >> 8) as u8, content.len() as u8]);
        }
        v.extend(content);
        v
    }

    fn name(cn: &str, org: &str) -> Vec<u8> {
        let attr = |oid: &[u8], v: &str| {
            der(
                0x31,
                &der(0x30, &[der(6, oid), der(0x0c, v.as_bytes())].concat()),
            )
        };
        der(0x30, &[attr(OID_ORG, org), attr(OID_CN, cn)].concat())
    }

    pub fn certificate_record(subject: &str, issuer: &str, sans: &[&str]) -> Vec<u8> {
        let san_names: Vec<u8> = sans.iter().flat_map(|s| der(0x82, s.as_bytes())).collect();
        let san_ext = der(
            0x30,
            &[der(6, OID_SAN), der(4, &der(0x30, &san_names))].concat(),
        );
        let exts = der(0xA3, &der(0x30, &san_ext));
        let tbs = der(
            0x30,
            &[
                der(0xA0, &der(2, &[2])),
                der(2, &[1]),
                der(0x30, &der(6, &[0x2a, 0x86, 0x48])),
                name(issuer, "Issuer Org"),
                der(
                    0x30,
                    &[der(0x17, b"240101000000Z"), der(0x18, b"20350101123045Z")].concat(),
                ),
                name(subject, "Subject Org"),
                der(0x30, &der(6, &[0x2a, 0x86, 0x48])),
                exts,
            ]
            .concat(),
        );
        let cert = der(0x30, &[tbs, der(0x30, &[]), der(3, &[0])].concat());
        let mut list = vec![
            (cert.len() >> 16) as u8,
            (cert.len() >> 8) as u8,
            cert.len() as u8,
        ];
        list.extend(&cert);
        let mut body = vec![
            (list.len() >> 16) as u8,
            (list.len() >> 8) as u8,
            list.len() as u8,
        ];
        body.extend(list);
        record(CT_HANDSHAKE, &handshake(HS_CERTIFICATE, &body))
    }

    #[test]
    fn parses_client_hello_metadata() {
        let p = parse(&client_hello("github.com", &["h2", "http/1.1"]));
        let h = p.client_hello.unwrap();
        assert_eq!(h.sni.as_deref(), Some("github.com"));
        assert_eq!(h.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(h.cipher_suites, vec![0x1301, 0x1302, 0xc02f]); // GREASE removed
        assert_eq!(h.supported_versions, vec![0x0304, 0x0303]);
        assert_eq!(p.handshake_types, vec![HS_CLIENT_HELLO]);
    }

    #[test]
    fn parses_server_hello_for_tls13_and_tls12() {
        let s = parse(&server_hello(true, 0x1301, None))
            .server_hello
            .unwrap();
        assert_eq!(
            (s.selected_version, s.cipher_suite, s.alpn),
            (Some(0x0304), 0x1301, None)
        );
        let s = parse(&server_hello(false, 0xc02f, Some("h2")))
            .server_hello
            .unwrap();
        assert_eq!(
            (s.selected_version, s.legacy_version, s.alpn.as_deref()),
            (None, 0x0303, Some("h2"))
        );
    }

    #[test]
    fn parses_certificate_metadata() {
        let mut data = server_hello(false, 0xc02f, None);
        data.extend(certificate_record(
            "github.com",
            "DigiCert TLS RSA",
            &["github.com", "www.github.com"],
        ));
        let p = parse(&data);
        let c = p.certificate.unwrap();
        assert_eq!(c.subject_cn.as_deref(), Some("github.com"));
        assert_eq!(c.issuer_cn.as_deref(), Some("DigiCert TLS RSA"));
        assert_eq!(c.subject_org.as_deref(), Some("Subject Org"));
        assert_eq!(c.not_before.as_deref(), Some("2024-01-01 00:00:00 UTC"));
        assert_eq!(c.not_after.as_deref(), Some("2035-01-01 12:30:45 UTC"));
        assert_eq!(c.dns_names, vec!["github.com", "www.github.com"]);
        assert_eq!(p.handshake_types, vec![HS_SERVER_HELLO, HS_CERTIFICATE]);
    }

    #[test]
    fn handshake_messages_may_span_records() {
        let hello = client_hello("split.example", &["h2"]);
        let body = &hello[5..];
        let (a, b) = body.split_at(40);
        let mut data = record(CT_HANDSHAKE, a);
        data.extend(record(CT_HANDSHAKE, b));
        assert_eq!(
            parse(&data).client_hello.unwrap().sni.as_deref(),
            Some("split.example")
        );
    }

    #[test]
    fn incomplete_message_is_reported_as_absent_not_wrong() {
        let hello = client_hello("later.example", &[]);
        for n in 0..hello.len() {
            let p = parse(&hello[..n]); // must never panic
            if n < hello.len() {
                assert!(
                    p.client_hello.is_none()
                        || p.client_hello.as_ref().unwrap().sni.is_some()
                        || n > 60
                );
            }
        }
        assert!(parse(&hello[..hello.len() - 1]).client_hello.is_none());
    }

    #[test]
    fn encrypted_records_are_listed_but_not_decoded() {
        let mut data = server_hello(true, 0x1301, None);
        data.extend(record(CT_CCS, &[1]));
        data.extend(record(CT_APPDATA, &[0xaa; 40]));
        let p = parse(&data);
        assert!(p.saw_non_handshake && p.server_hello.is_some() && p.certificate.is_none());
        assert_eq!(p.record_types, vec![CT_HANDSHAKE, CT_CCS, CT_APPDATA]);
    }

    #[test]
    fn detects_tls_records() {
        assert!(looks_like_tls(&client_hello("a.b", &[])));
        assert!(!looks_like_tls(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_tls(&[0x16, 3, 1, 0, 0]));
        assert!(!looks_like_tls(&[0x16, 3, 9, 0, 5]));
    }

    #[test]
    fn hostile_input_never_panics() {
        let base = [
            client_hello("evil.example", &["h2"]),
            server_hello(true, 0x1301, None),
            certificate_record("a", "b", &["c"]),
        ]
        .concat();
        for i in 0..base.len() {
            for v in [0u8, 1, 0x7f, 0x80, 0x82, 0xff] {
                let mut m = base.clone();
                m[i] = v;
                let _ = parse(&m);
            }
        }
        for n in 0..base.len() {
            let _ = parse(&base[..n]);
        }
        let _ = parse(&[0x16, 3, 1, 0xff, 0xff, 1, 0xff, 0xff, 0xff]);
        assert!(parse_x509(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn untrusted_text_is_escaped() {
        let p = parse(&client_hello("bad\u{1b}[31m.example", &["h\u{0}2"]));
        let h = p.client_hello.unwrap();
        assert!(!h.sni.unwrap().contains('\u{1b}'));
        assert_eq!(h.alpn, vec!["h\\x002"]);
    }

    #[test]
    fn names() {
        assert_eq!(version_name(0x0304), "TLS 1.3");
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(cipher_suite_name(0xdead), "0xdead");
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && !is_grease(0x0a1a));
    }
}

pub fn handshake_name(t: u8) -> String {
    match t {
        1 => "Client Hello".into(),
        2 => "Server Hello".into(),
        4 => "New Session Ticket".into(),
        8 => "Encrypted Extensions".into(),
        11 => "Certificate".into(),
        12 => "Server Key Exchange".into(),
        13 => "Certificate Request".into(),
        14 => "Server Hello Done".into(),
        15 => "Certificate Verify".into(),
        16 => "Client Key Exchange".into(),
        20 => "Finished".into(),
        n => format!("Handshake {n}"),
    }
}

/// One-line description for the packet list, e.g. `Client Hello (SNI: github.com)`.
pub fn describe(p: &TlsParse) -> String {
    let mut parts: Vec<String> = p
        .handshake_types
        .iter()
        .map(|&t| match (t, &p.client_hello) {
            (HS_CLIENT_HELLO, Some(h)) => match &h.sni {
                Some(sni) => format!("Client Hello (SNI: {sni})"),
                None => "Client Hello".to_string(),
            },
            _ => handshake_name(t),
        })
        .collect();
    if p.handshake_types.is_empty() && p.record_types.contains(&CT_HANDSHAKE) {
        parts.push("Handshake (continued)".into());
    }
    for &ct in &p.record_types {
        match ct {
            CT_CCS => parts.push("Change Cipher Spec".into()),
            CT_ALERT => parts.push("Alert".into()),
            CT_APPDATA => parts.push("Application Data".into()),
            _ => {}
        }
    }
    parts.dedup();
    if parts.is_empty() {
        "TLS record".into()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod describe_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn describes_records_for_the_packet_list() {
        assert_eq!(
            describe(&parse(&client_hello("github.com", &["h2"]))),
            "Client Hello (SNI: github.com)"
        );
        let mut d = server_hello(false, 0xc02f, None);
        d.extend(certificate_record("a", "b", &[]));
        assert_eq!(describe(&parse(&d)), "Server Hello, Certificate");
        let mut e = record(CT_CCS, &[1]);
        e.extend(record(CT_APPDATA, &[0; 10]));
        assert_eq!(describe(&parse(&e)), "Change Cipher Spec, Application Data");
        assert_eq!(
            describe(&parse(&record(CT_HANDSHAKE, &[0x0b, 0, 0x10]))),
            "Handshake (continued)"
        );
    }
}
