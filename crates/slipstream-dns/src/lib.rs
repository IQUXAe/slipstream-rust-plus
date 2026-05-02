mod base32;
mod codec;
mod dots;
mod name;
mod types;
mod wire;

pub use base32::{decode as base32_decode, encode as base32_encode, Base32Error};
pub use codec::{
    decode_query, decode_query_with_domains, decode_response, encode_query, encode_response,
    is_response,
};
pub use dots::{dotify, undotify};
pub use types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Question, Rcode, ResponseParams,
    CLASS_IN, EDNS_UDP_PAYLOAD, RR_A, RR_OPT, RR_TXT,
};

pub const DNS_RESPONSE_TTL_PUBLIC: u32 = 0;
pub const DEFAULT_PUBLIC_SAFE_RESPONSE_BYTES: usize = 360;
pub const LEGACY_EDNS0_PAYLOAD_MAGIC: &[u8; 4] = b"SLP\x01";
const PROBE_PREFIX: &str = "_slp-probe";
const PROBE_MARKER: &[u8; 16] = b"slipstream-probe";

pub fn build_qname(payload: &[u8], domain: &str) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    let max_payload = max_payload_len_for_domain(domain)?;
    if payload.len() > max_payload {
        return Err(DnsError::new("payload too large for domain"));
    }
    let base32 = base32_encode(payload);
    let dotted = dotify(&base32);
    Ok(format!("{}.{}.", dotted, domain))
}

pub fn build_probe_qname(
    domain: &str,
    token: u16,
    response_payload_len: usize,
) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    let qname = format!(
        "{}.{:04x}.{}.{}.",
        PROBE_PREFIX, token, response_payload_len, domain
    );
    if qname.len() > name::MAX_DNS_NAME_LEN {
        return Err(DnsError::new("probe qname too long"));
    }
    Ok(qname)
}

pub fn parse_probe_qname(qname: &str, domains: &[&str]) -> Option<(u16, usize)> {
    let normalized = qname.trim_end_matches('.');
    for domain in domains {
        let domain = domain.trim_end_matches('.');
        let suffix = format!(".{}", domain);
        let head = normalized.strip_suffix(&suffix)?;
        let mut parts = head.split('.');
        if parts.next()? != PROBE_PREFIX {
            continue;
        }
        let token = u16::from_str_radix(parts.next()?, 16).ok()?;
        let response_payload_len = parts.next()?.parse::<usize>().ok()?;
        if parts.next().is_some() {
            continue;
        }
        return Some((token, response_payload_len));
    }
    None
}

pub fn build_probe_payload(token: u16, response_payload_len: usize) -> Result<Vec<u8>, DnsError> {
    let min_len = PROBE_MARKER.len() + 2;
    if response_payload_len < min_len {
        return Err(DnsError::new("probe payload too small"));
    }
    let mut payload = Vec::with_capacity(response_payload_len);
    payload.extend_from_slice(PROBE_MARKER);
    payload.extend_from_slice(&token.to_be_bytes());
    while payload.len() < response_payload_len {
        payload.push(b'x');
    }
    Ok(payload)
}

pub fn validate_probe_payload(payload: &[u8], token: u16, response_payload_len: usize) -> bool {
    payload.len() == response_payload_len
        && payload.starts_with(PROBE_MARKER)
        && payload.get(PROBE_MARKER.len()..PROBE_MARKER.len() + 2) == Some(&token.to_be_bytes())
}

pub fn estimate_query_size(qname: &str) -> Result<usize, DnsError> {
    let params = QueryParams {
        id: 0,
        qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    };
    Ok(encode_query(&params)?.len())
}

pub fn estimate_txt_response_size(
    question_name: &str,
    payload_len: usize,
) -> Result<usize, DnsError> {
    let question = Question {
        name: question_name.to_string(),
        qtype: RR_TXT,
        qclass: CLASS_IN,
    };
    let payload = vec![0u8; payload_len];
    let response = encode_response(&ResponseParams {
        id: 0,
        rd: true,
        cd: false,
        question: &question,
        payload: Some(&payload),
        rcode: None,
    })?;
    Ok(response.len())
}

/// Maximum payload size for EDNS0 OPT record encoding
/// EDNS0 UDP payload is 4096, DNS header ~12 bytes, question ~domain+8, OPT ~11 bytes
/// Conservative limit accounting for domain name overhead
pub const MAX_EDNS0_PAYLOAD: usize = 1232;

/// Threshold for automatically switching to EDNS0 encoding
pub const EDNS0_THRESHOLD: usize = 200;

/// Build a DNS query packet with payload encoded in EDNS0 OPT record
/// This supports much larger payloads (~1232 bytes) than QNAME encoding (~140 bytes)
pub fn build_query_with_edns0_payload(
    payload: &[u8],
    domain: &str,
    query_id: u16,
) -> Result<Vec<u8>, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if payload.len() > MAX_EDNS0_PAYLOAD {
        return Err(DnsError::new("payload too large for EDNS0"));
    }

    let qname = format!("{}.", domain);
    let params = QueryParams {
        id: query_id,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    };

    encode_query_with_opt_payload(&params, payload)
}

pub fn max_payload_len_for_domain(domain: &str) -> Result<usize, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if domain.len() > name::MAX_DNS_NAME_LEN {
        return Err(DnsError::new("domain too long"));
    }
    let max_name_len = name::MAX_DNS_NAME_LEN;
    let max_dotted_len = max_name_len.saturating_sub(domain.len() + 1);
    if max_dotted_len == 0 {
        return Ok(0);
    }
    let mut max_base32_len = 0usize;
    for len in 1..=max_dotted_len {
        let dots = (len - 1) / 57;
        if len + dots > max_dotted_len {
            break;
        }
        max_base32_len = len;
    }

    let mut max_payload = (max_base32_len * 5) / 8;
    while max_payload > 0 && base32_len(max_payload) > max_base32_len {
        max_payload -= 1;
    }
    Ok(max_payload)
}

fn base32_len(payload_len: usize) -> usize {
    if payload_len == 0 {
        return 0;
    }
    (payload_len * 8).div_ceil(5)
}

/// Helper function for encoding query with OPT payload
fn encode_query_with_opt_payload(
    params: &QueryParams<'_>,
    opt_payload: &[u8],
) -> Result<Vec<u8>, DnsError> {
    use codec::encode_query;

    // First encode the basic query
    let mut packet = encode_query(params)?;

    // Now we need to replace the OPT record with one containing our payload
    // The basic encode_query adds an empty OPT record (11 bytes) at the end
    // We need to replace it with an OPT record containing the payload

    // Remove the empty OPT record (last 11 bytes)
    if packet.len() >= 11 {
        packet.truncate(packet.len() - 11);
    }

    // Add OPT record with payload
    // NAME: root (0x00)
    packet.push(0);
    // TYPE: OPT (41)
    packet.extend_from_slice(&RR_OPT.to_be_bytes());
    // CLASS: UDP payload size
    packet.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
    // TTL: extended RCODE and flags (4 bytes, all zeros)
    packet.extend_from_slice(&[0, 0, 0, 0]);
    // RDLENGTH: length of RDATA
    let mut legacy_payload =
        Vec::with_capacity(LEGACY_EDNS0_PAYLOAD_MAGIC.len() + opt_payload.len());
    legacy_payload.extend_from_slice(LEGACY_EDNS0_PAYLOAD_MAGIC);
    legacy_payload.extend_from_slice(opt_payload);
    let rdlen = legacy_payload.len() as u16;
    packet.extend_from_slice(&rdlen.to_be_bytes());
    // RDATA: explicit legacy marker + payload so public-recursive QNAME decode can ignore OPT noise
    packet.extend_from_slice(&legacy_payload);

    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::{
        build_probe_payload, build_probe_qname, build_qname, build_query_with_edns0_payload,
        estimate_query_size, estimate_txt_response_size, max_payload_len_for_domain,
        parse_probe_qname, validate_probe_payload, DEFAULT_PUBLIC_SAFE_RESPONSE_BYTES,
        MAX_EDNS0_PAYLOAD,
    };

    #[test]
    fn build_qname_rejects_payload_overflow() {
        let domain = "test.com";
        let max_payload = max_payload_len_for_domain(domain).expect("max payload");
        let payload = vec![0u8; max_payload + 1];
        assert!(build_qname(&payload, domain).is_err());
    }

    #[test]
    fn build_qname_rejects_long_domain() {
        let domain = format!("{}.com", "a".repeat(260));
        let payload = vec![0u8; 1];
        assert!(build_qname(&payload, &domain).is_err());
    }

    #[test]
    fn build_query_with_edns0_accepts_large_payload() {
        let domain = "test.com";
        let payload = vec![0xAB; 500]; // 500 bytes, much larger than QNAME limit
        let result = build_query_with_edns0_payload(&payload, domain, 0x1234);
        assert!(result.is_ok());
    }

    #[test]
    fn build_query_with_edns0_rejects_oversized_payload() {
        let domain = "test.com";
        let payload = vec![0xAB; MAX_EDNS0_PAYLOAD + 1];
        let result = build_query_with_edns0_payload(&payload, domain, 0x1234);
        assert!(result.is_err());
    }

    #[test]
    fn probe_qname_round_trips() {
        let qname = build_probe_qname("example.com", 0x1234, 360).expect("probe qname");
        assert_eq!(
            parse_probe_qname(&qname, &["example.com"]),
            Some((0x1234, 360))
        );
    }

    #[test]
    fn probe_payload_round_trips() {
        let payload = build_probe_payload(0x1234, 48).expect("probe payload");
        assert!(validate_probe_payload(&payload, 0x1234, 48));
    }

    #[test]
    fn estimators_return_non_zero_sizes() {
        let query_size = estimate_query_size("a.example.com.").expect("query size");
        let response_size =
            estimate_txt_response_size("a.example.com.", 64).expect("response size");
        assert!(query_size > 0);
        assert!(response_size > 0);
    }

    #[test]
    fn default_public_safe_response_fits_512_bytes() {
        let response_size =
            estimate_txt_response_size("a.example.com.", DEFAULT_PUBLIC_SAFE_RESPONSE_BYTES)
                .expect("response size");
        assert!(response_size <= 512, "response size was {}", response_size);
    }
}
