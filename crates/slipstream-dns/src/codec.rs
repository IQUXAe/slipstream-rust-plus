use crate::base32;
use crate::dots;
use crate::{DNS_RESPONSE_TTL_PUBLIC, LEGACY_EDNS0_PAYLOAD_MAGIC};

use crate::name::{encode_name, extract_subdomain_multi, parse_name};
use crate::types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Rcode, ResponseParams, EDNS_UDP_PAYLOAD,
    RR_OPT, RR_TXT,
};
use crate::wire::{
    parse_header, parse_question, parse_question_for_reply, read_u16, read_u32, write_u16,
    write_u32,
};

pub fn decode_query(packet: &[u8], domain: &str) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains(packet, &[domain])
}

pub fn decode_query_with_domains(
    packet: &[u8],
    domains: &[&str],
) -> Result<DecodedQuery, DecodeQueryError> {
    let header = match parse_header(packet) {
        Some(header) => header,
        None => return Err(DecodeQueryError::Drop),
    };

    let rd = header.rd;
    let cd = header.cd;

    if header.is_response {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    if header.qdcount != 1 {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    let question = match parse_question(packet, header.offset) {
        Ok((question, _)) => question,
        Err(_) => return Err(DecodeQueryError::Drop),
    };

    if question.qtype != RR_TXT {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    if let Some(payload) = try_decode_qname_payload(&question.name, domains).map_err(|rcode| {
        DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question.clone()),
            rcode,
        }
    })? {
        return Ok(DecodedQuery {
            id: header.id,
            rd,
            cd,
            question,
            payload,
        });
    }

    if let Some(opt_payload) = try_extract_opt_payload(packet, &header, &question.name, domains) {
        return Ok(DecodedQuery {
            id: header.id,
            rd,
            cd,
            question,
            payload: opt_payload,
        });
    }

    Err(DecodeQueryError::Reply {
        id: header.id,
        rd,
        cd,
        question: Some(question),
        rcode: Rcode::NameError,
    })
}

fn try_decode_qname_payload(name: &str, domains: &[&str]) -> Result<Option<Vec<u8>>, Rcode> {
    let subdomain_raw = match extract_subdomain_multi(name, domains) {
        Ok(subdomain_raw) => subdomain_raw,
        Err(Rcode::NameError) if question_matches_exact_domain(name, domains) => return Ok(None),
        Err(Rcode::NameError) => return Ok(None),
        Err(rcode) => return Err(rcode),
    };

    let undotted = dots::undotify(&subdomain_raw);
    if undotted.is_empty() {
        return Ok(None);
    }

    match base32::decode(&undotted) {
        Ok(payload) => Ok(Some(payload)),
        Err(_) => Err(Rcode::ServerFailure),
    }
}

/// Try to extract payload from a legacy EDNS0 OPT record.
/// Public-recursive QNAME queries may include arbitrary resolver OPT records, so OPT payload is
/// only accepted when the qname is the exact configured domain and the payload starts with the
/// explicit legacy magic marker.
fn try_extract_opt_payload(
    packet: &[u8],
    header: &crate::wire::Header,
    question_name: &str,
    domains: &[&str],
) -> Option<Vec<u8>> {
    if !question_matches_exact_domain(question_name, domains) {
        return None;
    }

    // EDNS0 is in Additional Records section (ARCOUNT)
    if header.arcount == 0 {
        return None;
    }

    // Skip over question section
    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4; // Skip QTYPE and QCLASS
    }

    // Skip over answer and authority sections
    for _ in 0..(header.ancount + header.nscount) {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 10 > packet.len() {
            return None;
        }
        offset += 8; // Skip TYPE, CLASS, TTL
        let rdlen = read_u16(packet, offset)? as usize;
        offset += 2;
        if offset + rdlen > packet.len() {
            return None;
        }
        offset += rdlen;
    }

    // Check additional records for OPT
    for _ in 0..header.arcount {
        let _name_start = offset;
        let (name, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;

        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = read_u16(packet, offset)?;
        offset += 2;
        let _class = read_u16(packet, offset)?;
        offset += 2;
        let _ttl = read_u32(packet, offset)?;
        offset += 4;
        let rdlen = read_u16(packet, offset)? as usize;
        offset += 2;

        if offset + rdlen > packet.len() {
            return None;
        }

        // Check if this is an OPT record with root name
        if rr_type == RR_OPT && (name.is_empty() || name == ".") {
            let rdata = &packet[offset..offset + rdlen];
            let payload = rdata.strip_prefix(LEGACY_EDNS0_PAYLOAD_MAGIC)?;
            if payload.is_empty() {
                return None;
            }
            return Some(payload.to_vec());
        }

        offset += rdlen;
    }

    None
}

fn question_matches_exact_domain(question_name: &str, domains: &[&str]) -> bool {
    domains.iter().any(|domain| {
        let domain_with_dot = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{}.", domain)
        };
        question_name == domain_with_dot
    })
}

pub fn encode_query(params: &QueryParams<'_>) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(256);
    let mut flags = 0u16;
    if !params.is_query {
        flags |= 0x8000;
    }
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, params.qdcount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    if params.qdcount > 0 {
        encode_name(params.qname, &mut out)?;
        write_u16(&mut out, params.qtype);
        write_u16(&mut out, params.qclass);
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn encode_response(params: &ResponseParams<'_>) -> Result<Vec<u8>, DnsError> {
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);

    let mut rcode = params.rcode.unwrap_or(if payload_len > 0 {
        Rcode::Ok
    } else {
        Rcode::NameError
    });

    let mut ancount = 0u16;
    if payload_len > 0 && rcode == Rcode::Ok {
        ancount = 1;
    } else if params.rcode.is_some() {
        rcode = params.rcode.unwrap_or(Rcode::Ok);
    }

    let mut out = Vec::with_capacity(256);
    let mut flags = 0x8000 | 0x0400;
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }
    flags |= rcode.to_u8() as u16;

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, ancount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(&params.question.name, &mut out)?;
    write_u16(&mut out, params.question.qtype);
    write_u16(&mut out, params.question.qclass);

    if ancount == 1 {
        out.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut out, params.question.qtype);
        write_u16(&mut out, params.question.qclass);
        write_u32(&mut out, DNS_RESPONSE_TTL_PUBLIC);
        let chunk_count = payload_len.div_ceil(255);
        let rdata_len = payload_len + chunk_count;
        if rdata_len > u16::MAX as usize {
            return Err(DnsError::new("payload too long"));
        }
        write_u16(&mut out, rdata_len as u16);
        if let Some(payload) = params.payload {
            let mut remaining = payload_len;
            let mut cursor = 0;
            while remaining > 0 {
                let chunk_len = remaining.min(255);
                out.push(chunk_len as u8);
                out.extend_from_slice(&payload[cursor..cursor + chunk_len]);
                cursor += chunk_len;
                remaining -= chunk_len;
            }
        }
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn decode_response(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(packet)?;
    if !header.is_response {
        return None;
    }
    let rcode = header.rcode?;
    if rcode != Rcode::Ok {
        return None;
    }
    if header.ancount != 1 {
        return None;
    }

    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }

    let (_, new_offset) = parse_name(packet, offset).ok()?;
    offset = new_offset;
    if offset + 10 > packet.len() {
        return None;
    }
    let qtype = read_u16(packet, offset)?;
    offset += 2;
    let _qclass = read_u16(packet, offset)?;
    offset += 2;
    let _ttl = read_u32(packet, offset)?;
    offset += 4;
    let rdlen = read_u16(packet, offset)? as usize;
    offset += 2;
    if offset + rdlen > packet.len() || rdlen < 1 {
        return None;
    }
    if qtype != RR_TXT {
        return None;
    }

    let mut remaining = rdlen;
    let mut cursor = offset;
    let mut out = Vec::with_capacity(rdlen);
    while remaining > 0 {
        let txt_len = packet[cursor] as usize;
        cursor += 1;
        remaining -= 1;
        if txt_len > remaining {
            return None;
        }
        out.extend_from_slice(&packet[cursor..cursor + txt_len]);
        cursor += txt_len;
        remaining -= txt_len;
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

pub fn is_response(packet: &[u8]) -> bool {
    parse_header(packet)
        .map(|header| header.is_response)
        .unwrap_or(false)
}

fn encode_opt_record(out: &mut Vec<u8>) -> Result<(), DnsError> {
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    write_u16(out, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode_query_with_domains, encode_query, encode_response};
    use crate::wire::{parse_header, parse_question, read_u16, read_u32};
    use crate::{
        build_qname, build_query_with_edns0_payload, QueryParams, Question, ResponseParams,
        CLASS_IN, DNS_RESPONSE_TTL_PUBLIC, EDNS_UDP_PAYLOAD, RR_OPT, RR_TXT,
    };

    fn append_opt_rdata(mut packet: Vec<u8>, rdata: &[u8]) -> Vec<u8> {
        assert!(packet.len() >= 11);
        packet.truncate(packet.len() - 11);
        packet.push(0);
        packet.extend_from_slice(&RR_OPT.to_be_bytes());
        packet.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
        packet
    }

    #[test]
    fn encode_response_rejects_large_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_TXT,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; u16::MAX as usize];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
        };
        assert!(encode_response(&params).is_err());
    }

    #[test]
    fn qname_query_with_empty_opt_decodes_as_qname_payload() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let qname = build_qname(&payload, "example.com").expect("qname");
        let packet = encode_query(&QueryParams {
            id: 0x1234,
            qname: &qname,
            qtype: RR_TXT,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        })
        .expect("query");

        let decoded = decode_query_with_domains(&packet, &["example.com"]).expect("decoded");
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn qname_query_with_arbitrary_opt_options_decodes_as_qname_payload() {
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let qname = build_qname(&payload, "example.com").expect("qname");
        let packet = encode_query(&QueryParams {
            id: 0x1234,
            qname: &qname,
            qtype: RR_TXT,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        })
        .expect("query");
        let packet = append_opt_rdata(packet, &[0x00, 0x08, 0x12, 0x34, 0x56, 0x78]);

        let decoded = decode_query_with_domains(&packet, &["example.com"]).expect("decoded");
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn legacy_edns0_payload_requires_magic_marker() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let packet =
            build_query_with_edns0_payload(&payload, "example.com", 0x1234).expect("query");
        let decoded = decode_query_with_domains(&packet, &["example.com"]).expect("decoded");
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn txt_response_ttl_is_zero() {
        let question = Question {
            name: "a.example.com.".to_string(),
            qtype: RR_TXT,
            qclass: CLASS_IN,
        };
        let payload = b"hello";
        let response = encode_response(&ResponseParams {
            id: 0x1234,
            rd: true,
            cd: false,
            question: &question,
            payload: Some(payload),
            rcode: None,
        })
        .expect("response");

        let header = parse_header(&response).expect("header");
        let (_, mut offset) = parse_question(&response, header.offset).expect("question");
        assert_eq!(response[offset], 0xC0);
        assert_eq!(response[offset + 1], 0x0C);
        offset += 2;
        assert_eq!(read_u16(&response, offset), Some(RR_TXT));
        offset += 4;
        assert_eq!(read_u32(&response, offset), Some(DNS_RESPONSE_TTL_PUBLIC));
    }
}
