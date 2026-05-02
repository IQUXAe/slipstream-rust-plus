use crate::error::ClientError;
use slipstream_core::normalize_dual_stack_addr;
use slipstream_dns::{
    build_probe_qname, decode_response, encode_query, validate_probe_payload, QueryParams,
    CLASS_IN, RR_TXT,
};
use slipstream_ffi::ResolverMode;
use std::time::Instant;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use super::resolver::ResolverState;

const BASIC_PROBE_RESPONSE_BYTES: usize = 32;
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);

pub(crate) async fn probe_resolvers(
    udp: &TokioUdpSocket,
    resolvers: &mut [ResolverState],
    domain: &str,
    public_safe_response_bytes: usize,
    public_fast_response_bytes: Option<usize>,
) -> Result<(), ClientError> {
    let mut any_enabled = false;

    for (index, resolver) in resolvers.iter_mut().enumerate() {
        if resolver.mode == ResolverMode::Authoritative {
            resolver.profile.supports_basic_txt = true;
            resolver.profile.max_response_payload_observed =
                public_fast_response_bytes.unwrap_or(public_safe_response_bytes);
            any_enabled = true;
            continue;
        }

        let mut probe_sizes = vec![BASIC_PROBE_RESPONSE_BYTES, public_safe_response_bytes];
        if let Some(public_fast_response_bytes) = public_fast_response_bytes {
            if public_fast_response_bytes > public_safe_response_bytes {
                probe_sizes.push(public_fast_response_bytes);
            }
        }

        let mut attempts = 0usize;
        let mut timeouts = 0usize;
        let mut enabled = true;

        for response_payload_len in probe_sizes {
            attempts = attempts.saturating_add(1);
            let token = ((index as u16) << 8) ^ (response_payload_len as u16).wrapping_add(0x5300);
            match send_probe(
                udp,
                resolver,
                domain,
                token,
                response_payload_len,
                attempts as u16,
            )
            .await
            {
                Ok(rtt_ms) => {
                    resolver.profile.supports_basic_txt = true;
                    resolver.profile.max_response_payload_observed = resolver
                        .profile
                        .max_response_payload_observed
                        .max(response_payload_len);
                    resolver.profile.rtt_ms = Some(
                        resolver
                            .profile
                            .rtt_ms
                            .map(|existing| existing.min(rtt_ms))
                            .unwrap_or(rtt_ms),
                    );
                    resolver.profile.last_error = None;
                }
                Err(err) => {
                    if err.contains("timed out") {
                        timeouts = timeouts.saturating_add(1);
                    }
                    resolver.profile.last_error = Some(err.clone());
                    enabled = false;
                    warn!(
                        "disabling resolver {} after probe failure for {} bytes: {}",
                        resolver.addr, response_payload_len, err
                    );
                    break;
                }
            }
        }

        resolver.profile.timeout_rate = if attempts == 0 {
            0.0
        } else {
            timeouts as f32 / attempts as f32
        };
        resolver.enabled = enabled && resolver.profile.supports_basic_txt;
        if resolver.enabled {
            any_enabled = true;
        }

        info!(
            "resolver_profile resolver={} supports_basic_txt={} max_response_payload_observed={} rtt_ms={} timeout_rate={:.2} last_error={}",
            resolver.addr,
            resolver.profile.supports_basic_txt,
            resolver.profile.max_response_payload_observed,
            resolver.profile.rtt_ms.unwrap_or(0),
            resolver.profile.timeout_rate,
            resolver
                .profile
                .last_error
                .as_deref()
                .unwrap_or("none")
        );
    }

    if !any_enabled {
        return Err(ClientError::new(
            "No resolver passed the public TXT capability probe",
        ));
    }

    Ok(())
}

async fn send_probe(
    udp: &TokioUdpSocket,
    resolver: &ResolverState,
    domain: &str,
    token: u16,
    response_payload_len: usize,
    query_id: u16,
) -> Result<u64, String> {
    let qname =
        build_probe_qname(domain, token, response_payload_len).map_err(|err| err.to_string())?;
    let query = encode_query(&QueryParams {
        id: query_id,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    })
    .map_err(|err| err.to_string())?;

    let start = Instant::now();
    udp.send_to(&query, resolver.addr)
        .await
        .map_err(|err| err.to_string())?;

    let mut recv_buf = vec![0u8; 4096];
    loop {
        let recv = timeout(PROBE_TIMEOUT, udp.recv_from(&mut recv_buf)).await;
        let (size, peer) = match recv {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return Err(err.to_string()),
            Err(_) => {
                return Err(format!(
                    "probe timed out waiting for {} byte TXT response",
                    response_payload_len
                ))
            }
        };
        if normalize_dual_stack_addr(peer) != resolver.addr {
            continue;
        }
        if dns_message_id(&recv_buf[..size]) != Some(query_id) {
            continue;
        }
        let payload = decode_response(&recv_buf[..size]).ok_or_else(|| {
            format!(
                "probe received non-TXT or empty response for {} bytes",
                response_payload_len
            )
        })?;
        if !validate_probe_payload(&payload, token, response_payload_len) {
            return Err(format!(
                "probe payload validation failed for {} bytes",
                response_payload_len
            ));
        }
        return Ok(start.elapsed().as_millis() as u64);
    }
}

fn dns_message_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([packet[0], packet[1]]))
}
