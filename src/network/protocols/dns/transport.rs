use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::RecordType;

use super::validation::{inspect_dns_response_header, validate_dns_response};

const UDP_RESPONSE_BUFFER_BYTES: usize = 4096;
const MAX_DNS_TCP_FRAME_BYTES: usize = u16::MAX as usize;

pub(super) struct DnsTransportResponse {
    pub(super) message: Message,
    pub(super) response_bytes: usize,
}

pub(super) enum AutoUdpResponse {
    Complete(DnsTransportResponse),
    Truncated { response_bytes: usize },
}

pub(super) struct DnsQueryPlan<'a> {
    pub(super) target: SocketAddr,
    pub(super) query: &'a [u8],
    pub(super) query_id: u16,
    pub(super) domain: &'a str,
    pub(super) record_type: RecordType,
    pub(super) timeout: Duration,
}

enum DnsAttemptError {
    Retryable(anyhow::Error),
    Fatal(anyhow::Error),
}

impl DnsAttemptError {
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Retryable(err) | Self::Fatal(err) => err,
        }
    }
}

pub(super) async fn query_udp_with_retries(
    plan: &DnsQueryPlan<'_>,
    retries: u8,
    attempts: &mut u32,
) -> Result<DnsTransportResponse> {
    query_with_retries(retries, attempts, || async { query_udp_once(plan).await }).await
}

pub(super) async fn query_udp_for_auto_with_retries(
    plan: &DnsQueryPlan<'_>,
    retries: u8,
    attempts: &mut u32,
) -> Result<AutoUdpResponse> {
    query_with_retries(retries, attempts, || async {
        query_udp_for_auto_once(plan).await
    })
    .await
}

pub(super) async fn query_tcp_with_retries(
    plan: &DnsQueryPlan<'_>,
    retries: u8,
    attempts: &mut u32,
) -> Result<DnsTransportResponse> {
    query_with_retries(retries, attempts, || async { query_tcp_once(plan).await }).await
}

async fn query_with_retries<F, Fut, T>(retries: u8, attempts: &mut u32, mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, DnsAttemptError>>,
{
    for attempt_index in 0..=retries {
        *attempts += 1;
        match attempt().await {
            Ok(response) => return Ok(response),
            Err(DnsAttemptError::Retryable(err)) if attempt_index < retries => {
                debug!(
                    "DNS query attempt {} failed with retryable error: {}",
                    attempt_index + 1,
                    err
                );
            }
            Err(err) => return Err(err.into_error()),
        }
    }

    unreachable!("retry loop always returns from the final attempt")
}

async fn query_udp_once(
    plan: &DnsQueryPlan<'_>,
) -> std::result::Result<DnsTransportResponse, DnsAttemptError> {
    let response = send_udp_query_once(plan.target, plan.query, plan.timeout).await?;
    let response_bytes = response.len();
    debug!("Received {} byte UDP response", response_bytes);
    let message = validate_dns_response(&response, plan.query_id, plan.domain, plan.record_type)
        .map_err(DnsAttemptError::Fatal)?;

    Ok(DnsTransportResponse {
        message,
        response_bytes,
    })
}

async fn query_udp_for_auto_once(
    plan: &DnsQueryPlan<'_>,
) -> std::result::Result<AutoUdpResponse, DnsAttemptError> {
    let response = send_udp_query_once(plan.target, plan.query, plan.timeout).await?;
    let response_bytes = response.len();
    debug!("Received {} byte UDP response", response_bytes);

    let header =
        inspect_dns_response_header(&response, plan.query_id).map_err(DnsAttemptError::Fatal)?;
    if header.truncated {
        debug!("UDP response had TC bit set; deferring full answer decode to TCP fallback");
        return Ok(AutoUdpResponse::Truncated { response_bytes });
    }

    let message = validate_dns_response(&response, plan.query_id, plan.domain, plan.record_type)
        .map_err(DnsAttemptError::Fatal)?;

    Ok(AutoUdpResponse::Complete(DnsTransportResponse {
        message,
        response_bytes,
    }))
}

async fn send_udp_query_once(
    target: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> std::result::Result<Vec<u8>, DnsAttemptError> {
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket to {}", bind_addr))
        .map_err(DnsAttemptError::Fatal)?;

    socket
        .connect(target)
        .await
        .with_context(|| format!("failed to connect to {}", target))
        .map_err(DnsAttemptError::Fatal)?;

    socket
        .send(query)
        .await
        .context("failed to send query")
        .map_err(DnsAttemptError::Fatal)?;

    let mut buf = [0u8; UDP_RESPONSE_BUFFER_BYTES];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => Ok(buf[..len].to_vec()),
        Ok(Err(err)) => Err(DnsAttemptError::Retryable(
            anyhow::Error::new(err).context("socket receive error"),
        )),
        Err(_) => Err(DnsAttemptError::Retryable(anyhow::anyhow!(
            "request timed out after {}ms",
            timeout.as_millis()
        ))),
    }
}

async fn query_tcp_once(
    plan: &DnsQueryPlan<'_>,
) -> std::result::Result<DnsTransportResponse, DnsAttemptError> {
    let response = match tokio::time::timeout(
        plan.timeout,
        send_tcp_query_once(plan.target, plan.query),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            return Err(DnsAttemptError::Retryable(anyhow::anyhow!(
                "request timed out after {}ms",
                plan.timeout.as_millis()
            )));
        }
    };
    let response_bytes = response.len();
    debug!("Received {} byte TCP response", response_bytes);
    let message = validate_dns_response(&response, plan.query_id, plan.domain, plan.record_type)
        .map_err(DnsAttemptError::Fatal)?;

    Ok(DnsTransportResponse {
        message,
        response_bytes,
    })
}

async fn send_tcp_query_once(
    target: SocketAddr,
    query: &[u8],
) -> std::result::Result<Vec<u8>, DnsAttemptError> {
    let frame = encode_tcp_frame(query).map_err(DnsAttemptError::Fatal)?;
    let mut stream = TcpStream::connect(target)
        .await
        .with_context(|| format!("failed to connect to {}", target))
        .map_err(DnsAttemptError::Retryable)?;

    stream
        .write_all(&frame)
        .await
        .context("failed to write DNS TCP query")
        .map_err(DnsAttemptError::Retryable)?;

    read_tcp_response(&mut stream).await
}

async fn read_tcp_response(
    stream: &mut TcpStream,
) -> std::result::Result<Vec<u8>, DnsAttemptError> {
    let mut length_prefix = [0u8; 2];
    stream
        .read_exact(&mut length_prefix)
        .await
        .context("failed to read DNS TCP response length")
        .map_err(DnsAttemptError::Retryable)?;
    let response_len = decode_tcp_frame_length(length_prefix).map_err(DnsAttemptError::Fatal)?;
    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .context("failed to read DNS TCP response body")
        .map_err(DnsAttemptError::Retryable)?;

    Ok(response)
}

pub(super) fn encode_tcp_frame(query: &[u8]) -> Result<Vec<u8>> {
    if query.is_empty() {
        return Err(anyhow!("DNS TCP query frame cannot be empty"));
    }
    if query.len() > u16::MAX as usize {
        return Err(anyhow!(
            "DNS TCP query too large: {} bytes exceeds {} byte frame limit",
            query.len(),
            u16::MAX
        ));
    }

    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    Ok(frame)
}

pub(super) fn decode_tcp_frame_length(length_prefix: [u8; 2]) -> Result<usize> {
    let response_len = u16::from_be_bytes(length_prefix) as usize;
    if response_len == 0 {
        return Err(anyhow!("DNS TCP response frame length cannot be zero"));
    }
    if response_len > MAX_DNS_TCP_FRAME_BYTES {
        return Err(anyhow!(
            "DNS TCP response frame length {} exceeds {} byte limit",
            response_len,
            MAX_DNS_TCP_FRAME_BYTES
        ));
    }
    Ok(response_len)
}
