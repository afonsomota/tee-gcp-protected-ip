//! Minimal GCP REST clients for attestation-gated artifact delivery
//! (issue #7): instance metadata, GCS for the ciphertext blobs, KMS for
//! unwrapping the data-encryption key, and the two token sources.
//!
//! Deliberately not the official SDKs: the launcher is the audited TCB, and
//! these few calls are small enough to be plainly visible. Outbound TLS uses
//! compiled-in `webpki-roots` — the runtime image has no CA bundle, so
//! filesystem certificate discovery must never happen.
//!
//! # Token sources
//!
//! * **Metadata token** — the VM service account's access token from the GCE
//!   metadata server. Used for GCS: the blobs are ciphertext, so plain
//!   service-account IAM is enough.
//! * **Federated token** — the Confidential Space attestation JWT (kept fresh
//!   by the launcher monitor at `/run/container_launcher/...`, audience
//!   `https://sts.googleapis.com`) exchanged at STS for an access token that
//!   authenticates as the workload-identity-pool principal. KMS decrypt is
//!   granted *only* to that principalSet, attribute-conditioned on the image
//!   digest — this is what makes the DEK unwrappable exclusively by attested
//!   workloads running the expected image.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::http::{Method, Request, StatusCode};
use serde_json::json;

const METADATA_BASE: &str = "http://metadata.google.internal/computeMetadata/v1";
const STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
/// Attestation JWT (audience `https://sts.googleapis.com`) that Confidential
/// Space keeps fresh inside the workload container.
const ATTESTATION_TOKEN_PATH: &str = "/run/container_launcher/attestation_verifier_claims_token";

/// Bounds the time to a response *head* (and, in `request`, the collected
/// body). Streaming bodies handed back to callers are not covered — the
/// multi-GB ciphertext download takes as long as it takes. The bound mainly
/// keeps boot-time config resolution from hanging the whole launcher on an
/// unresponsive metadata endpoint.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

type HttpsClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

fn https_client() -> &'static HttpsClient {
    static CLIENT: std::sync::OnceLock<HttpsClient> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
            .expect("webpki-roots client config")
            .https_or_http() // plain http allowed only for the metadata server
            .enable_http1()
            .build();
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector)
    })
}

/// Send a request and return the response with its status, leaving the body
/// unread (callers either collect it or stream it frame by frame).
async fn send(
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<hyper::Response<hyper::body::Incoming>, String> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("failed to build request for {uri}: {e}"))?;
    tokio::time::timeout(REQUEST_TIMEOUT, https_client().request(request))
        .await
        .map_err(|_| format!("request to {uri} timed out after {REQUEST_TIMEOUT:?}"))?
        .map_err(|e| format!("request to {uri} failed: {e}"))
}

/// One-shot request helper; returns the status and the collected body.
async fn request(
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<(StatusCode, Bytes), String> {
    let response = send(method, uri, headers, body).await?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed to read response from {uri}: {e}"))?
        .to_bytes();
    Ok((status, bytes))
}

fn json_field(bytes: &[u8], field: &str, context: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("{context}: response is not JSON: {e}"))?;
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{context}: response has no `{field}` field"))
}

/// Percent-encode a GCS object name for use as a single URL path segment
/// (object names contain `/`, which must become `%2F`).
fn encode_object_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// An instance metadata attribute (set by Terraform on the CVM), or `None`
/// if the attribute is absent.
pub async fn instance_attribute(name: &str) -> Result<Option<String>, String> {
    let uri = format!("{METADATA_BASE}/instance/attributes/{name}");
    let (status, body) = request(
        Method::GET,
        &uri,
        &[("Metadata-Flavor", "Google")],
        Vec::new(),
    )
    .await?;
    match status {
        StatusCode::NOT_FOUND => Ok(None),
        s if s.is_success() => Ok(Some(String::from_utf8_lossy(&body).into_owned())),
        s => Err(format!("metadata attribute {name} returned {s}")),
    }
}

/// POST a JSON body to an arbitrary HTTPS URL and return the status, discarding
/// the response body. Used for the scale-from-zero idle poke (issue #45) to the
/// untrusted controller: the launcher only needs the call delivered and treats
/// every error as "stay up", so the caller cares about the status, not the body.
/// Reuses the shared webpki-roots client — the controller's TLS chains to a
/// public CA, the same trust anchors the ACME and STS calls already use.
pub async fn post_json(uri: &str, body: Vec<u8>) -> Result<StatusCode, String> {
    let (status, _) = request(
        Method::POST,
        uri,
        &[("Content-Type", "application/json")],
        body,
    )
    .await?;
    Ok(status)
}

/// Access token of the VM's service account, from the metadata server.
pub async fn metadata_access_token() -> Result<String, String> {
    let uri = format!("{METADATA_BASE}/instance/service-accounts/default/token");
    let (status, body) = request(
        Method::GET,
        &uri,
        &[("Metadata-Flavor", "Google")],
        Vec::new(),
    )
    .await?;
    if !status.is_success() {
        return Err(format!("metadata token request returned {status}"));
    }
    json_field(&body, "access_token", "metadata token")
}

/// Exchange the Confidential Space attestation JWT at STS for an access token
/// that acts as the workload-identity-pool principal. `audience` is the full
/// `//iam.googleapis.com/projects/.../workloadIdentityPools/.../providers/...`
/// resource of the pool provider.
pub async fn federated_access_token(audience: &str) -> Result<String, String> {
    let attestation_jwt = std::fs::read_to_string(ATTESTATION_TOKEN_PATH)
        .map_err(|e| format!("cannot read attestation token {ATTESTATION_TOKEN_PATH}: {e}"))?;
    let body = json!({
        "audience": audience,
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
        "subjectToken": attestation_jwt.trim(),
    })
    .to_string();
    let (status, response) = request(
        Method::POST,
        STS_TOKEN_URL,
        &[("Content-Type", "application/json")],
        body.into_bytes(),
    )
    .await?;
    if !status.is_success() {
        return Err(format!(
            "STS token exchange returned {status}: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    json_field(&response, "access_token", "STS token exchange")
}

fn gcs_media_uri(bucket: &str, object: &str) -> String {
    format!(
        "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{}?alt=media",
        encode_object_name(object)
    )
}

/// Fetch a small GCS object (the manifest) into memory. Authenticates as the
/// VM service account; confidentiality comes from KMS, not from GCS IAM.
pub async fn gcs_get(token: &str, bucket: &str, object: &str) -> Result<Vec<u8>, String> {
    let uri = gcs_media_uri(bucket, object);
    let (status, body) = request(
        Method::GET,
        &uri,
        &[("Authorization", &format!("Bearer {token}"))],
        Vec::new(),
    )
    .await?;
    if !status.is_success() {
        return Err(format!(
            "GCS get {object} returned {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(body.to_vec())
}

/// Open a streaming GCS download (the multi-GB ciphertext): returns the
/// response body for the caller to consume frame by frame, so the blob is
/// never held in memory whole.
pub async fn gcs_get_stream(
    token: &str,
    bucket: &str,
    object: &str,
) -> Result<hyper::body::Incoming, String> {
    let uri = gcs_media_uri(bucket, object);
    let response = send(
        Method::GET,
        &uri,
        &[("Authorization", &format!("Bearer {token}"))],
        Vec::new(),
    )
    .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response
            .into_body()
            .collect()
            .await
            .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
            .unwrap_or_default();
        return Err(format!("GCS get {object} returned {status}: {body}"));
    }
    Ok(response.into_body())
}

/// Unwrap a KMS-wrapped DEK. With `wip_audience` set (production), the call
/// authenticates via the attested federated token; the key's IAM grants
/// decrypt only to the attested principalSet for the expected image digest,
/// so a non-attested principal cannot unwrap. `None` (plain service-account
/// token) is reachable only from the env-driven dev/test config —
/// `artifacts::Config` makes the audience mandatory in the metadata path.
pub async fn kms_decrypt(
    key: &str,
    wip_audience: Option<&str>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let token = match wip_audience {
        Some(audience) => federated_access_token(audience).await?,
        None => metadata_access_token().await?,
    };
    let uri = format!("https://cloudkms.googleapis.com/v1/{key}:decrypt");
    let body = json!({ "ciphertext": B64.encode(ciphertext) }).to_string();
    let (status, response) = request(
        Method::POST,
        &uri,
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
        body.into_bytes(),
    )
    .await?;
    if !status.is_success() {
        return Err(format!(
            "KMS decrypt returned {status}: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    let b64 = json_field(&response, "plaintext", "KMS decrypt")?;
    B64.decode(b64)
        .map_err(|e| format!("KMS decrypt: invalid base64 in response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_are_percent_encoded_for_the_url_path() {
        assert_eq!(
            encode_object_name("weights/model.gguf.enc"),
            "weights%2Fmodel.gguf.enc"
        );
        assert_eq!(encode_object_name("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(encode_object_name("sp ace+plus"), "sp%20ace%2Bplus");
    }
}
