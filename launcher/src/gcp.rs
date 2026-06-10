//! Minimal GCP REST clients for the sealed ACME state (issue 004): GCS for
//! the ciphertext blobs, KMS for wrapping, and the two token sources.
//!
//! Deliberately not the official SDKs: the launcher is the audited TCB, and
//! these four calls are small enough to be plainly visible. Outbound TLS uses
//! compiled-in `webpki-roots` — the runtime image is `scratch` with no CA
//! bundle (spike 001), so filesystem certificate discovery must never happen.
//!
//! # Token sources
//!
//! * **Metadata token** — the VM service account's access token from the GCE
//!   metadata server. Used for GCS: the blobs are ciphertext, so plain
//!   service-account IAM is enough.
//! * **Federated token** — the Confidential Space attestation JWT (written by
//!   the launcher monitor to `/run/container_launcher/...`, audience
//!   `https://sts.googleapis.com`) exchanged at STS for an access token that
//!   authenticates as the workload-identity-pool principal. KMS decrypt is
//!   granted *only* to that principalSet, attribute-conditioned on the image
//!   digest — this is what makes the ACME state unwrappable exclusively by
//!   attested workloads.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::http::{Method, Request, StatusCode};
use serde_json::json;

use crate::sealed_cache::{BlobStore, Sealer};

const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
/// Attestation JWT (audience `https://sts.googleapis.com`) that Confidential
/// Space keeps fresh inside the workload container.
const ATTESTATION_TOKEN_PATH: &str = "/run/container_launcher/attestation_verifier_claims_token";

type HttpsClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

fn https_client() -> HttpsClient {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
        .expect("webpki-roots client config")
        .https_or_http() // plain http allowed only for the metadata server
        .enable_http1()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector)
}

/// One-shot request helper; returns the status and body, or a description of
/// the transport failure.
async fn request(
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<(StatusCode, Bytes), String> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("failed to build request for {uri}: {e}"))?;
    let response = https_client()
        .request(request)
        .await
        .map_err(|e| format!("request to {uri} failed: {e}"))?;
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

/// Access token of the VM's service account, from the metadata server.
pub async fn metadata_access_token() -> Result<String, String> {
    let (status, body) = request(
        Method::GET,
        METADATA_TOKEN_URL,
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

/// GCS bucket holding the sealed (KMS-wrapped) ACME state. Authenticates as
/// the VM service account; confidentiality comes from KMS, not from GCS IAM.
pub struct GcsBlobStore {
    bucket: String,
}

impl GcsBlobStore {
    pub fn new(bucket: String) -> Self {
        Self { bucket }
    }
}

#[async_trait]
impl BlobStore for GcsBlobStore {
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let token = metadata_access_token().await?;
        let uri = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{name}?alt=media",
            self.bucket
        );
        let (status, body) = request(
            Method::GET,
            &uri,
            &[("Authorization", &format!("Bearer {token}"))],
            Vec::new(),
        )
        .await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            s if s.is_success() => Ok(Some(body.to_vec())),
            s => Err(format!(
                "GCS get {name} returned {s}: {}",
                String::from_utf8_lossy(&body)
            )),
        }
    }

    async fn put(&self, name: &str, data: &[u8]) -> Result<(), String> {
        let token = metadata_access_token().await?;
        let uri = format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={name}",
            self.bucket
        );
        let (status, body) = request(
            Method::POST,
            &uri,
            &[
                ("Authorization", &format!("Bearer {token}")),
                ("Content-Type", "application/octet-stream"),
            ],
            data.to_vec(),
        )
        .await?;
        if !status.is_success() {
            return Err(format!(
                "GCS put {name} returned {status}: {}",
                String::from_utf8_lossy(&body)
            ));
        }
        Ok(())
    }
}

/// Wraps/unwraps blobs with a Cloud KMS key. With `wip_audience` set
/// (production), calls authenticate via the attested federated token; the KMS
/// IAM policy grants decrypt only to that attested principalSet, so a
/// non-attested principal cannot unwrap the state.
pub struct KmsSealer {
    /// Full key name: `projects/.../locations/.../keyRings/.../cryptoKeys/...`.
    key: String,
    wip_audience: Option<String>,
}

impl KmsSealer {
    pub fn new(key: String, wip_audience: Option<String>) -> Self {
        Self { key, wip_audience }
    }

    async fn token(&self) -> Result<String, String> {
        match &self.wip_audience {
            Some(audience) => federated_access_token(audience).await,
            None => metadata_access_token().await,
        }
    }

    /// POST `{key}:{verb}` with `{ field: base64 }`, return the named field
    /// of the response (KMS encrypt/decrypt are symmetric in shape).
    async fn kms_call(
        &self,
        verb: &str,
        request_field: &str,
        response_field: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let token = self.token().await?;
        let uri = format!("https://cloudkms.googleapis.com/v1/{}:{verb}", self.key);
        let body = json!({ request_field: B64.encode(data) }).to_string();
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
                "KMS {verb} returned {status}: {}",
                String::from_utf8_lossy(&response)
            ));
        }
        let b64 = json_field(&response, response_field, &format!("KMS {verb}"))?;
        B64.decode(b64)
            .map_err(|e| format!("KMS {verb}: invalid base64 in response: {e}"))
    }
}

#[async_trait]
impl Sealer for KmsSealer {
    async fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // ACME state is a few KiB, far below the 64 KiB KMS plaintext cap,
        // so the whole blob is wrapped directly — no envelope scheme needed.
        self.kms_call("encrypt", "plaintext", "ciphertext", plaintext)
            .await
    }

    async fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        self.kms_call("decrypt", "ciphertext", "plaintext", ciphertext)
            .await
    }
}
