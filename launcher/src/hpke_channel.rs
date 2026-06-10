//! HPKE channel endpoints: key discovery and an encrypted echo round-trip.
//!
//! Suite (fixed; must match the frontend's hpke-js suite):
//! KEM X25519-HKDF-SHA256, KDF HKDF-SHA256, AEAD ChaCha20-Poly1305,
//! mode Base, empty AAD.
//!
//! # Envelope format (both directions)
//!
//! JSON `{"enc": "<base64>", "ct": "<base64>"}` — standard base64; `enc` is
//! the HPKE encapsulated key (32 bytes for X25519), `ct` the AEAD ciphertext.
//!
//! Request plaintext (browser → enclave), sealed to the enclave HPKE key
//! with `info = "tee-example/hpke/echo/request/v1"`:
//!
//! ```json
//! {"msg": "<utf-8 text>", "reply_pub": "<base64 raw 32-byte X25519 key>"}
//! ```
//!
//! Response plaintext (enclave → browser), sealed to the client-supplied
//! `reply_pub` with `info = "tee-example/hpke/echo/response/v1"`:
//!
//! ```json
//! {"echo": "<utf-8 text>"}
//! ```
//!
//! The client generates a fresh ephemeral reply keypair per request, so the
//! server keeps no session state and responses are ciphertext-only on the
//! wire in both directions.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::AppState;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub const REQUEST_INFO: &[u8] = b"tee-example/hpke/echo/request/v1";
pub const RESPONSE_INFO: &[u8] = b"tee-example/hpke/echo/response/v1";

/// The wire envelope: base64 of the encapsulated key and the ciphertext.
#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub enc: String,
    pub ct: String,
}

#[derive(Deserialize)]
struct EchoRequest {
    msg: String,
    /// Base64 raw 32-byte X25519 public key the response is sealed to.
    reply_pub: String,
}

/// Single-shot HPKE seal to a raw X25519 recipient public key.
pub fn seal(
    recipient_public: &[u8],
    info: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_public)
        .map_err(|e| format!("invalid recipient public key: {e}"))?;
    let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
    let (encapped, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        &[],
        &mut csprng,
    )
    .map_err(|e| format!("seal failed: {e}"))?;
    Ok((encapped.to_bytes().to_vec(), ct))
}

/// Single-shot HPKE open with the recipient private key.
pub fn open(
    recipient_private: &<Kem as KemTrait>::PrivateKey,
    enc: &[u8],
    info: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, String> {
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
        .map_err(|e| format!("invalid encapsulated key: {e}"))?;
    hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        recipient_private,
        &encapped,
        info,
        ct,
        &[],
    )
    .map_err(|e| format!("open failed: {e}"))
}

/// GET /hpke-key — the enclave's HPKE public key plus the hash forms the
/// client compares against the attestation token's `eat_nonce` entries.
pub async fn hpke_key(State(state): State<AppState>) -> Json<serde_json::Value> {
    let public = state.keys.hpke_public_bytes();
    Json(json!({
        "public_key": B64.encode(&public),
        "sha256": hex::encode(Sha256::digest(&public)),
        "eat_nonce": state.keys.hpke_nonce(),
    }))
}

/// POST /hpke/echo — decrypt the sealed request, seal `{"echo": msg}` back
/// to the client's ephemeral reply key. See module docs for the envelope.
pub async fn hpke_echo(State(state): State<AppState>, Json(envelope): Json<Envelope>) -> Response {
    match echo_inner(&state, &envelope) {
        Ok(reply) => Json(reply).into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
        }
    }
}

fn echo_inner(state: &AppState, envelope: &Envelope) -> Result<Envelope, String> {
    let enc = B64
        .decode(&envelope.enc)
        .map_err(|e| format!("enc is not valid base64: {e}"))?;
    let ct = B64
        .decode(&envelope.ct)
        .map_err(|e| format!("ct is not valid base64: {e}"))?;
    let plaintext = open(state.keys.hpke_private(), &enc, REQUEST_INFO, &ct)?;
    let request: EchoRequest = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("request plaintext is not valid JSON: {e}"))?;
    let reply_pub = B64
        .decode(&request.reply_pub)
        .map_err(|e| format!("reply_pub is not valid base64: {e}"))?;
    let reply_plaintext = json!({ "echo": request.msg }).to_string();
    let (reply_enc, reply_ct) = seal(&reply_pub, RESPONSE_INFO, reply_plaintext.as_bytes())?;
    Ok(Envelope {
        enc: B64.encode(reply_enc),
        ct: B64.encode(reply_ct),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EnclaveKeys;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            keys: Arc::new(EnclaveKeys::generate()),
            dev: false,
        }
    }

    async fn post_json(
        state: AppState,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = crate::app(state)
            .oneshot(
                Request::post(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn hpke_key_hash_matches_published_key() {
        let state = test_state();
        let response = crate::app(state.clone())
            .oneshot(Request::get("/hpke-key").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let public = B64.decode(body["public_key"].as_str().unwrap()).unwrap();
        assert_eq!(public.len(), 32);
        let hash = hex::encode(Sha256::digest(&public));
        assert_eq!(body["sha256"], hash);
        assert_eq!(body["eat_nonce"], format!("hpke:{hash}"));
        assert_eq!(body["eat_nonce"], state.keys.hpke_nonce());
    }

    #[tokio::test]
    async fn echo_roundtrips_through_sealed_envelopes() {
        let state = test_state();
        // Client side: ephemeral reply keypair + sealed request.
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (reply_sk, reply_pk) = Kem::gen_keypair(&mut csprng);
        let request = json!({
            "msg": "hello enclave 🌽",
            "reply_pub": B64.encode(reply_pk.to_bytes()),
        });
        let (enc, ct) = seal(
            &state.keys.hpke_public_bytes(),
            REQUEST_INFO,
            request.to_string().as_bytes(),
        )
        .unwrap();
        let envelope = json!({ "enc": B64.encode(enc), "ct": B64.encode(ct) });

        let (status, reply) = post_json(state, "/hpke/echo", envelope).await;
        assert_eq!(status, StatusCode::OK);

        // Open the reply with the ephemeral private key.
        let plaintext = open(
            &reply_sk,
            &B64.decode(reply["enc"].as_str().unwrap()).unwrap(),
            RESPONSE_INFO,
            &B64.decode(reply["ct"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(body["echo"], "hello enclave 🌽");
    }

    #[tokio::test]
    async fn echo_rejects_envelope_sealed_to_the_wrong_key() {
        let state = test_state();
        let other = EnclaveKeys::generate();
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (_, reply_pk) = Kem::gen_keypair(&mut csprng);
        let request = json!({ "msg": "x", "reply_pub": B64.encode(reply_pk.to_bytes()) });
        let (enc, ct) = seal(
            &other.hpke_public_bytes(),
            REQUEST_INFO,
            request.to_string().as_bytes(),
        )
        .unwrap();
        let envelope = json!({ "enc": B64.encode(enc), "ct": B64.encode(ct) });
        let (status, body) = post_json(state, "/hpke/echo", envelope).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("open failed"));
    }

    // ---- Rust ↔ TypeScript interop fixtures (DESIGN.md open spike #5) ----
    //
    // Shared JSON shape (all byte fields standard base64):
    //   { suite, generator, recipient_private_key, recipient_public_key,
    //     info, aad, plaintext, enc, ct }
    // Each side seals a known message to a known recipient key and commits
    // the fixture; the other side's test suite must open it.

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
    }

    #[test]
    fn rust_fixture_exists_and_opens_in_rust() {
        let path = fixtures_dir().join("hpke-interop.json");
        if !path.exists() {
            // Bootstrap: generate once, commit the result.
            let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
            let (sk, pk) = Kem::gen_keypair(&mut csprng);
            let info = b"tee-example/hpke-interop/v1";
            let plaintext = b"hpke interop test vector, sealed by the rust `hpke` crate";
            let (enc, ct) = seal(&pk.to_bytes(), info, plaintext).unwrap();
            let fixture = json!({
                "suite": {
                    "kem": "DHKEM(X25519, HKDF-SHA256)",
                    "kdf": "HKDF-SHA256",
                    "aead": "ChaCha20Poly1305",
                },
                "generator": "rust hpke v0.13",
                "recipient_private_key": B64.encode(sk.to_bytes()),
                "recipient_public_key": B64.encode(pk.to_bytes()),
                "info": B64.encode(info),
                "aad": "",
                "plaintext": B64.encode(plaintext),
                "enc": B64.encode(enc),
                "ct": B64.encode(ct),
            });
            std::fs::create_dir_all(fixtures_dir()).unwrap();
            std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
        }
        open_fixture(&path);
    }

    #[test]
    fn ts_generated_fixture_opens_in_rust() {
        let path = fixtures_dir().join("hpke-interop-ts.json");
        assert!(
            path.exists(),
            "missing {path:?}: run `pnpm test` in frontend/ to generate it"
        );
        open_fixture(&path);
    }

    fn open_fixture(path: &std::path::Path) {
        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let b64 = |k: &str| B64.decode(fixture[k].as_str().unwrap()).unwrap();
        let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&b64("recipient_private_key")).unwrap();
        let plaintext = open(&sk, &b64("enc"), &b64("info"), &b64("ct"))
            .unwrap_or_else(|e| panic!("failed to open {path:?}: {e}"));
        assert_eq!(
            plaintext,
            b64("plaintext"),
            "plaintext mismatch in {path:?}"
        );
    }
}
