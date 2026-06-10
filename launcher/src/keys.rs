//! Per-boot enclave key material and its attestation binding.
//!
//! At boot the launcher generates:
//!   * an X25519 HPKE keypair — the channel key the frontend encrypts to;
//!   * a TLS keypair — generated and hashed now so the binding format is
//!     fixed from day one; actual TLS serving (rustls-acme) is issue 004.
//!
//! # Binding encoding (resolves DESIGN.md open spike #2)
//!
//! A Confidential Space token request accepts an array of nonces: "Up to six
//! nonces are allowed. Each nonce must be between 10 and 74 bytes" (per
//! <https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources>,
//! checked 2026-06-10). Two hex-encoded SHA-256 hashes therefore fit as
//! *separate, self-describing* nonces alongside the caller's challenge — no
//! combined-hash structure is needed:
//!
//! ```text
//! eat_nonce = [ <caller challenge>, "hpke:<sha256 hex>", "tls:<sha256 hex>" ]
//! ```
//!
//! `"hpke:" + 64` hex chars = 69 bytes and `"tls:" + 64` = 68 bytes, both
//! within the 74-byte cap; three nonces total, within the cap of six.
//!
//! Hash preimages: the raw 32-byte X25519 public key for `hpke:`; the
//! SubjectPublicKeyInfo DER of the TLS public key for `tls:`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem as KemTrait, Serializable};
use rcgen::PublicKeyData;
use serde_json::json;
use sha2::{Digest, Sha256};

/// Image digest baked into dev-mode tokens; obviously not a real digest.
pub const DEV_IMAGE_DIGEST: &str = "sha256:dev-mode-unverified-image-digest";

pub struct EnclaveKeys {
    hpke_private: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    hpke_public: <X25519HkdfSha256 as KemTrait>::PublicKey,
    /// Held for issue 004 (TLS serving); only its public-key hash is used now.
    #[allow(dead_code)]
    tls_key: rcgen::KeyPair,
    tls_spki_der: Vec<u8>,
}

impl EnclaveKeys {
    /// Generate fresh keypairs. Called once per boot: the keys live only in
    /// enclave memory and die with the instance.
    pub fn generate() -> Self {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (hpke_private, hpke_public) = X25519HkdfSha256::gen_keypair(&mut csprng);
        let tls_key = rcgen::KeyPair::generate().expect("TLS keypair generation");
        let tls_spki_der = tls_key.subject_public_key_info();
        Self {
            hpke_private,
            hpke_public,
            tls_key,
            tls_spki_der,
        }
    }

    pub(crate) fn hpke_private(&self) -> &<X25519HkdfSha256 as KemTrait>::PrivateKey {
        &self.hpke_private
    }

    /// Raw 32-byte X25519 public key (the `hpke:` hash preimage).
    pub fn hpke_public_bytes(&self) -> Vec<u8> {
        self.hpke_public.to_bytes().to_vec()
    }

    /// `"hpke:<sha256 hex of raw public key>"` — 69 bytes, fits a nonce slot.
    pub fn hpke_nonce(&self) -> String {
        format!(
            "hpke:{}",
            hex::encode(Sha256::digest(self.hpke_public_bytes()))
        )
    }

    /// `"tls:<sha256 hex of SubjectPublicKeyInfo DER>"` — 68 bytes.
    pub fn tls_nonce(&self) -> String {
        format!("tls:{}", hex::encode(Sha256::digest(&self.tls_spki_der)))
    }

    /// An *unsigned* attestation-shaped JWT for local development, where no
    /// Confidential Space attestation service exists. Header `alg: none`,
    /// empty signature, issuer `urn:tee-example:dev-unverified` — impossible
    /// to mistake for (or verify as) a Google-signed token. The claims mirror
    /// the real token's shape (`eat_nonce`, `submods.container.image_digest`)
    /// so the frontend's digest and key-binding checks run unchanged.
    pub fn dev_token(&self, audience: &str, challenge: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_secs();
        let image_digest =
            std::env::var("DEV_IMAGE_DIGEST").unwrap_or_else(|_| DEV_IMAGE_DIGEST.to_string());
        let header = json!({ "alg": "none", "typ": "JWT" });
        let payload = json!({
            "iss": "urn:tee-example:dev-unverified",
            "aud": audience,
            "iat": now,
            "exp": now + 3600,
            "eat_nonce": [challenge, self.hpke_nonce(), self.tls_nonce()],
            "submods": { "container": { "image_digest": image_digest } },
            "hwmodel": "DEV_MODE_UNVERIFIED",
            "swname": "DEV_MODE_UNVERIFIED",
            "dbgstat": "enabled",
        });
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string()),
        )
    }
}
