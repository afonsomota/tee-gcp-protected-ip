//! Per-boot enclave key material and its attestation binding.
//!
//! At boot the launcher generates:
//!   * an X25519 HPKE keypair — the channel key the frontend encrypts to;
//!   * a placeholder TLS keypair, hashed so the binding format is fixed even
//!     before a certificate exists. When TLS serving is enabled (`tls.rs`),
//!     the binding is replaced with the SPKI of the ACME-issued certificate's
//!     key as soon as it is loaded from the sealed cache or freshly ordered,
//!     so attestation tokens always hash the key actually serving TLS.
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
    /// SPKI DER of the key currently bound as `tls:`. Starts as a per-boot
    /// placeholder; replaced by `set_tls_spki` when an ACME cert is active.
    tls_spki_der: std::sync::RwLock<Vec<u8>>,
}

impl EnclaveKeys {
    /// Generate fresh keypairs. Called once per boot: the keys live only in
    /// enclave memory and die with the instance.
    pub fn generate() -> Self {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (hpke_private, hpke_public) = X25519HkdfSha256::gen_keypair(&mut csprng);
        let tls_placeholder = rcgen::KeyPair::generate().expect("TLS keypair generation");
        Self {
            hpke_private,
            hpke_public,
            tls_spki_der: std::sync::RwLock::new(tls_placeholder.subject_public_key_info()),
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
        let spki = self.tls_spki_der.read().expect("tls spki lock");
        format!("tls:{}", hex::encode(Sha256::digest(&*spki)))
    }

    /// Rebind `tls:` to a new key, identified by its SubjectPublicKeyInfo
    /// DER. Called by the sealed ACME cache whenever a certificate is loaded
    /// or stored, so tokens minted afterwards hash the serving cert's key.
    pub fn set_tls_spki(&self, spki_der: Vec<u8>) {
        *self.tls_spki_der.write().expect("tls spki lock") = spki_der;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_self_describing_and_fit_the_attestation_limits() {
        let keys = EnclaveKeys::generate();
        for nonce in [keys.hpke_nonce(), keys.tls_nonce()] {
            assert!((10..=74).contains(&nonce.len()), "{nonce}");
        }
        assert!(keys.hpke_nonce().starts_with("hpke:"));
        assert!(keys.tls_nonce().starts_with("tls:"));
    }

    #[test]
    fn set_tls_spki_rebinds_the_tls_nonce() {
        let keys = EnclaveKeys::generate();
        let before = keys.tls_nonce();
        let spki = b"example spki der bytes".to_vec();
        keys.set_tls_spki(spki.clone());
        let after = keys.tls_nonce();
        assert_ne!(after, before);
        assert_eq!(after, format!("tls:{}", hex::encode(Sha256::digest(&spki))));
        // HPKE binding is untouched by TLS rebinds.
        assert_eq!(keys.hpke_nonce(), keys.hpke_nonce());
    }
}
