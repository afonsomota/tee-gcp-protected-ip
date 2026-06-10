//! Sealed persistence for ACME state (issue 004).
//!
//! rustls-acme persists two things between boots: the ACME account key and
//! the issued certificate (private key + chain, PEM). Both are stored as a
//! KMS-wrapped blob in GCS so that VM recreation neither hits Let's Encrypt
//! rate limits nor changes the serving key needlessly — and so that only
//! attested workloads can unwrap them (the KMS IAM policy is the gate; see
//! `gcp.rs`).
//!
//! The cache is generic over [`BlobStore`] (where ciphertext lives) and
//! [`Sealer`] (how it is wrapped) so the sealing logic is unit-testable
//! without GCP. Production wiring is `GcsBlobStore` + `KmsSealer`.
//!
//! # TLS key binding
//!
//! The cache is also where the `tls:` attestation binding is kept honest:
//! every certificate that passes through (loaded from the cache at boot, or
//! freshly ordered and stored) has its private key's SubjectPublicKeyInfo
//! extracted and pushed into [`EnclaveKeys::set_tls_spki`]. rustls-acme
//! deploys a new cert to its resolver immediately before calling
//! `store_cert`, so tokens minted after the swap hash the serving key; the
//! window in between is a single scheduler tick and a verifier that hits it
//! simply retries.

use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::keys::EnclaveKeys;

/// Wraps and unwraps blobs. Production: Cloud KMS (`gcp::KmsSealer`).
#[async_trait]
pub trait Sealer: Send + Sync {
    async fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String>;
    async fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String>;
}

/// Stores ciphertext blobs by name. Production: GCS (`gcp::GcsBlobStore`).
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, String>;
    async fn put(&self, name: &str, data: &[u8]) -> Result<(), String>;
}

pub struct SealedCache<B, S> {
    blobs: B,
    sealer: S,
    keys: Arc<EnclaveKeys>,
}

impl<B: BlobStore, S: Sealer> SealedCache<B, S> {
    pub fn new(blobs: B, sealer: S, keys: Arc<EnclaveKeys>) -> Self {
        Self {
            blobs,
            sealer,
            keys,
        }
    }

    async fn load(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        match self.blobs.get(name).await? {
            Some(ciphertext) => Ok(Some(self.sealer.unseal(&ciphertext).await?)),
            None => Ok(None),
        }
    }

    async fn store(&self, name: &str, plaintext: &[u8]) -> Result<(), String> {
        let ciphertext = self.sealer.seal(plaintext).await?;
        self.blobs.put(name, &ciphertext).await
    }
}

/// Deterministic object name for a (kind, identifiers, ACME directory)
/// tuple, so staging and production state never collide and a domain change
/// starts fresh. Hash-based to keep names short and URL-safe.
pub fn object_name(kind: &str, identifiers: &[String], directory_url: &str) -> String {
    let mut hasher = Sha256::new();
    for identifier in identifiers {
        hasher.update(identifier.as_bytes());
        hasher.update([0]);
    }
    hasher.update(directory_url.as_bytes());
    format!("{kind}-{}", hex::encode(&hasher.finalize()[..16]))
}

/// SubjectPublicKeyInfo DER of the private key in a rustls-acme cached cert
/// (PEM: private key first, then the chain).
pub fn spki_from_cert_pem(cert_pem: &[u8]) -> Result<Vec<u8>, String> {
    let blocks = pem::parse_many(cert_pem).map_err(|e| format!("cert is not valid PEM: {e}"))?;
    let key = blocks
        .iter()
        .find(|b| b.tag() == "PRIVATE KEY")
        .ok_or("no PRIVATE KEY block in cached cert")?;
    let keypair = rcgen::KeyPair::try_from(key.contents())
        .map_err(|e| format!("cert private key is not parseable PKCS#8: {e}"))?;
    use rcgen::PublicKeyData;
    Ok(keypair.subject_public_key_info())
}

#[async_trait]
impl<B: BlobStore, S: Sealer> rustls_acme::CertCache for SealedCache<B, S> {
    type EC = String;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let pem = self
            .load(&object_name("cert", domains, directory_url))
            .await?;
        if let Some(pem) = &pem {
            // Bind before rustls-acme deploys the cert to its resolver.
            self.keys.set_tls_spki(spki_from_cert_pem(pem)?);
        }
        Ok(pem)
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        // Rebind first: the freshly ordered cert is already serving.
        self.keys.set_tls_spki(spki_from_cert_pem(cert)?);
        self.store(&object_name("cert", domains, directory_url), cert)
            .await
    }
}

#[async_trait]
impl<B: BlobStore, S: Sealer> rustls_acme::AccountCache for SealedCache<B, S> {
    type EA = String;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        self.load(&object_name("account", contact, directory_url))
            .await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        self.store(&object_name("account", contact, directory_url), account)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_acme::{AccountCache, CertCache};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory store; also records names so tests can assert layout.
    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, Vec<u8>>>);

    #[async_trait]
    impl BlobStore for MemStore {
        async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.lock().unwrap().get(name).cloned())
        }
        async fn put(&self, name: &str, data: &[u8]) -> Result<(), String> {
            self.0.lock().unwrap().insert(name.into(), data.to_vec());
            Ok(())
        }
    }

    /// Reversible stand-in for KMS: prefixes a marker so sealed bytes are
    /// distinguishable from plaintext and tampering is detectable.
    struct MarkSealer;

    #[async_trait]
    impl Sealer for MarkSealer {
        async fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            Ok([b"SEALED:".as_slice(), plaintext].concat())
        }
        async fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            ciphertext
                .strip_prefix(b"SEALED:".as_slice())
                .map(<[u8]>::to_vec)
                .ok_or_else(|| "ciphertext missing seal marker".to_string())
        }
    }

    fn cache() -> SealedCache<MemStore, MarkSealer> {
        SealedCache::new(
            MemStore::default(),
            MarkSealer,
            Arc::new(EnclaveKeys::generate()),
        )
    }

    /// A cached-cert PEM exactly as rustls-acme writes it: PKCS#8 private
    /// key block first, then the certificate chain.
    fn fake_cached_cert() -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["api.example.com".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = format!("{}\n{}", key.serialize_pem(), cert.pem());
        use rcgen::PublicKeyData;
        (pem.into_bytes(), key.subject_public_key_info())
    }

    #[test]
    fn object_names_are_distinct_per_kind_domains_and_directory() {
        let domains = vec!["api.example.com".to_string()];
        let cert = object_name("cert", &domains, "https://acme/dir");
        assert_ne!(cert, object_name("account", &domains, "https://acme/dir"));
        assert_ne!(cert, object_name("cert", &domains, "https://acme/other"));
        assert_ne!(
            cert,
            object_name(
                "cert",
                &["other.example.com".to_string()],
                "https://acme/dir"
            )
        );
        // Same inputs, same name: state must be findable across boots.
        assert_eq!(cert, object_name("cert", &domains, "https://acme/dir"));
    }

    #[test]
    fn spki_extraction_matches_the_generating_key() {
        let (pem, expected_spki) = fake_cached_cert();
        assert_eq!(spki_from_cert_pem(&pem).unwrap(), expected_spki);
    }

    #[test]
    fn spki_extraction_rejects_pem_without_a_key() {
        let (pem, _) = fake_cached_cert();
        let pem_str = String::from_utf8(pem).unwrap();
        let cert_only = pem_str.split_once("-----BEGIN CERTIFICATE-----").unwrap();
        let cert_only = format!("-----BEGIN CERTIFICATE-----{}", cert_only.1);
        let err = spki_from_cert_pem(cert_only.as_bytes()).unwrap_err();
        assert!(err.contains("no PRIVATE KEY"), "{err}");
    }

    #[tokio::test]
    async fn cert_roundtrips_sealed_and_rebinds_the_tls_nonce() {
        let cache = cache();
        let domains = vec!["api.example.com".to_string()];
        let dir = "https://acme/dir";
        assert_eq!(cache.load_cert(&domains, dir).await.unwrap(), None);

        let (pem, spki) = fake_cached_cert();
        let nonce_before = cache.keys.tls_nonce();
        cache.store_cert(&domains, dir, &pem).await.unwrap();

        // Binding moved from the boot placeholder to the cert's key.
        let expected = format!("tls:{}", hex::encode(Sha256::digest(&spki)));
        assert_ne!(cache.keys.tls_nonce(), nonce_before);
        assert_eq!(cache.keys.tls_nonce(), expected);
        assert!(cache.keys.tls_nonce().len() <= 74);

        // The blob at rest is sealed, not plaintext.
        let name = object_name("cert", &domains, dir);
        let at_rest = cache.blobs.get(&name).await.unwrap().unwrap();
        assert!(at_rest.starts_with(b"SEALED:"));
        assert_ne!(at_rest, pem);

        // Loading returns the original PEM and keeps the binding.
        assert_eq!(cache.load_cert(&domains, dir).await.unwrap(), Some(pem));
        assert_eq!(cache.keys.tls_nonce(), expected);
    }

    #[tokio::test]
    async fn account_roundtrips_sealed_without_touching_tls_binding() {
        let cache = cache();
        let contact = vec!["mailto:ops@example.com".to_string()];
        let dir = "https://acme/dir";
        assert_eq!(cache.load_account(&contact, dir).await.unwrap(), None);

        let nonce_before = cache.keys.tls_nonce();
        cache
            .store_account(&contact, dir, b"account-key-bytes")
            .await
            .unwrap();
        assert_eq!(
            cache.load_account(&contact, dir).await.unwrap(),
            Some(b"account-key-bytes".to_vec())
        );
        assert_eq!(cache.keys.tls_nonce(), nonce_before);
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_closed() {
        let cache = cache();
        let contact = vec!["mailto:ops@example.com".to_string()];
        let dir = "https://acme/dir";
        cache.store_account(&contact, dir, b"secret").await.unwrap();

        let name = object_name("account", &contact, dir);
        cache.blobs.put(&name, b"garbage").await.unwrap();
        let err = cache.load_account(&contact, dir).await.unwrap_err();
        assert!(err.contains("seal marker"), "{err}");
    }
}
