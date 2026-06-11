//! In-memory ACME cache (issue 004).
//!
//! rustls-acme caches two things: the ACME account key and the issued
//! certificate (private key + chain, PEM). We deliberately persist neither —
//! every boot registers a fresh account and orders a fresh certificate, and
//! both die with the instance.
//!
//! Persisting them (the earlier design: KMS-wrapped blobs in GCS, unwrap
//! gated on attestation) would put GCS/KMS/STS client code — several hundred
//! lines — into the audited TCB to defend a property the platform cannot
//! deliver anyway: the KMS key lives in the operator's project, and a
//! project owner can always re-grant themselves decrypt. Fresh issuance per
//! boot costs only Let's Encrypt rate limits, which the staging directory
//! (the default, ~unlimited issuance) absorbs; production limits
//! (5 duplicates and 50 certs per domain per week) cover occasional live
//! demos. See docs/DESIGN.md.
//!
//! # TLS key binding
//!
//! The cache is also where the `tls:` attestation binding is kept honest:
//! every certificate that passes through has its private key's
//! SubjectPublicKeyInfo extracted and pushed into
//! [`EnclaveKeys::set_tls_spki`]. rustls-acme deploys a new cert to its
//! resolver immediately before calling `store_cert`, so tokens minted after
//! the swap hash the serving key; the window in between is a single
//! scheduler tick and a verifier that hits it simply retries.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::keys::EnclaveKeys;

pub struct InMemoryCache {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    keys: Arc<EnclaveKeys>,
}

impl InMemoryCache {
    pub fn new(keys: Arc<EnclaveKeys>) -> Self {
        Self {
            blobs: Mutex::new(HashMap::new()),
            keys,
        }
    }

    fn load(&self, name: &str) -> Option<Vec<u8>> {
        self.blobs.lock().expect("cache lock").get(name).cloned()
    }

    fn store(&self, name: &str, data: &[u8]) {
        self.blobs
            .lock()
            .expect("cache lock")
            .insert(name.to_string(), data.to_vec());
    }
}

/// Cache key for a (kind, identifiers, ACME directory) tuple, so staging and
/// production state never collide within a boot.
fn cache_name(kind: &str, identifiers: &[String], directory_url: &str) -> String {
    format!("{kind}\0{}\0{directory_url}", identifiers.join("\0"))
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
impl rustls_acme::CertCache for InMemoryCache {
    type EC = String;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let pem = self.load(&cache_name("cert", domains, directory_url));
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
        self.store(&cache_name("cert", domains, directory_url), cert);
        Ok(())
    }
}

#[async_trait]
impl rustls_acme::AccountCache for InMemoryCache {
    type EA = String;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        Ok(self.load(&cache_name("account", contact, directory_url)))
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        self.store(&cache_name("account", contact, directory_url), account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_acme::{AccountCache, CertCache};
    use sha2::{Digest, Sha256};

    fn cache() -> InMemoryCache {
        InMemoryCache::new(Arc::new(EnclaveKeys::generate()))
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
    fn cache_names_are_distinct_per_kind_domains_and_directory() {
        let domains = vec!["api.example.com".to_string()];
        let cert = cache_name("cert", &domains, "https://acme/dir");
        assert_ne!(cert, cache_name("account", &domains, "https://acme/dir"));
        assert_ne!(cert, cache_name("cert", &domains, "https://acme/other"));
        assert_ne!(
            cert,
            cache_name(
                "cert",
                &["other.example.com".to_string()],
                "https://acme/dir"
            )
        );
        assert_eq!(cert, cache_name("cert", &domains, "https://acme/dir"));
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
    async fn cert_roundtrips_and_rebinds_the_tls_nonce() {
        let cache = cache();
        let domains = vec!["api.example.com".to_string()];
        let dir = "https://acme/dir";
        // Nothing persists across boots: a fresh cache is always empty.
        assert_eq!(cache.load_cert(&domains, dir).await.unwrap(), None);

        let (pem, spki) = fake_cached_cert();
        let nonce_before = cache.keys.tls_nonce();
        cache.store_cert(&domains, dir, &pem).await.unwrap();

        // Binding moved from the boot placeholder to the cert's key.
        let expected = format!("tls:{}", hex::encode(Sha256::digest(&spki)));
        assert_ne!(cache.keys.tls_nonce(), nonce_before);
        assert_eq!(cache.keys.tls_nonce(), expected);
        assert!(cache.keys.tls_nonce().len() <= 74);

        // Loading within the same boot returns the PEM and keeps the binding.
        assert_eq!(cache.load_cert(&domains, dir).await.unwrap(), Some(pem));
        assert_eq!(cache.keys.tls_nonce(), expected);
    }

    #[tokio::test]
    async fn account_roundtrips_without_touching_tls_binding() {
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
}
