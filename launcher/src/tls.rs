//! TLS terminated inside the enclave (issue 004).
//!
//! When `TLS_DOMAIN` is set the launcher serves HTTPS directly: rustls-acme
//! obtains and renews a Let's Encrypt certificate via the TLS-ALPN-01
//! challenge (no port 80, no proxy, no load balancer — the TLS private key
//! never exists outside enclave memory). Nothing persists across boots:
//! every boot registers a fresh ACME account and orders a fresh certificate
//! (`acme_cache.rs` has the rationale and the rate-limit arithmetic).
//!
//! Outbound TLS to the ACME directory uses compiled-in `webpki-roots`
//! (rustls-acme is built with its `webpki-roots` feature): the trust anchors
//! are pinned by the audited, reproducible build instead of inherited from
//! whatever CA bundle the runtime base image happens to ship.
//!
//! Threat model: TLS here is defense-in-depth and ordinary web hygiene; the
//! user-facing privacy guarantee rides on the attested HPKE channel, not on
//! the certificate authority ecosystem. See docs/DESIGN.md.
//!
//! # Configuration
//!
//! In production these values arrive as GCE instance metadata attributes set
//! by Terraform (`tls-domain`, `acme-contact`, `acme-directory`), read via the
//! metadata server in [`TlsConfig::resolve`]. Deliberately *not* environment
//! variables: the release image must never carry
//! `tee.launch_policy.allow_env_override` (scripts/build-image.sh fails the
//! build if it appears), so the operator has no channel to inject environment
//! into the audited process. The matching `TLS_DOMAIN` / `ACME_CONTACT` /
//! `ACME_DIRECTORY` / `HTTPS_PORT` env vars exist as a dev/test override only —
//! without the launch-policy label they are not operator-settable in
//! production. `HTTPS_PORT` is env-only (local testing); production always
//! listens on 443.
//!
//! | Attribute / env var          | Meaning                                  |
//! |------------------------------|------------------------------------------|
//! | `tls-domain` / `TLS_DOMAIN`  | Domain to serve/order a cert for; unset = plain HTTP |
//! | `acme-contact` / `ACME_CONTACT` | Contact email for the ACME account (required) |
//! | `acme-directory` / `ACME_DIRECTORY` | `letsencrypt`, `letsencrypt-staging` (default), or a directory URL |
//! | `HTTPS_PORT` (env only)      | Listen port, default 443 (TLS-ALPN-01 validates on 443 only; non-default is for local testing) |

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::StreamExt;
use rustls_acme::AcmeConfig;

use crate::acme_cache::InMemoryCache;
use crate::AppState;

pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, PartialEq)]
pub struct TlsConfig {
    pub domain: String,
    pub contact: String,
    pub directory_url: String,
    pub https_port: u16,
}

impl TlsConfig {
    /// `Ok(None)` when TLS is disabled (`TLS_DOMAIN` unset); `Err` when it is
    /// enabled but incoherently configured — refuse to boot half-configured.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let nonempty = |name: &str| get(name).filter(|value| !value.is_empty());
        let Some(domain) = nonempty("TLS_DOMAIN") else {
            return Ok(None);
        };
        let require = |name: &str| {
            nonempty(name).ok_or(format!("TLS_DOMAIN is set but {name} is missing or empty"))
        };
        let directory_url = match nonempty("ACME_DIRECTORY").as_deref() {
            None | Some("letsencrypt-staging") => LETS_ENCRYPT_STAGING.to_string(),
            Some("letsencrypt") => LETS_ENCRYPT_PRODUCTION.to_string(),
            Some(url) if url.starts_with("https://") => url.to_string(),
            Some(other) => {
                return Err(format!(
                    "ACME_DIRECTORY must be `letsencrypt`, `letsencrypt-staging`, \
                     or an https:// directory URL, got `{other}`"
                ))
            }
        };
        let https_port = match get("HTTPS_PORT") {
            None => 443,
            Some(p) => p
                .parse()
                .map_err(|_| format!("HTTPS_PORT is not a valid port: `{p}`"))?,
        };
        Ok(Some(Self {
            domain,
            contact: require("ACME_CONTACT")?,
            directory_url,
            https_port,
        }))
    }

    /// Resolve TLS configuration for production: `TLS_DOMAIN` etc. from the
    /// environment first (dev/test override; not operator-settable in
    /// production, see module docs), otherwise from GCE instance metadata
    /// attributes (`tls-domain`, `acme-contact`, `acme-directory`). `HTTPS_PORT`
    /// stays env-only. The gathered values feed the existing [`from_lookup`]
    /// validation, so a half-configured domain is still a boot error and a
    /// metadata-server failure is an error, never a silent fallback.
    ///
    /// [`from_lookup`]: Self::from_lookup
    pub async fn resolve() -> Result<Option<Self>, String> {
        use std::collections::HashMap;

        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let mut values: HashMap<&'static str, String> = HashMap::new();

        // env-first; only probe metadata for keys the environment didn't set.
        for (env_name, attribute) in [
            ("TLS_DOMAIN", "tls-domain"),
            ("ACME_CONTACT", "acme-contact"),
            ("ACME_DIRECTORY", "acme-directory"),
        ] {
            let value = match env(env_name) {
                Some(v) => Some(v),
                None => crate::gcp::instance_attribute(attribute).await?,
            };
            if let Some(value) = value {
                values.insert(env_name, value);
            }
        }
        // HTTPS_PORT is dev/test-only (production validates on 443); never a
        // metadata attribute.
        if let Some(port) = env("HTTPS_PORT") {
            values.insert("HTTPS_PORT", port);
        }

        Self::from_lookup(|name| values.get(name).cloned())
    }
}

/// Serve the app over HTTPS, never returning. TLS-ALPN-01 challenge
/// handshakes are answered on the same port by the acceptor.
pub async fn serve(state: AppState, config: TlsConfig) {
    let cache = InMemoryCache::new(Arc::clone(&state.keys));
    let mut acme = AcmeConfig::new([config.domain.clone()])
        .contact_push(format!("mailto:{}", config.contact))
        .directory(&config.directory_url)
        .cache(cache)
        .state();
    let acceptor = acme.axum_acceptor(acme.default_rustls_config());
    tokio::spawn(async move {
        // Drive ACME: cache loads, orders, renewals. Events are the audit
        // trail of every cert/account state change.
        loop {
            match acme.next().await {
                Some(Ok(event)) => println!("acme event: {event:?}"),
                Some(Err(error)) => eprintln!("acme error: {error:?}"),
                None => break,
            }
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], config.https_port));
    println!(
        "launcher serving https://{} on {addr} (acme directory: {})",
        config.domain, config.directory_url
    );
    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(crate::app(state).into_make_service())
        .await
        .expect("https serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    const FULL: &[(&str, &str)] = &[
        ("TLS_DOMAIN", "api.example.com"),
        ("ACME_CONTACT", "ops@example.com"),
    ];

    #[test]
    fn no_domain_means_tls_disabled() {
        assert_eq!(TlsConfig::from_lookup(lookup(&[])).unwrap(), None);
        // Other vars without a domain still mean disabled.
        let partial = lookup(&[("ACME_CONTACT", "ops@example.com")]);
        assert_eq!(TlsConfig::from_lookup(partial).unwrap(), None);
        // Empty string counts as unset.
        let empty = lookup(&[("TLS_DOMAIN", "")]);
        assert_eq!(TlsConfig::from_lookup(empty).unwrap(), None);
    }

    #[test]
    fn full_config_parses_with_safe_defaults() {
        let config = TlsConfig::from_lookup(lookup(FULL)).unwrap().unwrap();
        assert_eq!(config.domain, "api.example.com");
        assert_eq!(config.contact, "ops@example.com");
        // Defaults: staging directory (rate-limit safety) and port 443.
        assert_eq!(config.directory_url, LETS_ENCRYPT_STAGING);
        assert_eq!(config.https_port, 443);
    }

    #[test]
    fn missing_contact_is_a_boot_error() {
        let err = TlsConfig::from_lookup(lookup(&[("TLS_DOMAIN", "api.example.com")])).unwrap_err();
        assert!(err.contains("ACME_CONTACT"), "{err}");
    }

    #[test]
    fn directory_selector_accepts_names_and_urls() {
        let with = |dir: &str| {
            let mut pairs = FULL.to_vec();
            let owned = dir.to_string();
            let pairs_owned: Vec<(String, String)> = pairs
                .drain(..)
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .chain(std::iter::once(("ACME_DIRECTORY".to_string(), owned)))
                .collect();
            let map: HashMap<String, String> = pairs_owned.into_iter().collect();
            TlsConfig::from_lookup(move |name| map.get(name).cloned())
        };
        assert_eq!(
            with("letsencrypt").unwrap().unwrap().directory_url,
            LETS_ENCRYPT_PRODUCTION
        );
        assert_eq!(
            with("letsencrypt-staging").unwrap().unwrap().directory_url,
            LETS_ENCRYPT_STAGING
        );
        assert_eq!(
            with("https://pebble.local/dir")
                .unwrap()
                .unwrap()
                .directory_url,
            "https://pebble.local/dir"
        );
        assert!(with("http://insecure/dir").is_err());
        assert!(with("bogus").is_err());
    }

    #[test]
    fn https_port_is_honored() {
        let mut pairs = FULL.to_vec();
        pairs.push(("HTTPS_PORT", "8443"));
        let config = TlsConfig::from_lookup(lookup(&pairs)).unwrap().unwrap();
        assert_eq!(config.https_port, 8443);

        let mut bad = FULL.to_vec();
        bad.push(("HTTPS_PORT", "not-a-port"));
        assert!(TlsConfig::from_lookup(lookup(&bad)).is_err());
    }
}
