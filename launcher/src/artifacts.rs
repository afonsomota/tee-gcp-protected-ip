//! Attestation-gated delivery of the model weights (issue #7).
//!
//! Release images ship without weights (spike 002). At boot, if the operator
//! configured a weights manifest, the launcher: fetches the manifest from
//! GCS, unwraps its data-encryption key with Cloud KMS *as the attested
//! workload-identity principal* (the only principal granted decrypt — see
//! infra/), streams the ciphertext from GCS through the envelope decryptor
//! into the tmpfs at `/models` (plaintext weights only ever exist in
//! SEV-SNP-encrypted guest memory), verifies size and SHA-256, and hands the
//! file to the llama-server supervisor. `/chat` serves errors until the
//! model is up — the same window as an image-baked model load.
//!
//! # Configuration
//!
//! Production: GCE instance metadata attributes set by Terraform
//! (`weights-bucket`, `weights-object`, `weights-kms-key`,
//! `weights-wip-audience`). Deliberately *not* environment variables: the
//! release image must never carry `tee.launch_policy.allow_env_override`
//! (scripts/build-image.sh fails the build if it appears), and instance
//! metadata gives the operator a config channel that cannot reach into the
//! audited process environment. `WEIGHTS_*` env vars exist as a dev/test
//! override only — without the launch-policy label they are not
//! operator-settable in production.
//!
//! # Envelope format
//!
//! Sealed by scripts/provision-weights.py: ChaCha20-Poly1305 in the
//! RustCrypto STREAM (BE32) construction, `chunk_size` plaintext bytes per
//! segment, AAD = the format string, DEK wrapped by KMS. The interop fixture
//! launcher/tests/fixtures/artifact-envelope.json pins the format between
//! the Python encryptor and this decryptor — regenerate it and run both test
//! suites if anything here changes.

use std::io::Write;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::stream::DecryptorBE32;
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use http_body_util::BodyExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const ENVELOPE_FORMAT: &str = "tee-example/artifact-envelope/v1";
const ENVELOPE_CIPHER: &str = "chacha20poly1305-stream-be32";
const ENVELOPE_AAD: &[u8] = ENVELOPE_FORMAT.as_bytes();
const TAG_SIZE: usize = 16;
const NONCE_PREFIX_SIZE: usize = 7;
/// Upper bound on accepted chunk sizes: a decoy manifest must not be able to
/// make the per-segment buffer arbitrarily large.
const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Where the decrypted model lands: the Confidential Space `tee-mount` tmpfs.
const DEFAULT_DEST: &str = "/models/model.gguf";

const FETCH_ATTEMPTS: u32 = 3;
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(15);

struct Config {
    bucket: String,
    object: String,
    kms_key: String,
    /// `None` only in dev/test setups; production always authenticates KMS
    /// via the attested federated token.
    wip_audience: Option<String>,
}

impl Config {
    /// Resolve weights configuration: `WEIGHTS_*` env vars first (dev/test
    /// override; not operator-settable in production, see module docs), then
    /// GCE instance metadata attributes. `None` = weights delivery not
    /// configured.
    async fn resolve(dev: bool) -> Option<Config> {
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        if let Some(object) = env("WEIGHTS_OBJECT") {
            return Some(Config {
                bucket: env("WEIGHTS_BUCKET")?,
                object,
                kms_key: env("WEIGHTS_KMS_KEY")?,
                wip_audience: env("WEIGHTS_WIP_AUDIENCE"),
            });
        }
        if dev {
            // Dev machines have no metadata server; don't probe for one.
            return None;
        }
        let attr = |name: &'static str| async move {
            crate::gcp::instance_attribute(name)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("weights: metadata attribute {name} unavailable: {e}");
                    None
                })
        };
        let object = attr("weights-object").await?;
        Some(Config {
            bucket: attr("weights-bucket").await?,
            object,
            kms_key: attr("weights-kms-key").await?,
            wip_audience: attr("weights-wip-audience").await,
        })
    }
}

/// If weights delivery is configured, spawn the fetch→decrypt→serve pipeline
/// and return the inference upstream `/chat` should (eventually) reach.
/// `None` = not configured; the caller falls back to `llama::init_from_env`.
pub async fn init(dev: bool) -> Option<String> {
    let config = Config::resolve(dev).await?;
    println!(
        "weights: delivering gs://{}/{} (KMS {})",
        config.bucket, config.object, config.kms_key
    );
    let upstream = crate::llama::planned_upstream();
    tokio::spawn(async move {
        for attempt in 1..=FETCH_ATTEMPTS {
            match deliver(&config).await {
                Ok(path) => {
                    crate::llama::start(path);
                    return;
                }
                // Boot races IAM propagation on a fresh deployment; retry a
                // few times before giving up (the VM stays up either way —
                // /chat keeps serving errors).
                Err(e) => eprintln!("weights: attempt {attempt}/{FETCH_ATTEMPTS} failed: {e}"),
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
        eprintln!("weights: giving up; /chat will keep failing");
    });
    Some(upstream)
}

#[derive(Deserialize)]
struct Manifest {
    format: String,
    cipher: String,
    chunk_size: usize,
    nonce_prefix: String,
    wrapped_dek: String,
    plaintext_size: u64,
    plaintext_sha256: String,
    ciphertext_object: String,
}

impl Manifest {
    fn parse(bytes: &[u8]) -> Result<Manifest, String> {
        let manifest: Manifest =
            serde_json::from_slice(bytes).map_err(|e| format!("manifest is not valid: {e}"))?;
        if manifest.format != ENVELOPE_FORMAT {
            return Err(format!("unsupported envelope format {:?}", manifest.format));
        }
        if manifest.cipher != ENVELOPE_CIPHER {
            return Err(format!("unsupported cipher {:?}", manifest.cipher));
        }
        if manifest.chunk_size == 0 || manifest.chunk_size > MAX_CHUNK_SIZE {
            return Err(format!("chunk_size {} out of range", manifest.chunk_size));
        }
        Ok(manifest)
    }
}

/// Fetch the manifest, unwrap the DEK as the attested principal, stream the
/// ciphertext through the decryptor onto tmpfs, verify, and return the path.
async fn deliver(config: &Config) -> Result<String, String> {
    let gcs_token = crate::gcp::metadata_access_token().await?;
    let manifest =
        Manifest::parse(&crate::gcp::gcs_get(&gcs_token, &config.bucket, &config.object).await?)?;

    let wrapped_dek = B64
        .decode(&manifest.wrapped_dek)
        .map_err(|e| format!("manifest wrapped_dek is not base64: {e}"))?;
    // The attestation-gated step: only an attested workload running the
    // expected image digest can make this call succeed.
    let dek = crate::gcp::kms_decrypt(
        &config.kms_key,
        config.wip_audience.as_deref(),
        &wrapped_dek,
    )
    .await?;
    let nonce_prefix = B64
        .decode(&manifest.nonce_prefix)
        .map_err(|e| format!("manifest nonce_prefix is not base64: {e}"))?;

    let dest = std::env::var("WEIGHTS_DEST").unwrap_or_else(|_| DEFAULT_DEST.to_string());
    let file = std::fs::File::create(&dest)
        .map_err(|e| format!("cannot create {dest} (is the tmpfs mounted?): {e}"))?;
    let mut decryptor = EnvelopeDecryptor::new(
        &dek,
        &nonce_prefix,
        manifest.chunk_size,
        std::io::BufWriter::new(file),
    )?;

    let mut body =
        crate::gcp::gcs_get_stream(&gcs_token, &config.bucket, &manifest.ciphertext_object).await?;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| format!("ciphertext download failed: {e}"))?;
        if let Some(data) = frame.data_ref() {
            decryptor.update(data)?;
        }
    }
    let (size, sha256) = decryptor.finish()?;

    if size != manifest.plaintext_size || hex::encode(sha256) != manifest.plaintext_sha256 {
        std::fs::remove_file(&dest).ok();
        return Err(format!(
            "decrypted weights do not match the manifest: got {size} bytes / sha256 {}, \
             expected {} bytes / sha256 {}",
            hex::encode(sha256),
            manifest.plaintext_size,
            manifest.plaintext_sha256
        ));
    }
    println!("weights: decrypted {size} bytes to {dest} (sha256 verified)");
    Ok(dest)
}

/// Streaming decryptor for the STREAM-BE32 envelope: feed ciphertext bytes
/// in arbitrary slices with `update`, then call `finish` once the stream
/// ends. Plaintext is written to the sink as full segments decrypt; size and
/// SHA-256 accumulate for the manifest check.
struct EnvelopeDecryptor<W: Write> {
    stream: DecryptorBE32<ChaCha20Poly1305>,
    /// Ciphertext bytes per full segment: `chunk_size` plaintext + tag.
    segment_size: usize,
    buf: Vec<u8>,
    sink: W,
    hasher: Sha256,
    plaintext_size: u64,
}

impl<W: Write> EnvelopeDecryptor<W> {
    fn new(dek: &[u8], nonce_prefix: &[u8], chunk_size: usize, sink: W) -> Result<Self, String> {
        if dek.len() != 32 {
            return Err(format!("DEK must be 32 bytes, got {}", dek.len()));
        }
        if nonce_prefix.len() != NONCE_PREFIX_SIZE {
            return Err(format!(
                "nonce prefix must be {NONCE_PREFIX_SIZE} bytes, got {}",
                nonce_prefix.len()
            ));
        }
        let cipher = ChaCha20Poly1305::new(dek.into());
        Ok(Self {
            stream: DecryptorBE32::from_aead(cipher, nonce_prefix.into()),
            segment_size: chunk_size + TAG_SIZE,
            buf: Vec::new(),
            sink,
            hasher: Sha256::new(),
            plaintext_size: 0,
        })
    }

    fn update(&mut self, data: &[u8]) -> Result<(), String> {
        self.buf.extend_from_slice(data);
        // A full segment is decryptable only once at least one byte follows
        // it — otherwise it might be the final segment, whose nonce carries
        // the last-flag and must wait for `finish`.
        while self.buf.len() > self.segment_size {
            let rest = self.buf.split_off(self.segment_size);
            let segment = std::mem::replace(&mut self.buf, rest);
            let plaintext = self
                .stream
                .decrypt_next(Payload {
                    msg: &segment,
                    aad: ENVELOPE_AAD,
                })
                .map_err(|_| "envelope decryption failed (wrong key or corrupt segment)")?;
            self.emit(&plaintext)?;
        }
        Ok(())
    }

    fn finish(self) -> Result<(u64, [u8; 32]), String> {
        let Self {
            stream,
            buf,
            mut sink,
            mut hasher,
            plaintext_size,
            ..
        } = self;
        let plaintext = stream
            .decrypt_last(Payload {
                msg: &buf,
                aad: ENVELOPE_AAD,
            })
            .map_err(|_| {
                "envelope decryption failed on the final segment (corrupt or truncated stream)"
            })?;
        hasher.update(&plaintext);
        sink.write_all(&plaintext)
            .and_then(|()| sink.flush())
            .map_err(|e| format!("failed to write weights file: {e}"))?;
        Ok((
            plaintext_size + plaintext.len() as u64,
            hasher.finalize().into(),
        ))
    }

    fn emit(&mut self, plaintext: &[u8]) -> Result<(), String> {
        self.hasher.update(plaintext);
        self.plaintext_size += plaintext.len() as u64;
        self.sink
            .write_all(plaintext)
            .map_err(|e| format!("failed to write weights file: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Python ↔ Rust interop fixture (scripts/provision-weights.py) ----
    //
    // The Python provisioning script seals the test vectors; this suite must
    // open every case. Regenerate with provision-weights.py --write-fixture;
    // scripts/test_provision_weights.py asserts the file matches its code.

    fn fixture() -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/artifact-envelope.json");
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("missing {path:?} (run provision-weights.py --write-fixture): {e}")
        }))
        .unwrap()
    }

    struct Case {
        name: String,
        chunk_size: usize,
        dek: Vec<u8>,
        nonce_prefix: Vec<u8>,
        plaintext: Vec<u8>,
        plaintext_size: u64,
        plaintext_sha256: String,
        ciphertext: Vec<u8>,
    }

    fn cases() -> Vec<Case> {
        let doc = fixture();
        assert_eq!(doc["format"], ENVELOPE_FORMAT);
        assert_eq!(doc["cipher"], ENVELOPE_CIPHER);
        assert_eq!(
            B64.decode(doc["aad"].as_str().unwrap()).unwrap(),
            ENVELOPE_AAD
        );
        doc["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let b64 = |k: &str| B64.decode(c[k].as_str().unwrap()).unwrap();
                Case {
                    name: c["name"].as_str().unwrap().to_string(),
                    chunk_size: c["chunk_size"].as_u64().unwrap() as usize,
                    dek: b64("dek"),
                    nonce_prefix: b64("nonce_prefix"),
                    plaintext: b64("plaintext"),
                    plaintext_size: c["plaintext_size"].as_u64().unwrap(),
                    plaintext_sha256: c["plaintext_sha256"].as_str().unwrap().to_string(),
                    ciphertext: b64("ciphertext"),
                }
            })
            .collect()
    }

    fn decrypt(
        case: &Case,
        ciphertext: &[u8],
        feed: usize,
    ) -> Result<(Vec<u8>, u64, String), String> {
        let mut out = Vec::new();
        let mut decryptor =
            EnvelopeDecryptor::new(&case.dek, &case.nonce_prefix, case.chunk_size, &mut out)?;
        for slice in ciphertext.chunks(feed.max(1)) {
            decryptor.update(slice)?;
        }
        let (size, sha) = decryptor.finish()?;
        Ok((out, size, hex::encode(sha)))
    }

    #[test]
    fn python_sealed_fixture_cases_open_in_rust() {
        for case in cases() {
            // Feed sizes straddle the segment boundary to exercise buffering.
            for feed in [1, 7, case.chunk_size + TAG_SIZE, usize::MAX] {
                let feed = feed.min(case.ciphertext.len().max(1));
                let (plaintext, size, sha) = decrypt(&case, &case.ciphertext, feed)
                    .unwrap_or_else(|e| panic!("case {:?} (feed {feed}): {e}", case.name));
                assert_eq!(plaintext, case.plaintext, "case {:?}", case.name);
                assert_eq!(size, case.plaintext_size, "case {:?}", case.name);
                assert_eq!(sha, case.plaintext_sha256, "case {:?}", case.name);
            }
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let case = &cases()[0];
        let mut tampered = case.ciphertext.clone();
        tampered[10] ^= 1;
        assert!(decrypt(case, &tampered, usize::MAX).is_err());
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        // Dropping the final segment must fail: the new last segment was
        // sealed without the last-flag in its nonce.
        let case = cases()
            .into_iter()
            .find(|c| c.ciphertext.len() > 2 * (c.chunk_size + TAG_SIZE))
            .unwrap();
        let truncated = &case.ciphertext[..case.chunk_size + TAG_SIZE];
        assert!(decrypt(&case, truncated, usize::MAX).is_err());
    }

    #[test]
    fn reordered_segments_are_rejected() {
        let case = cases()
            .into_iter()
            .find(|c| c.ciphertext.len() > 2 * (c.chunk_size + TAG_SIZE))
            .unwrap();
        let segment = case.chunk_size + TAG_SIZE;
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&case.ciphertext[segment..2 * segment]);
        swapped.extend_from_slice(&case.ciphertext[..segment]);
        swapped.extend_from_slice(&case.ciphertext[2 * segment..]);
        assert!(decrypt(&case, &swapped, usize::MAX).is_err());
    }

    #[test]
    fn manifest_validation_rejects_wrong_format_and_cipher() {
        let valid = serde_json::json!({
            "format": ENVELOPE_FORMAT,
            "cipher": ENVELOPE_CIPHER,
            "chunk_size": 4194304,
            "nonce_prefix": "AAAAAAAAAA==",
            "wrapped_dek": "AAAA",
            "plaintext_size": 1,
            "plaintext_sha256": "00",
            "ciphertext_object": "weights/x.enc",
        });
        assert!(Manifest::parse(valid.to_string().as_bytes()).is_ok());

        for (key, value) in [
            ("format", serde_json::json!("something/else/v9")),
            ("cipher", serde_json::json!("aes-gcm")),
            ("chunk_size", serde_json::json!(0)),
            ("chunk_size", serde_json::json!(MAX_CHUNK_SIZE + 1)),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(
                Manifest::parse(bad.to_string().as_bytes()).is_err(),
                "{key} should have been rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_key_material() {
        assert!(EnvelopeDecryptor::new(&[0; 16], &[0; 7], 32, Vec::new()).is_err());
        assert!(EnvelopeDecryptor::new(&[0; 32], &[0; 12], 32, Vec::new()).is_err());
    }
}
