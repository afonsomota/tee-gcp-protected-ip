//! Attestation-gated delivery of the model weights (issue #7).
//!
//! Release images ship without weights (spike 002). At boot, if the operator
//! configured a weights manifest, the launcher: fetches the manifest from
//! GCS, unwraps its data-encryption key with Cloud KMS *as the attested
//! workload-identity principal* (the only principal granted decrypt — see
//! infra/), streams the ciphertext from GCS through the envelope decryptor
//! into the tmpfs at `/models` (plaintext weights only ever exist in
//! SEV-SNP/TDX-encrypted guest memory), verifies size and SHA-256, and hands the
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

/// Where the decrypted chat model lands: the Confidential Space `tee-mount`
/// tmpfs. The embeddings model (issue #11) lands beside it.
const DEFAULT_DEST: &str = "/models/model.gguf";
const DEFAULT_EMBED_DEST: &str = "/models/embed.gguf";

/// Delivery retry budget. KMS IAM propagation can run several minutes past
/// infra's 120s `time_sleep` — especially after a digest rotation, where the
/// per-digest decrypt grant is replaced while the VM merely restarts — so
/// the budget must comfortably cover that, not just transient network blips.
const FETCH_ATTEMPTS: u32 = 10;
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);

/// Config-resolution retry budget. Resolution blocks server startup (the
/// caller needs to know whether an inference upstream exists), so this stays
/// short; each probe is bounded by gcp.rs's per-request timeout.
const RESOLVE_ATTEMPTS: u32 = 3;
const RESOLVE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// The env-var and instance-metadata names for one artifact's delivery
/// config. The weights (issue #7) and the wasm harness (issue #8) ride the
/// *same* envelope pipeline, differing only in these names — so one resolver
/// serves both. See `WEIGHTS` and `HARNESS`.
struct ArtifactNames {
    /// `WEIGHTS` / `HARNESS`: env-var prefix for the dev/test override.
    env_prefix: &'static str,
    /// `weights` / `harness`: instance-attribute prefix and log label.
    attr_prefix: &'static str,
}

impl ArtifactNames {
    fn env(&self, suffix: &str) -> String {
        format!("{}_{suffix}", self.env_prefix)
    }
    fn attr(&self, suffix: &str) -> String {
        format!("{}-{suffix}", self.attr_prefix)
    }
}

const WEIGHTS: ArtifactNames = ArtifactNames {
    env_prefix: "WEIGHTS",
    attr_prefix: "weights",
};
const HARNESS: ArtifactNames = ArtifactNames {
    env_prefix: "HARNESS",
    attr_prefix: "harness",
};
/// The embeddings model (issue #11) rides the same envelope pipeline as the
/// chat weights, under its own names so the two are configured independently.
const EMBED_WEIGHTS: ArtifactNames = ArtifactNames {
    env_prefix: "EMBED_WEIGHTS",
    attr_prefix: "embed-weights",
};

struct Config {
    bucket: String,
    object: String,
    kms_key: String,
    /// `None` only in dev/test setups; production always authenticates KMS
    /// via the attested federated token.
    wip_audience: Option<String>,
}

impl Config {
    /// Resolve an artifact's delivery configuration: `<PREFIX>_*` env vars
    /// first (dev/test override; not operator-settable in production, see
    /// module docs), then GCE instance metadata attributes `<prefix>-*`.
    /// `Ok(None)` = delivery not configured; partial configuration and
    /// metadata-server failures are errors, never a silent fallback — a
    /// deployment that configured delivery must not quietly boot without it.
    async fn resolve(dev: bool, names: &ArtifactNames) -> Result<Option<Config>, String> {
        let env = |name: String| std::env::var(&name).ok().filter(|v| !v.is_empty());
        if let Some(object) = env(names.env("OBJECT")) {
            let require = |suffix: &str| {
                let name = names.env(suffix);
                env(name.clone())
                    .ok_or_else(|| format!("{} is set but {name} is not", names.env("OBJECT")))
            };
            return Ok(Some(Config {
                bucket: require("BUCKET")?,
                object,
                kms_key: require("KMS_KEY")?,
                // No audience = plain service-account KMS auth: acceptable
                // only here, in the env-driven dev/test path.
                wip_audience: env(names.env("WIP_AUDIENCE")),
            }));
        }
        if dev {
            // Dev machines have no metadata server; don't probe for one.
            return Ok(None);
        }
        let Some(object) = crate::gcp::instance_attribute(&names.attr("object")).await? else {
            return Ok(None);
        };
        let require = |suffix: &str| {
            let name = names.attr(suffix);
            let object_attr = names.attr("object");
            async move {
                crate::gcp::instance_attribute(&name).await?.ok_or_else(|| {
                    format!("{object_attr} is set but metadata attribute {name} is missing")
                })
            }
        };
        Ok(Some(Config {
            bucket: require("bucket").await?,
            object,
            kms_key: require("kms-key").await?,
            // Mandatory in production: KMS must authenticate via the
            // attested federated token. A missing audience must never
            // downgrade to the (non-attested) service-account token.
            wip_audience: Some(require("wip-audience").await?),
        }))
    }
}

/// If weights delivery is configured, spawn the fetch→decrypt→serve pipeline
/// and return the inference upstream `/chat` should (eventually) reach.
/// `None` = not configured; the caller falls back to `llama::init_from_env`.
pub async fn init(dev: bool) -> Option<String> {
    let config = resolve_with_retries(dev, &WEIGHTS).await?;
    println!(
        "weights: delivering gs://{}/{} (KMS {})",
        config.bucket, config.object, config.kms_key
    );
    let upstream = crate::llama::planned_upstream();
    tokio::spawn(async move {
        match deliver_with_retries(&WEIGHTS, || {
            deliver(&config, DEFAULT_DEST, "WEIGHTS_DEST", "weights")
        })
        .await
        {
            Some(path) => {
                crate::llama::start(path);
            }
            None => eprintln!("weights: giving up; /chat will keep failing"),
        }
    });
    Some(upstream)
}

/// If embeddings-model delivery is configured, spawn the fetch→decrypt→serve
/// pipeline for the second (EmbeddingGemma) instance and return the upstream
/// the launcher's `embed` tool should (eventually) reach. `None` = not
/// configured; the caller falls back to `llama::init_embeddings_from_env`, and
/// failing that, semantic search degrades to keyword search.
pub async fn init_embeddings(dev: bool) -> Option<String> {
    let config = resolve_with_retries(dev, &EMBED_WEIGHTS).await?;
    println!(
        "embed-weights: delivering gs://{}/{} (KMS {})",
        config.bucket, config.object, config.kms_key
    );
    let upstream = crate::llama::planned_embed_upstream();
    tokio::spawn(async move {
        match deliver_with_retries(&EMBED_WEIGHTS, || {
            deliver(
                &config,
                DEFAULT_EMBED_DEST,
                "EMBED_WEIGHTS_DEST",
                "embed-weights",
            )
        })
        .await
        {
            Some(path) => {
                crate::llama::start_embeddings(path);
            }
            None => {
                eprintln!("embed-weights: giving up; semantic search will fall back to keywords")
            }
        }
    });
    Some(upstream)
}

/// Run `deliver` up to `FETCH_ATTEMPTS` times with `RETRY_DELAY` backoff,
/// returning the first success. Both artifacts share it so the harness gets the
/// same KMS-IAM-propagation budget as the weights (see `FETCH_ATTEMPTS`) rather
/// than the single shot it had before; the caller decides what to do with the
/// delivered value (start llama vs. compile + verify the module) and how to
/// report exhaustion. `None` = every attempt failed (each logged here); the VM
/// stays up and `/chat` keeps serving errors until — for a transient cause — a
/// later boot or retry lands.
async fn deliver_with_retries<T, Fut>(names: &ArtifactNames, deliver: impl Fn() -> Fut) -> Option<T>
where
    Fut: std::future::Future<Output = Result<T, String>>,
{
    for attempt in 1..=FETCH_ATTEMPTS {
        match deliver().await {
            Ok(value) => return Some(value),
            // Boot races IAM propagation (see FETCH_ATTEMPTS); a later attempt
            // lands once the grant propagates.
            Err(e) => eprintln!(
                "{}: attempt {attempt}/{FETCH_ATTEMPTS} failed: {e}",
                names.attr_prefix
            ),
        }
        if attempt < FETCH_ATTEMPTS {
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }
    None
}

async fn resolve_with_retries(dev: bool, names: &ArtifactNames) -> Option<Config> {
    for attempt in 1..=RESOLVE_ATTEMPTS {
        match Config::resolve(dev, names).await {
            Ok(config) => return config,
            Err(e) => eprintln!(
                "{}: config resolution {attempt}/{RESOLVE_ATTEMPTS} failed: {e}",
                names.attr_prefix
            ),
        }
        if attempt < RESOLVE_ATTEMPTS {
            tokio::time::sleep(RESOLVE_RETRY_DELAY).await;
        }
    }
    eprintln!(
        "{0}: cannot resolve configuration; {0} delivery disabled for this boot",
        names.attr_prefix
    );
    None
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
    /// Base64 detached Ed25519 signature over the decrypted plaintext. Present
    /// for the harness (issue #8), where the launcher verifies it against the
    /// pinned company key; absent for weights, where integrity rests on the
    /// SHA-256 above. `serde(default)` so weights manifests parse unchanged.
    #[serde(default)]
    signature: Option<String>,
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

    /// Decode the detached company signature; error if a manifest that must be
    /// signed (the harness) lacks it. Keeping the "required + base64-decode"
    /// invariant on the type means a new signed-artifact path can't forget it.
    fn required_signature(&self) -> Result<Vec<u8>, String> {
        let b64 = self
            .signature
            .as_deref()
            .ok_or("harness manifest is missing the required `signature` field")?;
        B64.decode(b64)
            .map_err(|e| format!("harness manifest signature is not base64: {e}"))
    }
}

/// Fail if the streamed plaintext doesn't match the manifest's size + SHA-256.
/// Both artifacts run the identical check after decryption; `label`
/// ("weights"/"harness") only flavors the error.
fn verify_against_manifest(
    manifest: &Manifest,
    size: u64,
    sha256: [u8; 32],
    label: &str,
) -> Result<(), String> {
    if size != manifest.plaintext_size || hex::encode(sha256) != manifest.plaintext_sha256 {
        return Err(format!(
            "decrypted {label} does not match the manifest: got {size} bytes / sha256 {}, \
             expected {} bytes / sha256 {}",
            hex::encode(sha256),
            manifest.plaintext_size,
            manifest.plaintext_sha256
        ));
    }
    Ok(())
}

/// Fetch + parse the manifest and unwrap its DEK as the attested principal —
/// the attestation-gated step shared by both artifacts. Returns the GCS token
/// (reused for the ciphertext download), the manifest, the unwrapped DEK, and
/// the decoded nonce prefix.
async fn fetch_manifest_and_key(
    config: &Config,
) -> Result<(String, Manifest, Vec<u8>, Vec<u8>), String> {
    let gcs_token = crate::gcp::metadata_access_token().await?;
    let manifest =
        Manifest::parse(&crate::gcp::gcs_get(&gcs_token, &config.bucket, &config.object).await?)?;

    let wrapped_dek = B64
        .decode(&manifest.wrapped_dek)
        .map_err(|e| format!("manifest wrapped_dek is not base64: {e}"))?;
    // Only an attested workload running the expected image digest can make
    // this KMS call succeed.
    let dek = crate::gcp::kms_decrypt(
        &config.kms_key,
        config.wip_audience.as_deref(),
        &wrapped_dek,
    )
    .await?;
    let nonce_prefix = B64
        .decode(&manifest.nonce_prefix)
        .map_err(|e| format!("manifest nonce_prefix is not base64: {e}"))?;
    Ok((gcs_token, manifest, dek, nonce_prefix))
}

/// Deliver the signed wasm harness (issue #8) over the same KMS-gated envelope
/// pipeline as the weights, with the same resolve + fetch retry budget so a
/// cold-boot race with KMS-IAM propagation no longer leaves `/chat` permanently
/// at 503. The artifact is small, so it is decrypted fully into guest memory (a
/// `Vec`) — never to disk. Returns `(wasm, signature)`; the caller
/// (`harness.rs`) verifies the detached Ed25519 signature against the pinned
/// company key before instantiating. `None` = not configured, or every
/// delivery attempt failed (each logged).
pub async fn deliver_harness(dev: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let config = resolve_with_retries(dev, &HARNESS).await?;
    println!(
        "harness: delivering gs://{}/{} (KMS {})",
        config.bucket, config.object, config.kms_key
    );
    deliver_with_retries(&HARNESS, || fetch_harness(&config)).await
}

/// One harness delivery attempt: fetch the manifest, unwrap its DEK as the
/// attested principal, decrypt the wasm into memory, and check size + SHA-256.
/// Retried by `deliver_with_retries` — only delivery/resolution transients are
/// retried here; the *signature* check stays fatal-by-design in `Harness::new`,
/// outside the retry loop, so a verified-bad module is never retried into
/// oblivion.
async fn fetch_harness(config: &Config) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (gcs_token, manifest, dek, nonce_prefix) = fetch_manifest_and_key(config).await?;

    // The harness manifest must carry the signature; weights manifests do not.
    let signature = manifest.required_signature()?;

    let mut wasm = Vec::new();
    let (size, sha256) = stream_into(
        &gcs_token,
        config,
        &manifest,
        &dek,
        &nonce_prefix,
        &mut wasm,
    )
    .await?;
    verify_against_manifest(&manifest, size, sha256, "harness")?;
    println!("harness: decrypted {size} bytes (sha256 verified; signature checked on load)");
    Ok((wasm, signature))
}

/// Fetch the manifest, unwrap the DEK as the attested principal, stream the
/// ciphertext through the decryptor onto tmpfs, verify, and return the path.
/// `default_dest`/`dest_env`/`label` flavor it per model (chat weights vs. the
/// embeddings model) — both ride the identical envelope + verification path.
async fn deliver(
    config: &Config,
    default_dest: &str,
    dest_env: &str,
    label: &str,
) -> Result<String, String> {
    let (gcs_token, manifest, dek, nonce_prefix) = fetch_manifest_and_key(config).await?;

    let dest = std::env::var(dest_env).unwrap_or_else(|_| default_dest.to_string());
    // Any failure must remove the partial plaintext: the tmpfs is guest RAM,
    // and a stranded multi-GB file would stay pinned for the VM's lifetime.
    let result = stream_decrypt_to(&gcs_token, config, &manifest, &dek, &nonce_prefix, &dest).await;
    let (size, sha256) = match result {
        Ok(written) => written,
        Err(e) => {
            std::fs::remove_file(&dest).ok();
            return Err(e);
        }
    };

    if let Err(e) = verify_against_manifest(&manifest, size, sha256, label) {
        std::fs::remove_file(&dest).ok();
        return Err(e);
    }
    println!("{label}: decrypted {size} bytes to {dest} (sha256 verified)");
    Ok(dest)
}

/// Stream the ciphertext object through the envelope decryptor into `dest`;
/// returns the plaintext size and SHA-256 for the manifest check.
async fn stream_decrypt_to(
    gcs_token: &str,
    config: &Config,
    manifest: &Manifest,
    dek: &[u8],
    nonce_prefix: &[u8],
    dest: &str,
) -> Result<(u64, [u8; 32]), String> {
    let file = std::fs::File::create(dest)
        .map_err(|e| format!("cannot create {dest} (is the tmpfs mounted?): {e}"))?;
    stream_into(
        gcs_token,
        config,
        manifest,
        dek,
        nonce_prefix,
        std::io::BufWriter::new(file),
    )
    .await
}

/// Stream `manifest.ciphertext_object` through the envelope decryptor into an
/// arbitrary sink (a tmpfs file for weights, an in-memory `Vec` for the
/// harness); returns the plaintext size and SHA-256 for the manifest check.
async fn stream_into<W: Write>(
    gcs_token: &str,
    config: &Config,
    manifest: &Manifest,
    dek: &[u8],
    nonce_prefix: &[u8],
    sink: W,
) -> Result<(u64, [u8; 32]), String> {
    let mut decryptor = EnvelopeDecryptor::new(dek, nonce_prefix, manifest.chunk_size, sink)?;
    let mut body =
        crate::gcp::gcs_get_stream(gcs_token, &config.bucket, &manifest.ciphertext_object).await?;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| format!("ciphertext download failed: {e}"))?;
        if let Some(data) = frame.data_ref() {
            decryptor.update(data)?;
        }
    }
    decryptor.finish()
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
            // drain (not split_off) keeps the buffer's capacity across the
            // ~thousand segments of a multi-GB stream.
            let segment: Vec<u8> = self.buf.drain(..self.segment_size).collect();
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
            .map_err(|e| format!("failed to write decrypted artifact: {e}"))?;
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
            .map_err(|e| format!("failed to write decrypted artifact: {e}"))
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

    // ---- delivery retry scaffold (issue #8 fix) -------------------------
    //
    // The clock is paused (`start_paused`), so the RETRY_DELAY backoff between
    // attempts advances instantly — these stay hermetic (no network, no real
    // sleep). They guard the harness's new "retry like the weights" behaviour.

    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test(start_paused = true)]
    async fn deliver_with_retries_recovers_after_transient_failures() {
        let calls = AtomicU32::new(0);
        // Fail the first two attempts (a stand-in for KMS-IAM propagation lag),
        // succeed on the third — mirroring a cold-boot race that later clears.
        let out = deliver_with_retries(&HARNESS, || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(format!("transient {n}"))
                } else {
                    Ok::<u32, String>(42)
                }
            }
        })
        .await;
        assert_eq!(out, Some(42));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn deliver_with_retries_gives_up_after_the_budget() {
        let calls = AtomicU32::new(0);
        let out: Option<u32> = deliver_with_retries(&WEIGHTS, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<u32, String>("always failing".into()) }
        })
        .await;
        assert_eq!(out, None);
        // Exactly the budget — no more, no fewer.
        assert_eq!(calls.load(Ordering::SeqCst), FETCH_ATTEMPTS);
    }

    #[test]
    fn manifest_signature_is_optional_and_round_trips() {
        let base = serde_json::json!({
            "format": ENVELOPE_FORMAT,
            "cipher": ENVELOPE_CIPHER,
            "chunk_size": 4194304,
            "nonce_prefix": "AAAAAAAAAA==",
            "wrapped_dek": "AAAA",
            "plaintext_size": 1,
            "plaintext_sha256": "00",
            "ciphertext_object": "harness/harness.wasm.enc",
        });
        // Weights manifests carry no signature → None (the harness path then
        // refuses delivery; weights never reach that check).
        assert!(Manifest::parse(base.to_string().as_bytes())
            .unwrap()
            .signature
            .is_none());

        // Harness manifests carry the base64 company signature.
        let mut signed = base.clone();
        signed["signature"] = serde_json::json!("c2lnbmF0dXJl");
        assert_eq!(
            Manifest::parse(signed.to_string().as_bytes())
                .unwrap()
                .signature
                .as_deref(),
            Some("c2lnbmF0dXJl")
        );
    }
}
