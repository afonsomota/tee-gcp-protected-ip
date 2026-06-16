//! llama-server subprocess supervision.
//!
//! The launcher owns inference engines as child processes: llama.cpp's
//! `llama-server`, each loaded with a model and bound to `127.0.0.1` so it is
//! reachable only from inside the container. If a process dies it is
//! restarted with exponential backoff. The launcher never parses model
//! output itself — `/chat` (see `chat.rs`) proxies OpenAI-style
//! completion requests per user message, and enclave tools call the models directly.
//!
//! Configuration is environment variables, resolved once at boot:
//!
//! - `LLAMA_MODEL_PATH` — chat GGUF model file; presence enables supervision.
//! - `LLAMA_EMBEDDING_MODEL_PATH` — embedding GGUF model (optional); enables
//!   a second instance for fast embedding inference (issue #11).
//! - `LLAMA_SERVER_BIN` — binary path (default `/app/llama-server`).
//! - `LLAMA_PORT` — chat model loopback port (default 8081).
//! - `LLAMA_EMBEDDING_PORT` — embedding model loopback port (default 8082).
//! - `LLAMA_EXTRA_ARGS` — whitespace-split extra args for chat model.
//! - `LLAMA_EMBEDDING_EXTRA_ARGS` — extra args for embedding model.
//! - `LLAMA_UPSTREAM` — dev mode only: skip supervision, use external server.
//! - `LLAMA_EMBEDDING_UPSTREAM` — dev mode only: skip supervision, use external embedding server.
//!
//! None of the `LLAMA_*` variables may ever be listed in the image's
//! `tee.launch_policy.allow_env_override` label: an operator who could set
//! them could point decrypted user messages at an arbitrary address.
//! Confidential Space rejects operator-supplied env vars unless that label
//! allows them, so production is safe by default; the dev-mode gate below
//! makes the bypass impossible even if the label were ever added.

use std::time::Duration;

use tokio::process::Command;
use tokio::time::Instant;

/// Defaults match the official `ghcr.io/ggml-org/llama.cpp:server` image.
const DEFAULT_BIN: &str = "/app/llama-server";
const DEFAULT_CHAT_PORT: u16 = 8081;
const DEFAULT_EMBEDDING_PORT: u16 = 8082;

/// Backoff for restarting a dying llama-server: start here, double while the
/// process keeps dying quickly, cap, and reset once a run survives
/// `STABLE_RUN` (a crash after a long healthy run restarts promptly).
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const STABLE_RUN: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct LlamaConfig {
    pub bin: String,
    pub model: String,
    pub port: u16,
    pub extra_args: Vec<String>,
    /// Initial restart backoff; only tests shrink this.
    pub initial_backoff: Duration,
    /// Model type for logging; "chat" or "embedding".
    model_type: &'static str,
}

/// The loopback port the chat llama-server will bind to.
fn chat_port_from_env() -> u16 {
    std::env::var("LLAMA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_CHAT_PORT)
}

/// The loopback port the embedding llama-server will bind to.
fn embedding_port_from_env() -> u16 {
    std::env::var("LLAMA_EMBEDDING_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_EMBEDDING_PORT)
}

/// The `host:port` a supervised chat llama-server will serve on, before any model
/// exists. Lets artifact delivery (artifacts.rs) hand `/chat` its upstream
/// at boot while the model is still being fetched and decrypted.
pub fn planned_chat_upstream() -> String {
    format!("127.0.0.1:{}", chat_port_from_env())
}

#[allow(dead_code)]
/// The `host:port` a supervised embedding llama-server will serve on.
/// Placeholder for future artifact-delivery support (issue #11).
pub fn planned_embedding_upstream() -> String {
    format!("127.0.0.1:{}", embedding_port_from_env())
}

impl LlamaConfig {
    fn chat_from_env(model: String) -> Self {
        Self {
            bin: std::env::var("LLAMA_SERVER_BIN").unwrap_or_else(|_| DEFAULT_BIN.to_string()),
            model,
            port: chat_port_from_env(),
            extra_args: std::env::var("LLAMA_EXTRA_ARGS")
                .map(|a| a.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
            initial_backoff: INITIAL_BACKOFF,
            model_type: "chat",
        }
    }

    fn embedding_from_env(model: String) -> Self {
        Self {
            bin: std::env::var("LLAMA_SERVER_BIN").unwrap_or_else(|_| DEFAULT_BIN.to_string()),
            model,
            port: embedding_port_from_env(),
            extra_args: std::env::var("LLAMA_EMBEDDING_EXTRA_ARGS")
                .map(|a| a.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
            initial_backoff: INITIAL_BACKOFF,
            model_type: "embedding",
        }
    }

    fn args(&self) -> Vec<String> {
        let mut args = vec![
            "-m".to_string(),
            self.model.clone(),
            // Loopback only: the model must not be reachable from outside
            // the container. The HPKE channel is the only way in.
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            self.port.to_string(),
            "--no-webui".to_string(),
        ];
        args.extend(self.extra_args.iter().cloned());
        args
    }

    fn upstream(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn log_prefix(&self) -> String {
        format!("inference/{}", self.model_type)
    }
}

/// Resolved inference configuration: chat model and optional embedding model.
pub struct InferenceConfig {
    pub chat: String,
    pub embedding: Option<String>,
}

/// Resolve inference configuration from the environment. Returns both the chat
/// and embedding model upstreams, or `None` for chat when not configured.
pub fn init_from_env(dev: bool) -> Option<InferenceConfig> {
    // Empty counts as unset: the Dockerfile sets LLAMA_MODEL_PATH="" when no
    // weights are baked into the image.
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());

    let chat = if let Some(model) = env("LLAMA_MODEL_PATH") {
        Some(start_chat(model))
    } else if let Some(upstream) = env("LLAMA_UPSTREAM") {
        // An external upstream receives decrypted user messages, so the
        // audited TCB must never honor it in production (see module docs).
        if !dev {
            eprintln!("inference/chat: LLAMA_UPSTREAM ignored outside dev mode; /chat will serve 503");
            return None;
        }
        println!("inference/chat: using external llama-server at {upstream} (unsupervised, dev only)");
        Some(upstream)
    } else {
        println!("inference/chat: not configured (set LLAMA_MODEL_PATH or LLAMA_UPSTREAM); /chat will serve 503");
        None
    }?;

    let embedding = if let Some(model) = env("LLAMA_EMBEDDING_MODEL_PATH") {
        Some(start_embedding(model))
    } else if let Some(upstream) = env("LLAMA_EMBEDDING_UPSTREAM") {
        if !dev {
            eprintln!("inference/embedding: LLAMA_EMBEDDING_UPSTREAM ignored outside dev mode");
            None
        } else {
            println!("inference/embedding: using external llama-server at {upstream} (unsupervised, dev only)");
            Some(upstream)
        }
    } else {
        None
    };

    Some(InferenceConfig { chat, embedding })
}

/// Supervise a chat llama-server on the given model file and return the
/// `host:port` it will serve on. Called at boot when weights are baked into
/// the image, or after artifact delivery has decrypted them onto tmpfs.
pub fn start_chat(model: String) -> String {
    let config = LlamaConfig::chat_from_env(model);
    let upstream = config.upstream();
    supervise(config);
    upstream
}

/// Supervise an embedding llama-server on the given model file and return the
/// `host:port` it will serve on.
pub fn start_embedding(model: String) -> String {
    let config = LlamaConfig::embedding_from_env(model);
    let upstream = config.upstream();
    supervise(config);
    upstream
}

/// Spawn the supervision loop and a one-shot readiness probe that logs the
/// boot-to-ready time (model load dominates; the number feeds the ops docs).
fn supervise(config: LlamaConfig) {
    let boot = Instant::now();
    let upstream = config.upstream();
    let log_prefix = config.log_prefix();
    tokio::spawn(async move {
        match wait_until_healthy(&upstream, Duration::from_secs(600)).await {
            Ok(()) => println!(
                "{}: ready in {:.1}s (boot to /health ok)",
                log_prefix,
                boot.elapsed().as_secs_f64()
            ),
            Err(e) => eprintln!("{}: never became healthy: {e}", log_prefix),
        }
    });
    tokio::spawn(supervision_loop(config));
}

async fn supervision_loop(config: LlamaConfig) {
    let mut backoff = config.initial_backoff;
    let log_prefix = config.log_prefix();
    loop {
        println!(
            "{}: starting {} {}",
            log_prefix,
            config.bin,
            config.args().join(" ")
        );
        let started = Instant::now();
        match Command::new(&config.bin).args(config.args()).spawn() {
            Ok(mut child) => {
                let status = child.wait().await;
                eprintln!(
                    "{}: exited ({}) after {:.1}s",
                    log_prefix,
                    status.map_or_else(|e| e.to_string(), |s| s.to_string()),
                    started.elapsed().as_secs_f64()
                );
                if started.elapsed() >= STABLE_RUN {
                    backoff = config.initial_backoff;
                }
            }
            Err(e) => eprintln!("{}: failed to spawn {}: {e}", log_prefix, config.bin),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Poll `GET /health` until it returns 200 or the deadline passes.
pub async fn wait_until_healthy(upstream: &str, deadline: Duration) -> Result<(), String> {
    let end = Instant::now() + deadline;
    loop {
        if let Ok((status, _)) =
            crate::upstream::request(upstream, hyper::Method::GET, "/health", None).await
        {
            if status.is_success() {
                return Ok(());
            }
        }
        if Instant::now() >= end {
            return Err(format!("no healthy response within {deadline:?}"));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A dying child must be restarted: run a script that appends a line to
    /// a log file and exits non-zero, then watch the file grow.
    #[tokio::test]
    async fn supervision_restarts_a_dying_process() {
        let dir = std::env::temp_dir().join(format!("llama-supervise-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("runs.log");
        let script = dir.join("fake-llama-server.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho run >> {}\nexit 1\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let config = LlamaConfig {
            bin: script.to_str().unwrap().to_string(),
            model: "unused.gguf".to_string(),
            port: 0,
            extra_args: vec![],
            initial_backoff: Duration::from_millis(20),
            model_type: "chat",
        };
        let supervisor = tokio::spawn(supervision_loop(config));

        let mut runs = 0;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            runs = std::fs::read_to_string(&log)
                .map(|s| s.lines().count())
                .unwrap_or(0);
            if runs >= 3 {
                break;
            }
        }
        supervisor.abort();
        std::fs::remove_dir_all(&dir).ok();
        assert!(runs >= 3, "expected >=3 supervised runs, saw {runs}");
    }

    #[test]
    fn args_pin_the_server_to_loopback() {
        let config = LlamaConfig {
            bin: "llama-server".to_string(),
            model: "/models/gemma.gguf".to_string(),
            port: 8081,
            extra_args: vec!["--ctx-size".to_string(), "4096".to_string()],
            initial_backoff: INITIAL_BACKOFF,
            model_type: "chat",
        };
        let args = config.args();
        let host_at = args.iter().position(|a| a == "--host").unwrap();
        assert_eq!(args[host_at + 1], "127.0.0.1");
        assert!(args.contains(&"--no-webui".to_string()));
        assert!(args.ends_with(&["--ctx-size".to_string(), "4096".to_string()]));
        assert_eq!(config.upstream(), "127.0.0.1:8081");
    }
}
