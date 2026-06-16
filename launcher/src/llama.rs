//! llama-server subprocess supervision.
//!
//! The launcher owns the inference engine as a child process: llama.cpp's
//! `llama-server`, loaded with the chat model, bound to `127.0.0.1` so it is
//! reachable only from inside the container. If the process dies it is
//! restarted with exponential backoff. The launcher never parses model
//! output itself — `/chat` (see `chat.rs`) proxies one OpenAI-style
//! completion request per user message.
//!
//! Configuration is environment variables, resolved once at boot:
//!
//! - `LLAMA_MODEL_PATH` — GGUF model file; presence enables supervision.
//! - `LLAMA_SERVER_BIN` — binary path (default `/app/llama-server`, where
//!   the official llama.cpp server image installs it).
//! - `LLAMA_PORT` — loopback port (default 8081).
//! - `LLAMA_EXTRA_ARGS` — whitespace-split extra args (context size, threads).
//! - `LLAMA_UPSTREAM` — dev mode only (`--dev` / `LAUNCHER_DEV=1`): skip
//!   supervision entirely and use an already-running llama-server at this
//!   `host:port`.
//!
//! None of the `LLAMA_*` variables may ever be listed in the image's
//! `tee.launch_policy.allow_env_override` label: an operator who could set
//! them — `LLAMA_UPSTREAM` especially — could point decrypted user messages
//! at an arbitrary address. Confidential Space rejects operator-supplied env
//! vars unless that label allows them, so production is safe by default;
//! the dev-mode gate below makes the bypass impossible even if the label
//! were ever added.

use std::time::Duration;

use tokio::process::Command;
use tokio::time::Instant;

/// Defaults match the official `ghcr.io/ggml-org/llama.cpp:server` image.
const DEFAULT_BIN: &str = "/app/llama-server";
const DEFAULT_PORT: u16 = 8081;

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
}

/// The loopback port llama-server will be told to bind, resolved from the
/// environment the same way `LlamaConfig::from_env` does.
fn port_from_env() -> u16 {
    std::env::var("LLAMA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// The `host:port` a supervised llama-server will serve on, before any model
/// exists. Lets artifact delivery (artifacts.rs) hand `/chat` its upstream
/// at boot while the model is still being fetched and decrypted.
pub fn planned_upstream() -> String {
    format!("127.0.0.1:{}", port_from_env())
}

impl LlamaConfig {
    fn from_env(model: String) -> Self {
        Self {
            bin: std::env::var("LLAMA_SERVER_BIN").unwrap_or_else(|_| DEFAULT_BIN.to_string()),
            model,
            port: port_from_env(),
            extra_args: std::env::var("LLAMA_EXTRA_ARGS")
                .map(|a| a.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
            initial_backoff: INITIAL_BACKOFF,
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
}

/// Resolve inference configuration from the environment. Returns the
/// `host:port` of the llama-server the `/chat` endpoint should call, or
/// `None` when inference is not configured (the endpoint then serves 503).
pub fn init_from_env(dev: bool) -> Option<String> {
    // Empty counts as unset: the Dockerfile sets LLAMA_MODEL_PATH="" when no
    // weights are baked into the image.
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    if let Some(model) = env("LLAMA_MODEL_PATH") {
        Some(start(model))
    } else if let Some(upstream) = env("LLAMA_UPSTREAM") {
        // An external upstream receives decrypted user messages, so the
        // audited TCB must never honor it in production (see module docs).
        if !dev {
            eprintln!("inference: LLAMA_UPSTREAM ignored outside dev mode; /chat will serve 503");
            return None;
        }
        println!("inference: using external llama-server at {upstream} (unsupervised, dev only)");
        Some(upstream)
    } else {
        println!("inference: not configured (set LLAMA_MODEL_PATH or LLAMA_UPSTREAM); /chat will serve 503");
        None
    }
}

/// Supervise a llama-server on the given model file and return the
/// `host:port` it will serve on. Called at boot when weights are baked into
/// the image, or after artifact delivery has decrypted them onto tmpfs.
pub fn start(model: String) -> String {
    let config = LlamaConfig::from_env(model);
    let upstream = config.upstream();
    supervise(config);
    upstream
}

/// Spawn the supervision loop and a one-shot readiness probe that logs the
/// boot-to-ready time (model load dominates; the number feeds the ops docs).
fn supervise(config: LlamaConfig) {
    let boot = Instant::now();
    let upstream = config.upstream();
    tokio::spawn(async move {
        match wait_until_healthy(&upstream, Duration::from_secs(600)).await {
            Ok(()) => println!(
                "inference: llama-server ready in {:.1}s (boot to /health ok)",
                boot.elapsed().as_secs_f64()
            ),
            Err(e) => eprintln!("inference: llama-server never became healthy: {e}"),
        }
    });
    tokio::spawn(supervision_loop(config));
}

async fn supervision_loop(config: LlamaConfig) {
    let mut backoff = config.initial_backoff;
    loop {
        println!(
            "inference: starting {} {}",
            config.bin,
            config.args().join(" ")
        );
        let started = Instant::now();
        match Command::new(&config.bin).args(config.args()).spawn() {
            Ok(mut child) => {
                let status = child.wait().await;
                eprintln!(
                    "inference: llama-server exited ({}) after {:.1}s",
                    status.map_or_else(|e| e.to_string(), |s| s.to_string()),
                    started.elapsed().as_secs_f64()
                );
                if started.elapsed() >= STABLE_RUN {
                    backoff = config.initial_backoff;
                }
            }
            Err(e) => eprintln!("inference: failed to spawn {}: {e}", config.bin),
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
        };
        let args = config.args();
        let host_at = args.iter().position(|a| a == "--host").unwrap();
        assert_eq!(args[host_at + 1], "127.0.0.1");
        assert!(args.contains(&"--no-webui".to_string()));
        assert!(args.ends_with(&["--ctx-size".to_string(), "4096".to_string()]));
        assert_eq!(config.upstream(), "127.0.0.1:8081");
    }
}
