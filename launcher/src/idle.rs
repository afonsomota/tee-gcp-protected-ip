//! Scale-from-zero idle timer (issue #45).
//!
//! Confidential Space has no serverless mode for SEV-SNP or TDX, so "scale to zero" is
//! a stopped VM woken on demand by a tiny always-on controller (a Cloud
//! Function; see `controller/`). This module is the launcher half: an idle
//! timer that, after `idle-timeout-minutes` with no inbound request, pokes the
//! controller's `/idle` endpoint. The controller — not the launcher — decides
//! whether to actually stop the instance, gated on the weekly Let's Encrypt
//! cert budget.
//!
//! The launcher stays deliberately dumb. It counts no certs and parses no CT
//! logs; it tracks only the time of the last handled request and, when that
//! goes stale, sends one outbound POST. Every failure is fail-safe: a
//! controller that is unreachable, slow, or erroring leaves the VM running. The
//! audited TCB gains a timer and one poke — it asks to be stopped, it is never
//! granted authority over its own lifecycle.
//!
//! # Configuration
//!
//! Like the TLS config (`tls.rs`), these arrive as GCE instance metadata
//! attributes in production (`controller-url`, `idle-timeout-minutes`), with
//! matching env vars (`IDLE_CONTROLLER_URL`, `IDLE_TIMEOUT_MINUTES`) as a
//! dev/test override only — the release image carries no
//! `allow_env_override`, so the operator cannot inject them in production. With
//! no controller URL configured the timer never runs: local dev and any
//! deployment without a controller simply stay up.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Shared "last activity" clock: unix seconds of the most recently handled
/// request. The request middleware bumps it; the idle loop reads it.
pub type Activity = Arc<AtomicI64>;

const DEFAULT_IDLE_TIMEOUT_MINUTES: u64 = 45;

/// Current unix time in whole seconds. A backward clock step only postpones a
/// shutdown (the elapsed window looks shorter), never forces one early, so
/// plain wall-clock time is fine for an idle timer.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A fresh activity clock, armed to "now" so a just-booted VM gets a full idle
/// window before the first check.
pub fn new_activity() -> Activity {
    Arc::new(AtomicI64::new(now_secs()))
}

/// Record that a request was just handled.
pub fn touch(activity: &Activity) {
    activity.store(now_secs(), Ordering::Relaxed);
}

#[derive(Debug, PartialEq)]
pub struct IdleConfig {
    /// Base URL of the controller (no trailing slash); `/idle` is appended.
    pub controller_url: String,
    pub timeout: Duration,
}

impl IdleConfig {
    /// Build from a lookup of resolved values. `None` when no controller URL is
    /// set (idle shutdown disabled). A present-but-garbage timeout falls back
    /// to the default rather than failing — a typo in a tfvar must never wedge
    /// the enclave offline; the worst case is the wrong idle window.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let url = get("IDLE_CONTROLLER_URL").filter(|v| !v.is_empty())?;
        let minutes = get("IDLE_TIMEOUT_MINUTES")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|m| *m > 0)
            .unwrap_or(DEFAULT_IDLE_TIMEOUT_MINUTES);
        Some(Self {
            controller_url: url.trim().trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(minutes * 60),
        })
    }

    /// Resolve idle configuration for production: env first (dev/test override,
    /// not operator-settable in production), otherwise GCE instance metadata
    /// (`controller-url`, `idle-timeout-minutes`). A metadata-server error is
    /// swallowed to `None` for that key — idle shutdown is best-effort, so a
    /// flaky metadata read leaves the VM up rather than crashing boot.
    pub async fn resolve() -> Option<Self> {
        use std::collections::HashMap;

        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let mut values: HashMap<&'static str, String> = HashMap::new();
        for (env_name, attribute) in [
            ("IDLE_CONTROLLER_URL", "controller-url"),
            ("IDLE_TIMEOUT_MINUTES", "idle-timeout-minutes"),
        ] {
            let value = match env(env_name) {
                Some(v) => Some(v),
                None => crate::gcp::instance_attribute(attribute)
                    .await
                    .unwrap_or(None),
            };
            if let Some(value) = value {
                values.insert(env_name, value);
            }
        }
        Self::from_lookup(|name| values.get(name).cloned())
    }
}

/// Whether the idle timeout has elapsed since the last handled request.
fn elapsed_idle(now: i64, last_activity: i64, timeout: Duration) -> bool {
    now.saturating_sub(last_activity) >= timeout.as_secs() as i64
}

/// Spawn the idle-timer loop. It wakes periodically; once the time since the
/// last handled request exceeds the timeout, it pokes the controller's `/idle`
/// and re-arms. The controller decides whether to stop the VM (budget-gated);
/// if it does, this process simply disappears with the instance, so any code
/// after the poke only runs in the "declined, stay warm" case.
pub fn spawn(config: IdleConfig, activity: Activity) {
    tokio::spawn(async move {
        let idle_url = format!("{}/idle", config.controller_url);
        // Check often enough to be responsive, but never busy-loop: at most
        // once a minute, and never longer than the timeout itself.
        let tick = config
            .timeout
            .min(Duration::from_secs(60))
            .max(Duration::from_secs(1));
        println!(
            "idle timer armed: timeout {}s, controller {}",
            config.timeout.as_secs(),
            config.controller_url
        );
        loop {
            tokio::time::sleep(tick).await;
            if !elapsed_idle(now_secs(), activity.load(Ordering::Relaxed), config.timeout) {
                continue;
            }
            match crate::gcp::post_json(&idle_url, b"{}".to_vec()).await {
                Ok(status) => println!("idle poke -> {idle_url}: {status}"),
                // Fail-safe: any error leaves the VM up; the next window retries.
                Err(e) => eprintln!("idle poke failed (staying up): {e}"),
            }
            // Re-arm: only reached when the controller declined to stop us
            // (within budget already spent). Wait a full window before asking
            // again instead of hammering it every tick.
            touch(&activity);
        }
    });
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

    #[test]
    fn no_controller_url_means_disabled() {
        assert_eq!(IdleConfig::from_lookup(lookup(&[])), None);
        // A timeout without a URL is still disabled — there is nowhere to poke.
        assert_eq!(
            IdleConfig::from_lookup(lookup(&[("IDLE_TIMEOUT_MINUTES", "10")])),
            None
        );
        // Empty URL counts as unset.
        assert_eq!(
            IdleConfig::from_lookup(lookup(&[("IDLE_CONTROLLER_URL", "")])),
            None
        );
    }

    #[test]
    fn url_is_trimmed_and_default_timeout_applies() {
        let config =
            IdleConfig::from_lookup(lookup(&[("IDLE_CONTROLLER_URL", "https://ctl.run.app/")]))
                .unwrap();
        assert_eq!(config.controller_url, "https://ctl.run.app");
        assert_eq!(
            config.timeout,
            Duration::from_secs(DEFAULT_IDLE_TIMEOUT_MINUTES * 60)
        );
    }

    #[test]
    fn explicit_timeout_is_honored_and_garbage_falls_back() {
        let with = |minutes: &str| {
            IdleConfig::from_lookup(lookup(&[
                ("IDLE_CONTROLLER_URL", "https://ctl"),
                ("IDLE_TIMEOUT_MINUTES", minutes),
            ]))
            .unwrap()
            .timeout
        };
        assert_eq!(with("10"), Duration::from_secs(600));
        // Non-numeric and zero both fall back to the default, never to a
        // zero-length window that would stop the VM the instant it boots.
        assert_eq!(
            with("nonsense"),
            Duration::from_secs(DEFAULT_IDLE_TIMEOUT_MINUTES * 60)
        );
        assert_eq!(
            with("0"),
            Duration::from_secs(DEFAULT_IDLE_TIMEOUT_MINUTES * 60)
        );
    }

    #[test]
    fn elapsed_idle_fires_only_past_the_window() {
        let timeout = Duration::from_secs(600);
        assert!(!elapsed_idle(1_000, 1_000, timeout)); // just active
        assert!(!elapsed_idle(1_599, 1_000, timeout)); // 599s < 600s
        assert!(elapsed_idle(1_600, 1_000, timeout)); // exactly at the window
        assert!(elapsed_idle(5_000, 1_000, timeout)); // well past

        // A clock that jumped backwards must not trigger an early stop.
        assert!(!elapsed_idle(900, 1_000, timeout));
    }
}
