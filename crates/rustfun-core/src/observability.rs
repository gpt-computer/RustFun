//! Metrics collection and Prometheus rendering.
//!
//! Metrics are collected in-process (no external dependency) and rendered in Prometheus text
//! exposition format for the dev server. Counters and histograms are fixed-shape and cheap:
//! the hot path must not allocate per observation beyond the bucket lookup.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Latency buckets in milliseconds.
const LATENCY_BUCKETS: [u64; 11] = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 5000];

#[derive(Debug, Default)]
struct Histogram {
    counts: [AtomicU64; LATENCY_BUCKETS.len()],
    overflow: AtomicU64,
    sum_ms: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn observe(&self, millis: u64) {
        for (index, bound) in LATENCY_BUCKETS.iter().enumerate() {
            if millis <= *bound {
                self.counts[index].fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
        if millis > LATENCY_BUCKETS[LATENCY_BUCKETS.len() - 1] {
            self.overflow.fetch_add(1, Ordering::Relaxed);
        }
        self.sum_ms.fetch_add(millis, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        let buckets: Vec<(u64, u64)> = LATENCY_BUCKETS
            .iter()
            .enumerate()
            .map(|(i, bound)| (*bound, self.counts[i].load(Ordering::Relaxed)))
            .collect();
        HistogramSnapshot {
            buckets,
            count: self.count.load(Ordering::Relaxed),
            sum_ms: self.sum_ms.load(Ordering::Relaxed),
        }
    }
}

/// A histogram snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistogramSnapshot {
    /// Cumulative bucket counts (`le` semantics).
    pub buckets: Vec<(u64, u64)>,
    /// Total observations.
    pub count: u64,
    /// Sum of observed values in milliseconds.
    pub sum_ms: u64,
}

impl HistogramSnapshot {
    /// Approximate quantile in milliseconds, using the highest non-empty bucket.
    pub fn approximate_quantile(&self, quantile: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = (self.count as f64 * quantile).ceil() as u64;
        let mut cumulative = 0;
        for (bound, count) in &self.buckets {
            cumulative += count;
            if cumulative >= target {
                return *bound;
            }
        }
        LATENCY_BUCKETS[LATENCY_BUCKETS.len() - 1]
    }
}

/// Runtime counters exposed by the metrics registry.
#[derive(Debug, Default)]
pub struct Metrics {
    invocations_total: AtomicU64,
    invocations_succeeded: AtomicU64,
    invocations_failed: AtomicU64,
    cold_starts: AtomicU64,
    warm_starts: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    builds_total: AtomicU64,
    instances_created: AtomicU64,
    instances_destroyed: AtomicU64,
    sandbox_violations: AtomicU64,
    invocation_latency: Histogram,
    cold_start_latency: Histogram,
    warm_start_latency: Histogram,
    queue_latency: Histogram,
    build_latency: Histogram,
    gauges: Mutex<BTreeMap<String, i64>>,
}

/// A point-in-time copy of every metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Total invocations.
    pub invocations_total: u64,
    /// Successful invocations.
    pub invocations_succeeded: u64,
    /// Failed invocations.
    pub invocations_failed: u64,
    /// Cold starts.
    pub cold_starts: u64,
    /// Warm starts.
    pub warm_starts: u64,
    /// Artifact cache hits.
    pub cache_hits: u64,
    /// Artifact cache misses.
    pub cache_misses: u64,
    /// Builds performed.
    pub builds_total: u64,
    /// Instances created.
    pub instances_created: u64,
    /// Instances destroyed.
    pub instances_destroyed: u64,
    /// Sandbox violations observed.
    pub sandbox_violations: u64,
    /// Invocation latency histogram.
    pub invocation_latency: HistogramSnapshot,
    /// Cold-start latency histogram.
    pub cold_start_latency: HistogramSnapshot,
    /// Warm-start latency histogram.
    pub warm_start_latency: HistogramSnapshot,
    /// Scheduler queue latency histogram.
    pub queue_latency: HistogramSnapshot,
    /// Build latency histogram.
    pub build_latency: HistogramSnapshot,
    /// Gauges such as live instance count.
    pub gauges: BTreeMap<String, i64>,
}

impl MetricsSnapshot {
    /// Fraction of invocations that succeeded (0.0 when none have run).
    pub fn success_rate(&self) -> f64 {
        if self.invocations_total == 0 {
            return 0.0;
        }
        self.invocations_succeeded as f64 / self.invocations_total as f64
    }

    /// Warm reuse rate: warm starts over total starts.
    pub fn warm_ratio(&self) -> f64 {
        let total = self.cold_starts + self.warm_starts;
        if total == 0 {
            return 0.0;
        }
        self.warm_starts as f64 / total as f64
    }

    /// Artifact cache hit rate.
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / total as f64
    }
}

impl Metrics {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed invocation.
    pub fn record_invocation(&self, duration_ms: u64, success: bool) {
        self.invocations_total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.invocations_succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.invocations_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.invocation_latency.observe(duration_ms);
    }

    /// Record an instance start.
    pub fn record_start(&self, duration_ms: u64, warm: bool) {
        if warm {
            self.warm_starts.fetch_add(1, Ordering::Relaxed);
            self.warm_start_latency.observe(duration_ms);
        } else {
            self.cold_starts.fetch_add(1, Ordering::Relaxed);
            self.cold_start_latency.observe(duration_ms);
        }
        self.instances_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an instance teardown.
    pub fn record_instance_destroyed(&self) {
        self.instances_destroyed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an artifact build.
    pub fn record_build(&self, duration_ms: u64) {
        self.builds_total.fetch_add(1, Ordering::Relaxed);
        self.build_latency.observe(duration_ms);
    }

    /// Record an artifact cache lookup.
    pub fn record_cache_lookup(&self, hit: bool) {
        if hit {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a sandbox violation.
    pub fn record_sandbox_violation(&self) {
        self.sandbox_violations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record scheduler queue time.
    pub fn record_queue_latency(&self, millis: u64) {
        self.queue_latency.observe(millis);
    }

    /// Set a gauge.
    pub fn set_gauge(&self, key: impl Into<String>, value: i64) {
        if let Ok(mut gauges) = self.gauges.lock() {
            gauges.insert(key.into(), value);
        }
    }

    /// Increment a gauge by one.
    pub fn increment_gauge(&self, key: &str) {
        if let Ok(mut gauges) = self.gauges.lock() {
            *gauges.entry(key.to_owned()).or_insert(0) += 1;
        }
    }

    /// Decrement a gauge by one.
    pub fn decrement_gauge(&self, key: &str) {
        if let Ok(mut gauges) = self.gauges.lock() {
            *gauges.entry(key.to_owned()).or_insert(0) -= 1;
        }
    }

    /// Read a gauge.
    pub fn gauge(&self, key: &str) -> Option<i64> {
        self.gauges.lock().ok().and_then(|g| g.get(key).copied())
    }

    /// Take a snapshot.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            invocations_total: self.invocations_total.load(Ordering::Relaxed),
            invocations_succeeded: self.invocations_succeeded.load(Ordering::Relaxed),
            invocations_failed: self.invocations_failed.load(Ordering::Relaxed),
            cold_starts: self.cold_starts.load(Ordering::Relaxed),
            warm_starts: self.warm_starts.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            builds_total: self.builds_total.load(Ordering::Relaxed),
            instances_created: self.instances_created.load(Ordering::Relaxed),
            instances_destroyed: self.instances_destroyed.load(Ordering::Relaxed),
            sandbox_violations: self.sandbox_violations.load(Ordering::Relaxed),
            invocation_latency: self.invocation_latency.snapshot(),
            cold_start_latency: self.cold_start_latency.snapshot(),
            warm_start_latency: self.warm_start_latency.snapshot(),
            queue_latency: self.queue_latency.snapshot(),
            build_latency: self.build_latency.snapshot(),
            gauges: self.gauges.lock().map(|g| g.clone()).unwrap_or_default(),
        }
    }

    /// Render the snapshot in Prometheus text exposition format.
    pub fn to_prometheus(&self) -> String {
        prometheus_render(&self.snapshot())
    }
}

fn counter(name: &str, help: &str, value: u64, out: &mut String) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    out.push_str(&format!("{name} {value}\n"));
}

fn histogram(name: &str, help: &str, snapshot: &HistogramSnapshot, out: &mut String) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} histogram\n"));
    for (bound, count) in &snapshot.buckets {
        out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {count}\n"));
    }
    out.push_str(&format!(
        "{name}_bucket{{le=\"+Inf\"}} {}\n",
        snapshot.count
    ));
    out.push_str(&format!("{name}_sum {}\n", snapshot.sum_ms));
    out.push_str(&format!("{name}_count {}\n", snapshot.count));
}

/// Render a snapshot in Prometheus text exposition format.
pub fn prometheus_render(snapshot: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(2048);
    counter(
        "rustfun_invocations_total",
        "Total function invocations.",
        snapshot.invocations_total,
        &mut out,
    );
    counter(
        "rustfun_invocations_succeeded_total",
        "Invocations that returned a payload.",
        snapshot.invocations_succeeded,
        &mut out,
    );
    counter(
        "rustfun_invocations_failed_total",
        "Invocations that returned an error.",
        snapshot.invocations_failed,
        &mut out,
    );
    counter(
        "rustfun_cold_starts_total",
        "Instances created for an invocation.",
        snapshot.cold_starts,
        &mut out,
    );
    counter(
        "rustfun_warm_starts_total",
        "Invocations served by a reused instance.",
        snapshot.warm_starts,
        &mut out,
    );
    counter(
        "rustfun_cache_hits_total",
        "Artifact cache hits.",
        snapshot.cache_hits,
        &mut out,
    );
    counter(
        "rustfun_cache_misses_total",
        "Artifact cache misses.",
        snapshot.cache_misses,
        &mut out,
    );
    counter(
        "rustfun_builds_total",
        "Artifact builds executed.",
        snapshot.builds_total,
        &mut out,
    );
    counter(
        "rustfun_instances_created_total",
        "Runtime instances created.",
        snapshot.instances_created,
        &mut out,
    );
    counter(
        "rustfun_instances_destroyed_total",
        "Runtime instances destroyed.",
        snapshot.instances_destroyed,
        &mut out,
    );
    counter(
        "rustfun_sandbox_violations_total",
        "Sandbox violations observed.",
        snapshot.sandbox_violations,
        &mut out,
    );
    histogram(
        "rustfun_invocation_duration_ms",
        "Invocation duration in milliseconds.",
        &snapshot.invocation_latency,
        &mut out,
    );
    histogram(
        "rustfun_cold_start_duration_ms",
        "Cold start duration in milliseconds.",
        &snapshot.cold_start_latency,
        &mut out,
    );
    histogram(
        "rustfun_warm_start_duration_ms",
        "Warm start (reuse) duration in milliseconds.",
        &snapshot.warm_start_latency,
        &mut out,
    );
    histogram(
        "rustfun_queue_duration_ms",
        "Scheduler queue time in milliseconds.",
        &snapshot.queue_latency,
        &mut out,
    );
    histogram(
        "rustfun_build_duration_ms",
        "Artifact build duration in milliseconds.",
        &snapshot.build_latency,
        &mut out,
    );
    for (key, value) in &snapshot.gauges {
        out.push_str(&format!("# TYPE {key} gauge\n{key} {value}\n"));
    }
    out
}

/// Configure a `tracing` subscriber from `RUST_LOG`, once.
///
/// Diagnostics always go to **stderr** so that stdout carries only command output. A CLI
/// printing machine-readable JSON must never have a warning interleaved with it.
pub fn init_tracing(default_level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("rustfun={default_level},warn")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_rates() {
        let metrics = Metrics::new();
        metrics.record_invocation(10, true);
        metrics.record_invocation(20, false);
        metrics.record_start(100, false);
        metrics.record_start(1, true);
        metrics.record_cache_lookup(true);
        metrics.record_cache_lookup(false);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.invocations_total, 2);
        assert_eq!(snapshot.invocations_succeeded, 1);
        assert_eq!(snapshot.invocations_failed, 1);
        assert!((snapshot.success_rate() - 0.5).abs() < f64::EPSILON);
        assert!((snapshot.warm_ratio() - 0.5).abs() < f64::EPSILON);
        assert!((snapshot.cache_hit_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn histograms_bucket_observations() {
        let metrics = Metrics::new();
        metrics.record_invocation(1, true);
        metrics.record_invocation(3, true);
        metrics.record_invocation(9000, true);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.invocation_latency.count, 3);
        assert_eq!(snapshot.invocation_latency.sum_ms, 9004);
        assert_eq!(snapshot.invocation_latency.buckets[0], (1, 1));
        assert_eq!(snapshot.invocation_latency.approximate_quantile(0.5), 5);
        assert_eq!(snapshot.invocation_latency.approximate_quantile(1.0), 5000);
    }

    #[test]
    fn gauges_track_live_instances() {
        let metrics = Metrics::new();
        metrics.increment_gauge("rustfun_instances_live");
        metrics.increment_gauge("rustfun_instances_live");
        assert_eq!(metrics.gauge("rustfun_instances_live"), Some(2));
        metrics.decrement_gauge("rustfun_instances_live");
        assert_eq!(metrics.gauge("rustfun_instances_live"), Some(1));
        assert_eq!(metrics.gauge("missing"), None);
    }

    #[test]
    fn prometheus_output_is_well_formed() {
        let metrics = Metrics::new();
        metrics.record_invocation(12, true);
        metrics.record_start(300, false);
        metrics.record_build(50);
        metrics.record_sandbox_violation();
        metrics.set_gauge("rustfun_instances_live", 3);
        let text = metrics.to_prometheus();
        assert!(text.contains("rustfun_invocations_total 1"));
        assert!(text.contains("# TYPE rustfun_invocation_duration_ms histogram"));
        assert!(text.contains("rustfun_invocation_duration_ms_count 1"));
        assert!(text.contains("rustfun_instances_live 3"));
        assert!(text.contains("rustfun_sandbox_violations_total 1"));
        for line in text.lines() {
            assert!(line.is_empty() || line.starts_with('#') || line.split(' ').count() >= 2);
        }
    }

    #[test]
    fn empty_snapshot_has_zero_rates() {
        let snapshot = Metrics::new().snapshot();
        assert_eq!(snapshot.success_rate(), 0.0);
        assert_eq!(snapshot.warm_ratio(), 0.0);
        assert_eq!(snapshot.cache_hit_rate(), 0.0);
        assert_eq!(snapshot.invocation_latency.approximate_quantile(0.5), 0);
    }
}
