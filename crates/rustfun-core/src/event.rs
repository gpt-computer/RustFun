//! The in-process event bus.
//!
//! Everything observable in RustFun flows through one bus: lifecycle events, captured logs,
//! and (indirectly) metric updates. Subscribers receive events asynchronously so a slow sink
//! cannot stall the execution path; a sink that overflows its queue drops events and records
//! the drop rather than applying backpressure to the kernel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustfun_events::{Event, EventContext};
use tokio::sync::mpsc;

use crate::error::{ErrorContext, Result, RustFunError};

/// Default capacity of a subscriber queue.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Severity of a captured log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Verbose diagnostics.
    Trace,
    /// Debug information.
    Debug,
    /// Normal operation.
    Info,
    /// Recoverable problems.
    Warn,
    /// Failures.
    Error,
}

impl LogLevel {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Parse a level name.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" | "" => Some(LogLevel::Info),
            "warn" | "warning" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }
}

/// A log record captured from a function or the platform.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Severity.
    pub level: LogLevel,
    /// Subsystem that produced the record (e.g. `instance`, `runtime`, `scheduler`).
    pub source: String,
    /// Message body.
    pub message: String,
    /// Correlation identifiers.
    pub context: EventContext,
}

impl LogRecord {
    /// Create a log record.
    pub fn new(level: LogLevel, source: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level,
            source: source.into(),
            message: message.into(),
            context: EventContext::default(),
        }
    }

    /// Attach correlation context.
    #[must_use]
    pub fn with_context(mut self, context: EventContext) -> Self {
        self.context = context;
        self
    }
}

/// A message delivered to subscribers.
#[derive(Debug, Clone)]
pub enum EventMessage {
    /// A lifecycle event.
    Event(Event),
    /// A log record.
    Log(LogRecord),
}

impl From<Event> for EventMessage {
    fn from(value: Event) -> Self {
        EventMessage::Event(value)
    }
}

impl From<LogRecord> for EventMessage {
    fn from(value: LogRecord) -> Self {
        EventMessage::Log(value)
    }
}

/// A consumer of events.
pub trait EventSink: Send + Sync {
    /// Stable sink name, used in diagnostics.
    fn name(&self) -> &str;

    /// Deliver a message.
    fn handle(&self, message: &EventMessage);
}

/// A sink that forwards messages to `tracing`.
#[derive(Debug, Default)]
pub struct TracingSink;

impl EventSink for TracingSink {
    fn name(&self) -> &str {
        "tracing"
    }

    fn handle(&self, message: &EventMessage) {
        match message {
            EventMessage::Event(event) => {
                tracing::info!(event = event.name(), id = %event.id, payload = ?event.kind, "rustfun event");
            }
            EventMessage::Log(record) => {
                let target = format!("rustfun::{}", record.source);
                // `target` must be a literal for the tracing macros, so dispatch through a
                // helper that formats the target once.
                emit_log(target, record.level, &record.message);
            }
        }
    }
}

fn emit_log(target: String, level: LogLevel, message: &str) {
    match level {
        LogLevel::Trace => tracing::trace!(target: "rustfun", source = %target, "{message}"),
        LogLevel::Debug => tracing::debug!(target: "rustfun", source = %target, "{message}"),
        LogLevel::Info => tracing::info!(target: "rustfun", source = %target, "{message}"),
        LogLevel::Warn => tracing::warn!(target: "rustfun", source = %target, "{message}"),
        LogLevel::Error => tracing::error!(target: "rustfun", source = %target, "{message}"),
    }
}

/// A sink that retains messages in memory, for tests and the `rustfun logs` command.
#[derive(Debug, Default)]
pub struct LogStream {
    records: Mutex<Vec<LogRecord>>,
    capacity: AtomicU64,
}

impl LogStream {
    /// Create a stream retaining up to `capacity` records (0 = unbounded).
    pub fn new(capacity: u64) -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            capacity: AtomicU64::new(capacity),
        }
    }

    /// Snapshot the retained records.
    pub fn snapshot(&self) -> Vec<LogRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Retained record count.
    pub fn len(&self) -> usize {
        self.records.lock().map(|r| r.len()).unwrap_or(0)
    }

    /// Whether no records are retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl EventSink for LogStream {
    fn name(&self) -> &str {
        "log-stream"
    }

    fn handle(&self, message: &EventMessage) {
        let EventMessage::Log(record) = message else {
            return;
        };
        if let Ok(mut records) = self.records.lock() {
            let cap = self.capacity.load(Ordering::Relaxed) as usize;
            if cap > 0 && records.len() >= cap {
                records.remove(0);
            }
            records.push(record.clone());
        }
    }
}

/// Counts events delivered and dropped, so backpressure is observable.
#[derive(Debug, Default)]
struct Counters {
    published: AtomicU64,
    dropped: AtomicU64,
}

/// A subscriber: its queue, the sink it feeds, and the queue capacity.
type Subscriber = (mpsc::Sender<EventMessage>, Arc<dyn EventSink>, usize);

/// Fan-out bus for events and logs.
#[derive(Clone)]
pub struct EventBus {
    subscribers: Arc<Mutex<Vec<Subscriber>>>,
    counters: Arc<Counters>,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("subscribers", &self.subscriber_count())
            .field(
                "published",
                &self.counters.published.load(Ordering::Relaxed),
            )
            .field("dropped", &self.counters.dropped.load(Ordering::Relaxed))
            .finish()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create a bus with no subscribers.
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
            counters: Arc::new(Counters::default()),
        }
    }

    /// Create a bus that forwards to `tracing`.
    pub fn with_tracing() -> Self {
        let bus = Self::new();
        bus.subscribe(Arc::new(TracingSink), DEFAULT_QUEUE_CAPACITY);
        bus
    }

    /// Subscribe a sink. The sink also receives a direct (synchronous) copy so that tests and
    /// in-memory consumers observe events without polling a queue.
    pub fn subscribe(&self, sink: Arc<dyn EventSink>, queue_capacity: usize) {
        let (tx, _rx) = mpsc::channel(queue_capacity.max(1));
        if let Ok(mut subs) = self.subscribers.lock() {
            subs.push((tx, sink, queue_capacity.max(1)));
        }
    }

    /// Number of subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Total messages published.
    pub fn published(&self) -> u64 {
        self.counters.published.load(Ordering::Relaxed)
    }

    /// Total messages dropped because a subscriber queue was full.
    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    /// Publish a message. Never blocks and never fails.
    pub fn publish<M: Into<EventMessage>>(&self, message: M) {
        let message = message.into();
        self.counters.published.fetch_add(1, Ordering::Relaxed);
        let Ok(subs) = self.subscribers.lock() else {
            return;
        };
        for (tx, sink, _cap) in subs.iter() {
            sink.handle(&message);
            if tx.try_send(message.clone()).is_err() {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Publish a lifecycle event.
    pub fn emit(&self, event: Event) {
        self.publish(event);
    }

    /// Publish a log record.
    pub fn log(&self, record: LogRecord) {
        self.publish(record);
    }
}

impl From<RustFunError> for EventMessage {
    fn from(value: RustFunError) -> Self {
        EventMessage::Log(LogRecord::new(
            LogLevel::Error,
            "platform",
            value.to_string(),
        ))
    }
}

/// Helper to build an [`ErrorContext`] naming the current operation.
pub fn op_context(operation: &str) -> ErrorContext {
    ErrorContext::new().operation(operation)
}

/// Convenience result alias for bus operations that cannot fail meaningfully.
pub type PublishResult = Result<()>;

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_events::EventKind;
    use rustfun_model::{FunctionId, InstanceId};
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug, Default)]
    struct CountingSink {
        events: AtomicUsize,
        logs: AtomicUsize,
    }

    impl EventSink for CountingSink {
        fn name(&self) -> &str {
            "counting"
        }

        fn handle(&self, message: &EventMessage) {
            match message {
                EventMessage::Event(_) => {
                    self.events.fetch_add(1, Ordering::Relaxed);
                }
                EventMessage::Log(_) => {
                    self.logs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    #[test]
    fn events_reach_subscribers() {
        let bus = EventBus::new();
        let sink = Arc::new(CountingSink::default());
        bus.subscribe(sink.clone(), 16);
        bus.emit(Event::new(EventKind::InstanceReady {
            instance_id: InstanceId::new(),
        }));
        assert_eq!(sink.events.load(Ordering::Relaxed), 1);
        assert_eq!(bus.published(), 1);
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[test]
    fn log_stream_retains_and_trims() {
        let bus = EventBus::new();
        let stream = Arc::new(LogStream::new(2));
        bus.subscribe(stream.clone(), 16);
        for i in 0..5 {
            bus.log(LogRecord::new(LogLevel::Info, "test", format!("line {i}")));
        }
        let records = stream.snapshot();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message, "line 3");
        assert_eq!(records[1].message, "line 4");
    }

    #[test]
    fn publish_never_panics_without_subscribers() {
        let bus = EventBus::new();
        bus.emit(Event::new(EventKind::FunctionDestroyed {
            function_id: FunctionId::new(),
            name: "hello".into(),
        }));
        assert_eq!(bus.published(), 1);
        assert_eq!(bus.dropped(), 0);
    }

    #[test]
    fn log_levels_roundtrip() {
        for level in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ] {
            assert_eq!(LogLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(LogLevel::parse("nonsense"), None);
        assert_eq!(LogLevel::parse("warning"), Some(LogLevel::Warn));
    }
}
