//! Bounded, captured process logs.
//!
//! Function output is untrusted: an instance must not be able to exhaust host memory by
//! writing to stdout. Every stream is captured into a fixed-budget ring, and the number of
//! dropped lines is reported so that truncation is never silent.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Which stream a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogStreamKind {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl LogStreamKind {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            LogStreamKind::Stdout => "stdout",
            LogStreamKind::Stderr => "stderr",
        }
    }
}

/// A captured log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Stream the line came from.
    pub stream: LogStreamKind,
    /// Line contents (newline stripped).
    pub text: String,
    /// Milliseconds since the process started.
    pub offset_ms: u64,
    /// Monotonic sequence number, so consumers can detect gaps.
    pub sequence: u64,
}

/// A fixed-capacity log buffer for one process.
#[derive(Debug)]
pub struct LogBuffer {
    lines: Mutex<VecDeque<LogLine>>,
    capacity: usize,
    dropped: AtomicU64,
    sequence: AtomicU64,
    started: Instant,
}

impl LogBuffer {
    /// Create a buffer retaining at most `capacity` lines.
    pub fn new(capacity: usize) -> Self {
        Self {
            lines: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    /// Append a line, evicting the oldest line when the buffer is full.
    pub fn push(&self, stream: LogStreamKind, text: impl Into<String>) {
        let line = LogLine {
            stream,
            text: text.into(),
            offset_ms: self.started.elapsed().as_millis() as u64,
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
        };
        if let Ok(mut lines) = self.lines.lock() {
            while lines.len() >= self.capacity {
                lines.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            lines.push_back(line);
        }
    }

    /// Snapshot the retained lines.
    pub fn snapshot(&self) -> Vec<LogLine> {
        self.lines
            .lock()
            .map(|l| l.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Retained line count.
    pub fn len(&self) -> usize {
        self.lines.lock().map(|l| l.len()).unwrap_or(0)
    }

    /// Whether no lines are retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of evicted lines.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Render retained lines as text.
    pub fn to_text(&self) -> String {
        self.snapshot()
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_lines_in_order() {
        let buffer = LogBuffer::new(4);
        buffer.push(LogStreamKind::Stdout, "one");
        buffer.push(LogStreamKind::Stderr, "two");
        let lines = buffer.snapshot();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text, "one");
        assert_eq!(lines[0].sequence, 0);
        assert_eq!(lines[1].stream, LogStreamKind::Stderr);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn evicts_oldest_and_reports_drops() {
        let buffer = LogBuffer::new(2);
        for i in 0..5 {
            buffer.push(LogStreamKind::Stdout, format!("line {i}"));
        }
        let lines = buffer.snapshot();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text, "line 3");
        assert_eq!(lines[1].text, "line 4");
        assert_eq!(buffer.dropped(), 3);
    }

    #[test]
    fn zero_capacity_is_clamped() {
        let buffer = LogBuffer::new(0);
        buffer.push(LogStreamKind::Stdout, "x");
        assert_eq!(buffer.capacity(), 1);
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn text_rendering_joins_lines() {
        let buffer = LogBuffer::new(8);
        buffer.push(LogStreamKind::Stdout, "a");
        buffer.push(LogStreamKind::Stdout, "b");
        assert_eq!(buffer.to_text(), "a\nb");
    }
}
