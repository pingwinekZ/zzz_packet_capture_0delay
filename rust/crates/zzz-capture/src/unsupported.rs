//! Placeholder backend for targets that have no live capture implementation.
//!
//! Keeping the same API means the CLI and GUI still compile on macOS and other
//! Unixes; they report the unsupported platform instead of failing to build.

use crate::{CaptureError, Packet};

/// A capture that can never be opened.
#[derive(Clone)]
pub struct Capture;

impl Capture {
    pub fn port_filter(port: u16) -> String {
        format!("udp port {port}")
    }

    pub fn open(_port: u16) -> Result<Self, CaptureError> {
        Err(CaptureError::Unsupported(std::env::consts::OS))
    }

    pub fn open_filtered(_filter: &str, _port: u16) -> Result<Self, CaptureError> {
        Err(CaptureError::Unsupported(std::env::consts::OS))
    }

    pub fn recv(&self, _buffer: &mut [u8]) -> Result<Option<Packet>, CaptureError> {
        Err(CaptureError::Unsupported(std::env::consts::OS))
    }

    pub fn stop(&self) {}

    pub fn is_stopped(&self) -> bool {
        true
    }

    pub fn packets(&self) -> u64 {
        0
    }

    pub fn skipped(&self) -> u64 {
        0
    }

    pub fn direction_conflicts(&self) -> u64 {
        0
    }
}
