//! prometheuz: a Prometheus/node-exporter driver.
//!
//! Note:
//! - Zig std only, standalone package. This file is the public root.
//! - Scrapes node-exporter (or any Prometheus text 0.0.4 endpoint), pushes
//!   via remote_write, queries via PromQL, and carries an app-side metric
//!   registry (Counter, Gauge) for values that never come from a scrape.

const std = @import("std");
const builtin = @import("builtin");

/// THE ONLY SOURCE OF TRUTH for Zig SEMVER for prometheuz source.
///
/// Note:
/// - Do not create in other place!
pub const ZIG_SEMVER = struct {
    pub const MAJOR: usize = builtin.zig_version.major;
    pub const MINOR: usize = builtin.zig_version.minor;
    pub const PATCH: usize = builtin.zig_version.patch;
};

// --------------------------------------------------------- //

pub const http_client = @import("http_client.zig");
pub const config = @import("config.zig");
pub const url = @import("url.zig");
pub const sample = @import("sample.zig");
pub const parser = @import("parser.zig");
pub const snapshot = @import("snapshot.zig");
pub const scrape = @import("scrape.zig");
pub const scraper = @import("scraper.zig");
pub const registry = @import("registry.zig");
pub const expose_mod = @import("expose.zig");
pub const protobuf = @import("protobuf.zig");
pub const snappy = @import("snappy.zig");
pub const remote_write = @import("remote_write.zig");
pub const query_mod = @import("query.zig");

/// Own minimal HTTP/1.1 client surface, re-exported.
pub const HttpClient = http_client;

/// Flat per-surface configs, re-exported.
pub const ScrapeConfig = config.ScrapeConfig;
pub const WriteConfig = config.WriteConfig;
pub const QueryConfig = config.QueryConfig;

/// Target URL parsing, re-exported.
pub const parseScrapeUrl = url.parseScrapeUrl;
pub const parseWriteUrl = url.parseWriteUrl;
pub const parseQueryUrl = url.parseQueryUrl;

/// Parsed text 0.0.4 types, re-exported.
pub const MetricType = sample.MetricType;
pub const Label = sample.Label;
pub const Sample = sample.Sample;
pub const MetricFamily = sample.MetricFamily;

/// Text 0.0.4 parser, re-exported.
pub const parse = parser.parse;

/// Scrape result, re-exported: prometheuz.Snapshot.
pub const Snapshot = snapshot.Snapshot;

/// One-shot scrape primitive, re-exported: prometheuz.scrapeOnce(...).
pub const scrapeOnce = scrape.scrapeOnce;

/// Background poller, re-exported: prometheuz.Scraper.start(...).
pub const Scraper = scraper.Scraper;

/// App-authored metric registry, re-exported.
pub const Registry = registry.Registry;
pub const Counter = registry.Counter;
pub const Gauge = registry.Gauge;
pub const CounterVec = registry.CounterVec;
pub const GaugeVec = registry.GaugeVec;

/// Text 0.0.4 encoder, re-exported: prometheuz.expose(arena, &registry).
pub const expose = expose_mod.expose;

/// remote_write push, re-exported: prometheuz.remoteWrite(...).
pub const remoteWrite = remote_write.remoteWrite;

/// PromQL query, re-exported.
pub const query = query_mod.query;
pub const queryRange = query_mod.queryRange;
pub const QueryResult = query_mod.QueryResult;
pub const VectorEntry = query_mod.VectorEntry;
pub const MatrixEntry = query_mod.MatrixEntry;
pub const Point = query_mod.Point;

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test {
    _ = http_client;
    _ = config;
    _ = url;
    _ = sample;
    _ = parser;
    _ = snapshot;
    _ = scrape;
    _ = scraper;
    _ = registry;
    _ = expose_mod;
    _ = protobuf;
    _ = snappy;
    _ = remote_write;
    _ = query_mod;
}
