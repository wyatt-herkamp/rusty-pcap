//! Compatibility report runner for the hadrielk/pcapng-test-generator corpus.
//!
//! Walks the test suite's `output_le/` and `output_be/` directories, attempts
//! to parse every `*.pcapng` file with `SyncPcapNgReader`, compares the
//! observed block counts against the sibling `*.txt` descriptor, and prints
//! a table summarising what rusty-pcap supports today.
//!
//! Usage:
//!     cargo run --example pcapng-test-suite -- /path/to/pcapng-test-generator

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use rusty_pcap::pcap_ng::{
    SyncPcapNgReader,
    blocks::{CUSTOM_BLOCK_COPYABLE, PcapNgBlock},
};

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum EndianArg {
    Le,
    Be,
    Both,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum CategoryArg {
    Basic,
    Advanced,
    Difficult,
    All,
}

#[derive(Parser, Debug)]
#[command(
    name = "pcapng-test-suite",
    about = "Run rusty-pcap against the hadrielk/pcapng-test-generator corpus and emit a support report"
)]
struct Cli {
    /// Path to the pcapng-test-generator root (the dir containing output_le/ and output_be/)
    suite_path: PathBuf,

    #[arg(long, value_enum, default_value_t = EndianArg::Both)]
    endianness: EndianArg,

    #[arg(long, value_enum, default_value_t = CategoryArg::All)]
    category: CategoryArg,

    /// Show the full error message in the Notes column instead of truncating
    #[arg(long)]
    show_errors: bool,

    /// Hide rows whose status is Pass
    #[arg(long)]
    only_failures: bool,
}

#[derive(Debug, Default, Clone)]
struct Counts {
    by_abbr: BTreeMap<String, u32>,
    unknown_ids: BTreeMap<u32, u32>,
}

impl Counts {
    fn bump_abbr(&mut self, abbr: &str) {
        *self.by_abbr.entry(abbr.to_string()).or_default() += 1;
    }
    fn bump_unknown(&mut self, id: u32) {
        *self.unknown_ids.entry(id).or_default() += 1;
    }
}

#[derive(Debug, Default)]
struct Descriptor {
    description: String,
    category: String,
    expected: BTreeMap<String, u32>,
}

#[derive(Debug)]
enum Status {
    Pass,
    Partial,
    Mismatch(String),
    Fail(String),
}

impl Status {
    fn label(&self) -> &'static str {
        match self {
            Status::Pass => "Pass",
            Status::Partial => "Partial",
            Status::Mismatch(_) => "Mismatch",
            Status::Fail(_) => "Fail",
        }
    }
    fn color(&self) -> Color {
        match self {
            Status::Pass => Color::Green,
            Status::Partial => Color::Yellow,
            Status::Mismatch(_) => Color::Magenta,
            Status::Fail(_) => Color::Red,
        }
    }
}
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum TestEndianness {
    Little = 0,
    Big = 1,
}
impl TestEndianness {
    fn directory_name(&self) -> &'static str {
        match self {
            TestEndianness::Little => "output_le",
            TestEndianness::Big => "output_be",
        }
    }
    fn label(&self) -> &'static str {
        match self {
            TestEndianness::Little => "LE",
            TestEndianness::Big => "BE",
        }
    }
}
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum TestCategory {
    Basic = 0,
    Advanced = 1,
    Difficult = 2,
}
impl TestCategory {
    fn directory_name(&self) -> &'static str {
        match self {
            TestCategory::Basic => "basic",
            TestCategory::Advanced => "advanced",
            TestCategory::Difficult => "difficult",
        }
    }
}
/// Ordering for this struct is defined by category, then endianness, then test name, to make the
/// final report easier to read.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TestFile {
    category: TestCategory,
    name: String,
    endianness: TestEndianness,
}

#[derive(Debug)]
struct Row {
    test: String,
    endianness: &'static str,
    category: String,
    description: String,
    status: Status,
    counts: Counts,
}
fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    let endiannesses: &[TestEndianness] = match cli.endianness {
        EndianArg::Le => &[TestEndianness::Little],
        EndianArg::Be => &[TestEndianness::Big],
        EndianArg::Both => &[TestEndianness::Little, TestEndianness::Big],
    };
    let categories: &[TestCategory] = match cli.category {
        CategoryArg::Basic => &[TestCategory::Basic],
        CategoryArg::Advanced => &[TestCategory::Advanced],
        CategoryArg::Difficult => &[TestCategory::Difficult],
        CategoryArg::All => &[
            TestCategory::Basic,
            TestCategory::Advanced,
            TestCategory::Difficult,
        ],
    };

    let mut rows: Vec<Row> = Vec::new();
    for endianness in endiannesses {
        for category in categories {
            let dir = cli
                .suite_path
                .join(endianness.directory_name())
                .join(category.directory_name());
            if !dir.is_dir() {
                eprintln!("note: skipping {} (not a directory)", dir.display());
                continue;
            }
            let mut pcapng_paths: Vec<(PathBuf, TestFile)> = std::fs::read_dir(&dir)
                .with_context(|| format!("reading {}", dir.display()))?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("pcapng"))
                .map(|path| {
                    let test_file = TestFile {
                        category: *category,
                        name: path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("?")
                            .to_string(),
                        endianness: *endianness,
                    };
                    (path, test_file)
                })
                .collect();
            pcapng_paths.sort_by(|(_, f1), (_, f2)| f1.cmp(f2));
            for (path, test_file) in pcapng_paths {
                let row = run_one(
                    &path,
                    test_file.endianness.label(),
                    test_file.category.directory_name(),
                );
                rows.push(row);
            }
        }
    }

    let summary = Summary::from_rows(&rows);
    render_table(&rows, &cli);
    println!();
    summary.print();

    Ok(if summary.has_real_failures() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn run_one(path: &Path, end_label: &'static str, fallback_category: &str) -> Row {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("?")
        .to_string();
    let descriptor_path = path.with_extension("txt");
    let descriptor = if descriptor_path.is_file() {
        parse_descriptor(&descriptor_path).unwrap_or_default()
    } else {
        Descriptor::default()
    };
    let description = if descriptor.description.is_empty() {
        "(no .txt descriptor)".to_string()
    } else {
        descriptor.description.clone()
    };
    let category = if descriptor.category.is_empty() {
        fallback_category.to_string()
    } else {
        descriptor.category.clone()
    };

    match probe(path) {
        Err(message) => Row {
            test: stem,
            endianness: end_label,
            category,
            description,
            status: Status::Fail(message),
            counts: Counts::default(),
        },
        Ok(counts) => {
            let status = classify(&counts, &descriptor.expected);
            Row {
                test: stem,
                endianness: end_label,
                category,
                description,
                status,
                counts,
            }
        }
    }
}

fn probe(path: &Path) -> Result<Counts, String> {
    let file = File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut reader = BufReader::new(file);
    let mut ng = SyncPcapNgReader::new(&mut reader).map_err(|e| format!("{e}"))?;

    let mut counts = Counts::default();
    // SyncPcapNgReader::new consumes the initial Section Header Block, so seed
    // the SHB counter with it; subsequent SHBs (in multi-section files) are
    // surfaced by next_block() and counted in the loop below.
    counts.bump_abbr("SHB");

    loop {
        match ng.next_block() {
            Ok(Some(block)) => match block {
                PcapNgBlock::SectionHeader(_) => counts.bump_abbr("SHB"),
                PcapNgBlock::InterfaceDescription(_) => counts.bump_abbr("IDB"),
                PcapNgBlock::EnhancedPacket(_) => counts.bump_abbr("EPB"),
                PcapNgBlock::SimplePacket(_) => counts.bump_abbr("SPB"),
                PcapNgBlock::NameResolution(_) => counts.bump_abbr("NRB"),
                PcapNgBlock::InterfaceStatistics(_) => counts.bump_abbr("ISB"),
                PcapNgBlock::DecryptionSecrets(_) => counts.bump_abbr("DSB"),
                PcapNgBlock::Custom(cb) => {
                    // The test corpus distinguishes "CB" (may-copy) from "DCB"
                    // (do-not-copy) in its descriptors, so mirror that split
                    // here for count-comparison purposes.
                    if cb.block_id == CUSTOM_BLOCK_COPYABLE {
                        counts.bump_abbr("CB");
                    } else {
                        counts.bump_abbr("DCB");
                    }
                }
                PcapNgBlock::Generic(g) => counts.bump_unknown(g.block_id),
            },
            Ok(None) => return Ok(counts),
            Err(e) => return Err(format!("{e}")),
        }
    }
}

// Abbreviations that map onto real PcapNgBlock variants (not Generic).
const NATIVE_ABBRS: &[&str] = &["SHB", "IDB", "EPB", "SPB", "NRB", "ISB", "CB", "DCB", "DSB"];

fn is_native(abbr: &str) -> bool {
    NATIVE_ABBRS.contains(&abbr)
}

fn classify(counts: &Counts, expected: &BTreeMap<String, u32>) -> Status {
    // Mismatch wins over Partial: silent parse divergence is more severe than
    // "ran into a known-unsupported block type."
    let mut mismatches: Vec<String> = Vec::new();
    if !expected.is_empty() {
        let mut keys: Vec<&String> = expected.keys().collect();
        for actual_key in counts.by_abbr.keys() {
            if !expected.contains_key(actual_key) {
                keys.push(actual_key);
            }
        }
        keys.sort();
        keys.dedup();
        for key in keys {
            let want = expected.get(key).copied().unwrap_or(0);
            let got = counts.by_abbr.get(key).copied().unwrap_or(0);
            if want != got {
                mismatches.push(format!("{key} expected={want} got={got}"));
            }
        }
    }
    if !mismatches.is_empty() {
        return Status::Mismatch(mismatches.join(", "));
    }

    let has_unsupported_native = counts
        .by_abbr
        .iter()
        .any(|(abbr, n)| *n > 0 && !is_native(abbr));
    if has_unsupported_native || !counts.unknown_ids.is_empty() {
        return Status::Partial;
    }
    Status::Pass
}

fn parse_descriptor(path: &Path) -> Result<Descriptor> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading descriptor {}", path.display()))?;
    let mut d = Descriptor::default();
    let mut in_counts = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Description:") {
            d.description = rest.trim().to_string();
            in_counts = false;
        } else if let Some(rest) = trimmed.strip_prefix("Category:") {
            d.category = rest.trim().to_string();
            in_counts = false;
        } else if trimmed.starts_with("Block counts:") {
            in_counts = true;
        } else if trimmed.starts_with("Block sequence:") {
            in_counts = false;
        } else if in_counts
            && !trimmed.is_empty()
            && let Some((abbr, n)) = trimmed.split_once(':')
        {
            let abbr = abbr.trim().to_string();
            if let Ok(n) = n.trim().parse::<u32>()
                && !abbr.is_empty()
            {
                d.expected.insert(abbr, n);
            }
        }
    }
    Ok(d)
}

fn render_table(rows: &[Row], cli: &Cli) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Test"),
            Cell::new("End"),
            Cell::new("Category"),
            Cell::new("Status"),
            Cell::new("Description"),
            Cell::new("Notes"),
        ]);

    for row in rows {
        if cli.only_failures && matches!(row.status, Status::Pass) {
            continue;
        }
        let notes = render_notes(&row.status, &row.counts, cli.show_errors);
        table.add_row(vec![
            Cell::new(&row.test),
            Cell::new(row.endianness),
            Cell::new(&row.category),
            Cell::new(row.status.label()).fg(row.status.color()),
            Cell::new(&row.description),
            Cell::new(notes),
        ]);
    }

    println!("{table}");
}

fn render_notes(status: &Status, counts: &Counts, show_full_error: bool) -> String {
    match status {
        Status::Pass => String::new(),
        Status::Partial => {
            let unsupported = render_unsupported(counts);
            if unsupported.is_empty() {
                String::from("unsupported block types present")
            } else {
                format!("unsupported: {unsupported}")
            }
        }
        Status::Mismatch(detail) => detail.clone(),
        Status::Fail(message) => {
            if show_full_error {
                message.clone()
            } else {
                truncate(message, 80)
            }
        }
    }
}

fn render_unsupported(counts: &Counts) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (abbr, n) in &counts.by_abbr {
        if !is_native(abbr) && *n > 0 {
            parts.push(format!("{abbr}({n})"));
        }
    }
    for (id, n) in &counts.unknown_ids {
        parts.push(format!("id=0x{id:08X}({n})"));
    }
    parts.join(", ")
}

fn truncate(s: &str, max: usize) -> String {
    let one_line: String = s.replace('\n', " ");
    match one_line.char_indices().nth(max) {
        Some((idx, _)) => format!("{}…", &one_line[..idx]),
        None => one_line,
    }
}

struct Summary {
    total: usize,
    pass: usize,
    partial: usize,
    mismatch: usize,
    fail: usize,
    unsupported_abbrs: BTreeMap<String, u32>,
    unknown_ids: BTreeMap<u32, u32>,
}

impl Summary {
    fn from_rows(rows: &[Row]) -> Self {
        let mut s = Summary {
            total: rows.len(),
            pass: 0,
            partial: 0,
            mismatch: 0,
            fail: 0,
            unsupported_abbrs: BTreeMap::new(),
            unknown_ids: BTreeMap::new(),
        };
        for row in rows {
            match &row.status {
                Status::Pass => s.pass += 1,
                Status::Partial => s.partial += 1,
                Status::Mismatch(_) => s.mismatch += 1,
                Status::Fail(_) => s.fail += 1,
            }
            for (abbr, n) in &row.counts.by_abbr {
                if !is_native(abbr) && *n > 0 {
                    *s.unsupported_abbrs.entry(abbr.clone()).or_default() += *n;
                }
            }
            for (id, n) in &row.counts.unknown_ids {
                *s.unknown_ids.entry(*id).or_default() += *n;
            }
        }
        s
    }

    fn has_real_failures(&self) -> bool {
        self.mismatch > 0 || self.fail > 0
    }

    fn print(&self) {
        println!(
            "Summary: {} files | {} pass | {} partial | {} mismatch | {} fail",
            self.total, self.pass, self.partial, self.mismatch, self.fail
        );
        if !self.unsupported_abbrs.is_empty() || !self.unknown_ids.is_empty() {
            let mut parts: Vec<String> = self
                .unsupported_abbrs
                .iter()
                .map(|(k, n)| format!("{k}({n})"))
                .collect();
            for (id, n) in &self.unknown_ids {
                parts.push(format!("id=0x{id:08X}({n})"));
            }
            println!("Unsupported blocks observed: {}", parts.join(", "));
        }
    }
}
