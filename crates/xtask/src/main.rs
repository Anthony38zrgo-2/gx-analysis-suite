//! xtask — helpers de build/release y benchmark del workspace (GX-020/A02).
//!
//! Comandos:
//! - `cargo xtask build` / `build-debug`: build del workspace + copia a dist/.
//! - `cargo xtask bench [--release] [--scenario NAME] [--lines N] [--files N]`
//!   `[--objects N] [--runs R] [--out FILE] [--check]`:
//!   harness de benchmark de release con corpus fijo, CPU/allocations/peak
//!   working set, latencia de cancelación y resultados JSON machine-readable.
//!   `--check` verifica operation-counts deterministas (gate de CI).

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use gx_core::budget::ExecutionBudget;
use gx_core::models::{AnalysisRequest, QgPolicy};
use gx_core::stats::{self, ScanStats};
use gx_sources::filesystem::discover_source_files;
use gx_sources::xpz_extractor::extract_source_objects_with_budget;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Allocator contador (A02.3): mide llamadas y bytes reservados por fase.
struct CountingAllocator;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_CALLS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct AllocStats {
    alloc_calls: u64,
    allocated_bytes: u64,
    dealloc_calls: u64,
}

fn alloc_snapshot() -> AllocStats {
    AllocStats {
        alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
        allocated_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
    }
}

fn alloc_delta(before: AllocStats, after: AllocStats) -> AllocStats {
    AllocStats {
        alloc_calls: after.alloc_calls.saturating_sub(before.alloc_calls),
        allocated_bytes: after.allocated_bytes.saturating_sub(before.allocated_bytes),
        dealloc_calls: after.dealloc_calls.saturating_sub(before.dealloc_calls),
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    match command {
        "build" => build(true),
        "build-debug" => build(false),
        "bench" => bench(&args[1..]),
        "check-boundaries" => check_boundaries(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("[xtask] comando desconocido: '{other}'");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("xtask — helpers del workspace gx-linter-rs");
    println!("  cargo xtask build        release build + copia a dist/gx.exe");
    println!("  cargo xtask build-debug  debug build + copia a dist/gx.exe");
    println!("  cargo xtask check-boundaries  verifica el path mínimo del engine (B04)");
    println!("  cargo xtask bench        benchmark (requiere release)");
    println!("    --release            exige perfil release (default)");
    println!("    --no-release-check   permite corridas exploratorias en debug");
    println!("    --scenario NAME      small-files (default) | diagnostic-heavy |");
    println!("                         clean | long-lines | wide-xml | real");
    println!("    --lines N            líneas por archivo (default 1000)");
    println!("    --files N            archivos del corpus (default 50)");
    println!("    --objects N          objetos por XML en wide-xml (default 20)");
    println!("    --runs R             corridas repetidas (default 5)");
    println!("    --out FILE           escribe el JSON en FILE (default stdout)");
    println!("    --check              gate determinista de operation-counts (CI)");
}

fn build(release: bool) -> anyhow::Result<()> {
    let profile = if release { "release" } else { "debug" };
    println!("[xtask] cargo build --workspace --{profile}");

    let mut args = vec!["build", "--workspace"];
    if release {
        args.push("--release");
    }
    let status = Command::new("cargo").args(&args).status()?;
    if !status.success() {
        anyhow::bail!("cargo build falló ({status})");
    }

    let source = Path::new("target").join(profile).join("gx.exe");
    if source.is_file() {
        std::fs::create_dir_all("dist")?;
        let destination = Path::new("dist").join("gx.exe");
        std::fs::copy(&source, &destination)?;
        println!(
            "[xtask] copiado {} -> {}",
            source.display(),
            destination.display()
        );
    }
    Ok(())
}

/// B04/E01: el engine SIN la feature `archives` no debe enlazar SQLite,
/// Tauri, PDF ni el soporte nativo de ZIP/RAR.
fn check_boundaries() -> Result<()> {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("no se pudo resolver el root del workspace")?;

    let banned = [
        "rusqlite",
        "libsqlite3-sys",
        "sqlite3",
        "tauri",
        "printpdf",
        "lopdf",
        "zip",
        "unrar",
    ];

    let output = Command::new("cargo")
        .current_dir(&workspace)
        .args([
            "tree",
            "-e",
            "normal",
            "-p",
            "gx_engine",
            "--no-default-features",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .output()
        .context("no se pudo ejecutar cargo tree")?;
    if !output.status.success() {
        bail!(
            "cargo tree falló: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let names: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(|name| name.to_lowercase())
        .collect();
    let found: Vec<&str> = banned
        .iter()
        .copied()
        .filter(|banned| names.iter().any(|name| name == banned))
        .collect();
    if !found.is_empty() {
        bail!(
            "fronteras violadas: el engine sin `archives` enlaza {found:?} \
             (ver B04 del roadmap)"
        );
    }

    // El path mínimo no sólo no enlaza: debe COMPILAR sin la feature.
    let status = Command::new("cargo")
        .current_dir(&workspace)
        .args(["check", "-p", "gx_engine", "--no-default-features"])
        .status()
        .context("no se pudo ejecutar cargo check")?;
    if !status.success() {
        bail!("el engine sin `archives` no compila (cargo check falló)");
    }

    println!("[xtask] fronteras OK: engine sin `archives` no enlaza SQLite/Tauri/PDF/zip/unrar");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Benchmark (A02)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    SmallFiles,
    DiagnosticHeavy,
    Clean,
    LongLines,
    WideXml,
    Real,
}

impl Scenario {
    fn parse(name: &str) -> Result<Self> {
        match name {
            "small-files" => Ok(Scenario::SmallFiles),
            "diagnostic-heavy" => Ok(Scenario::DiagnosticHeavy),
            "clean" => Ok(Scenario::Clean),
            "long-lines" => Ok(Scenario::LongLines),
            "wide-xml" => Ok(Scenario::WideXml),
            "real" => Ok(Scenario::Real),
            other => bail!("escenario desconocido: '{other}'"),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Scenario::SmallFiles => "small-files",
            Scenario::DiagnosticHeavy => "diagnostic-heavy",
            Scenario::Clean => "clean",
            Scenario::LongLines => "long-lines",
            Scenario::WideXml => "wide-xml",
            Scenario::Real => "real",
        }
    }
}

#[derive(Debug, Clone)]
struct BenchArgs {
    scenario: Scenario,
    lines: usize,
    files: usize,
    objects: usize,
    runs: usize,
    out: Option<PathBuf>,
    require_release: bool,
    check: bool,
}

impl Default for BenchArgs {
    fn default() -> Self {
        Self {
            scenario: Scenario::SmallFiles,
            lines: 1000,
            files: 50,
            objects: 20,
            runs: 5,
            out: None,
            require_release: true,
            check: false,
        }
    }
}

fn bench(args: &[String]) -> Result<()> {
    let options = parse_bench_args(args)?;
    if options.require_release && cfg!(debug_assertions) {
        bail!(
            "el benchmark debe correr en release: `cargo run --release -p xtask -- bench` \
             (o `--no-release-check` para una corrida exploratoria)"
        );
    }

    let manifest = generate_corpus(&options)?;

    let enabled: Vec<String> = {
        let mut ids: Vec<String> = gx_rules::all_rules()
            .iter()
            .filter(|r| !r.is_abstract())
            .map(|r| r.id().to_string())
            .collect();
        ids.sort();
        ids
    };
    let request = AnalysisRequest {
        schema_version: 1,
        inputs: vec![PathBuf::from(&manifest.directory)],
        enabled_rule_ids: enabled.clone(),
        policy: QgPolicy::Absolute {
            max_errors: u32::MAX,
            max_warnings: u32::MAX,
        },
        record_history: false,
        retain_sensitive_evidence: false,
    };
    let budget = ExecutionBudget::default();

    if options.check {
        let run = run_once(0, &request, &enabled, &budget, true)?;
        check_gates(&manifest, &run, enabled.len())?;
        println!(
            "[xtask] BENCH GATES OK — scenario={} files={} lines={} findings={} rule_evals={} factories={}",
            manifest.scenario,
            manifest.files,
            manifest.total_lines,
            run.findings,
            run.analysis_stats.rule_evaluations,
            run.analysis_stats.rule_factory_invocations
        );
        return Ok(());
    }

    let mut runs: Vec<RunReport> = Vec::with_capacity(options.runs);
    for run_index in 0..options.runs {
        runs.push(run_once(run_index, &request, &enabled, &budget, false)?);
    }
    let summary = summarize(&runs);

    let report = BenchReport {
        schema: "gx-bench/2",
        generated_at: timestamp(),
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        engine_version: env!("CARGO_PKG_VERSION"),
        rustc_version: rustc_version(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        corpus: manifest,
        profile_rules: enabled,
        runs,
        summary,
    };

    let json = serde_json::to_string_pretty(&report)?;
    match options.out {
        Some(path) => {
            std::fs::write(&path, format!("{json}\n"))
                .with_context(|| format!("no se pudo escribir '{}'", path.display()))?;
            eprintln!("[xtask] resultados: {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn parse_bench_args(args: &[String]) -> Result<BenchArgs> {
    let mut options = BenchArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--release" => options.require_release = true,
            "--no-release-check" => options.require_release = false,
            "--check" => options.check = true,
            "--scenario" => {
                i += 1;
                options.scenario =
                    Scenario::parse(args.get(i).context("--scenario requiere un nombre")?)?;
            }
            "--lines" => {
                i += 1;
                options.lines = parse_usize(args.get(i), "--lines")?;
            }
            "--files" => {
                i += 1;
                options.files = parse_usize(args.get(i), "--files")?;
            }
            "--objects" => {
                i += 1;
                options.objects = parse_usize(args.get(i), "--objects")?;
            }
            "--runs" => {
                i += 1;
                options.runs = parse_usize(args.get(i), "--runs")?;
            }
            "--out" => {
                i += 1;
                options.out = Some(PathBuf::from(
                    args.get(i).context("--out requiere una ruta")?,
                ));
            }
            other => bail!("argumento de bench desconocido: '{other}'"),
        }
        i += 1;
    }
    if options.files == 0 || options.lines == 0 || options.objects == 0 || options.runs == 0 {
        bail!("--files, --lines, --objects y --runs deben ser > 0");
    }
    if options.check {
        options.runs = 1;
    }
    Ok(options)
}

fn parse_usize(value: Option<&String>, flag: &str) -> Result<usize> {
    value
        .with_context(|| format!("{flag} requiere un valor"))?
        .parse()
        .with_context(|| format!("valor inválido para {flag}"))
}

/// Corpus fijo (A02.4): mismo contenido y hash en cada corrida.
fn generate_corpus(options: &BenchArgs) -> Result<CorpusManifest> {
    match options.scenario {
        Scenario::Real => real_corpus(),
        Scenario::WideXml => synthetic_corpus(
            options,
            wide_xml_file,
            Some(options.files * options.lines * CODE_LINES_PER_OBJECT),
        ),
        _ => {
            let builder: fn(usize, usize) -> String = match options.scenario {
                Scenario::SmallFiles => small_files_file,
                Scenario::DiagnosticHeavy => diagnostic_heavy_file,
                Scenario::Clean => clean_file,
                Scenario::LongLines => long_lines_file,
                Scenario::WideXml | Scenario::Real => unreachable!(),
            };
            synthetic_corpus(options, builder, Some(options.files * options.lines))
        }
    }
}

fn synthetic_corpus(
    options: &BenchArgs,
    builder: fn(usize, usize) -> String,
    expected_lines: Option<usize>,
) -> Result<CorpusManifest> {
    let dir = PathBuf::from("target").join("bench-corpus");
    std::fs::create_dir_all(&dir)?;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("txt") | Some("xml")
            ) {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    let mut hasher = Sha256::new();
    for file_index in 0..options.files {
        let content = builder(file_index, options.lines);
        hasher.update(content.as_bytes());
        let extension = if options.scenario == Scenario::WideXml {
            "xml"
        } else {
            "txt"
        };
        let path = dir.join(format!("obj_{file_index:05}.{extension}"));
        std::fs::write(&path, content)
            .with_context(|| format!("no se pudo escribir '{}'", path.display()))?;
    }
    let digest = hasher.finalize();

    let (expected_objects, expected_parses) = match options.scenario {
        Scenario::WideXml => (Some(options.files * options.lines), Some(options.files)),
        _ => (Some(options.files), Some(0)),
    };
    Ok(CorpusManifest {
        scenario: options.scenario.name().to_string(),
        directory: dir.to_string_lossy().to_string(),
        files: options.files,
        lines_per_file: options.lines,
        total_lines: expected_lines.unwrap_or(0),
        expected_objects,
        expected_xml_parses: expected_parses,
        sha256: digest.iter().map(|b| format!("{b:02X}")).collect(),
    })
}

/// Escenario real: exports de `tests/fixtures/sources/real` (XPZ/ZIP/RAR).
fn real_corpus() -> Result<CorpusManifest> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sources/real");
    if !dir.is_dir() {
        bail!("no existe el corpus real: {}", dir.display());
    }
    let report = discover_source_files(&dir);
    if report.files.is_empty() {
        bail!(
            "el corpus real no contiene archivos fuente: {}",
            dir.display()
        );
    }
    let mut hasher = Sha256::new();
    for file in &report.files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        hasher.update(name.as_bytes());
        let bytes =
            std::fs::read(file).with_context(|| format!("no se pudo leer '{}'", file.display()))?;
        hasher.update(&bytes);
    }
    let digest = hasher.finalize();
    Ok(CorpusManifest {
        scenario: Scenario::Real.name().to_string(),
        directory: dir.to_string_lossy().to_string(),
        files: report.files.len(),
        lines_per_file: 0,
        total_lines: 0,
        expected_objects: None,
        expected_xml_parses: None,
        sha256: digest.iter().map(|b| format!("{b:02X}")).collect(),
    })
}

// Generadores de contenido deterministas ────────────────────────────────

fn small_files_file(file_index: usize, lines: usize) -> String {
    let mut out = String::with_capacity(lines * 48);
    let with_context = file_index.is_multiple_of(5);
    for line in 0..lines {
        match line % 12 {
            0 if with_context => out.push_str("for each Customer\n"),
            1 if with_context => out.push_str("    where CustomerId = 42\n"),
            2 if with_context => out.push_str("    &lower = &lower + 1\n"),
            3 if with_context => out.push_str("endfor\n"),
            5 => out.push_str("sub 'Inicializar'\n"),
            6 => out.push_str("    // comentario sin cierre\n"),
            7 => out.push_str("endsub\n"),
            9 => out.push_str("    do 'Inicializar'\n"),
            _ => out.push_str("    &value = &value + 1\n"),
        }
    }
    out
}

/// Todas las líneas violan alguna regla (presión de diagnostics).
fn diagnostic_heavy_file(file_index: usize, lines: usize) -> String {
    let mut out = String::with_capacity(lines * 64);
    for line in 0..lines {
        match line % 4 {
            0 => out.push_str("&lower = &lower + 1\n"),
            1 => out.push_str("if &temp > 1 and &temp < 20 and &myvar = 5 and &ok = true\n"),
            2 => out.push_str("    do 'NoExiste'\n"),
            _ => {
                let _ = file_index;
                out.push_str("sub 'SinNullvalue'\n");
            }
        }
    }
    out
}

/// Sin hallazgos: cabecera de Historia de Cambios + comentarios.
fn clean_file(_file_index: usize, lines: usize) -> String {
    const HEADERS: &[&str] = &[
        "// CODIGO INICIATIVA: demo",
        "// DESCRIPCION: objeto limpio",
        "// RESPONSIBLE: qa",
        "// VERSION: 1.0",
    ];
    let mut out = String::with_capacity(lines * 32);
    let header_count = HEADERS.len().min(lines);
    for header in &HEADERS[..header_count] {
        out.push_str(header);
        out.push('\n');
    }
    for line in header_count..lines {
        out.push_str(&format!("// linea limpia {line}"));
        out.push('\n');
    }
    out
}

/// Líneas muy largas (estrés de la pasada léxica).
fn long_lines_file(_file_index: usize, lines: usize) -> String {
    let payload = "a".repeat(4092);
    let mut out = String::with_capacity(lines * 4100);
    for _ in 0..lines {
        out.push_str("&Value = '");
        out.push_str(&payload);
        out.push_str("'\n");
    }
    out
}

/// Líneas de código por objeto en el escenario `wide-xml`.
const CODE_LINES_PER_OBJECT: usize = 4;

/// Un XML con muchos GXObjects, cada uno con `CODE_LINES_PER_OBJECT` líneas.
fn wide_xml_file(_file_index: usize, objects: usize) -> String {
    let mut out = String::with_capacity(objects * 320);
    out.push_str("<?xml version=\"1.0\"?>\n<ExportFile>\n");
    for object in 0..objects {
        out.push_str("<GXObject><Procedure><Info><Name>");
        out.push_str(&format!("Obj{object:05}"));
        out.push_str("</Name></Info>");
        out.push_str("<Events><![CDATA[");
        out.push_str("for each Customer\n");
        out.push_str("    where CustomerId = 42\n");
        out.push_str("    &lower = &lower + 1\n");
        out.push_str("endfor\n");
        out.push_str("]]></Events></Procedure></GXObject>\n");
    }
    out.push_str("</ExportFile>\n");
    out
}

#[derive(Debug, Clone, Serialize)]
struct CorpusManifest {
    scenario: String,
    directory: String,
    files: usize,
    lines_per_file: usize,
    /// Líneas esperadas por el gate (0 = sin gate).
    total_lines: usize,
    expected_objects: Option<usize>,
    expected_xml_parses: Option<usize>,
    sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunReport {
    run: usize,
    /// `cold` en la primera corrida, `warm` en las siguientes (A02.3).
    temperature: &'static str,
    discovery_ms: f64,
    extraction_ms: f64,
    full_analysis_ms: f64,
    /// Serialización del resultado (proxy de export/IPC, A02.2).
    serialization_ms: f64,
    /// Líneas del corpus por segundo en el análisis completo.
    throughput_lines_per_sec: f64,
    extraction_stats: ScanStats,
    analysis_stats: ScanStats,
    findings: usize,
    failures: usize,
    /// Bytes del JSON de findings materializado.
    result_bytes: usize,
    allocation: AllocStats,
    /// CPU (kernel+user) del análisis completo; None fuera de Windows.
    cpu_ms: Option<f64>,
    /// Latencia de cancelación cooperativa medida (A02.3).
    cancellation_latency_ms: Option<f64>,
    peak_working_set_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct Summary {
    runs: usize,
    min_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
struct BenchReport {
    schema: &'static str,
    generated_at: String,
    profile: &'static str,
    engine_version: &'static str,
    rustc_version: String,
    os: &'static str,
    arch: &'static str,
    corpus: CorpusManifest,
    profile_rules: Vec<String>,
    runs: Vec<RunReport>,
    summary: Summary,
}

fn run_once(
    run_index: usize,
    request: &AnalysisRequest,
    _enabled: &[String],
    budget: &ExecutionBudget,
    check_mode: bool,
) -> Result<RunReport> {
    // Fase 1: discovery.
    stats::reset();
    let discovery_start = Instant::now();
    let discovery =
        discover_source_files(Path::new(request.inputs[0].to_str().unwrap_or_default()));
    let discovery_ms = millis(discovery_start.elapsed());

    // Fase 2: extracción (decompresión/decodificación/parseo sin reglas).
    stats::reset();
    let extraction_start = Instant::now();
    let mut objects = 0usize;
    for file in &discovery.files {
        let outcome = extract_source_objects_with_budget(file, budget, None)?;
        objects += outcome.objects.len();
    }
    let extraction_ms = millis(extraction_start.elapsed());
    let extraction_stats = stats::snapshot();

    // Fase 3: análisis completo (discovery + extracción + linteo).
    stats::reset();
    let alloc_before = alloc_snapshot();
    let cpu_before = cpu_time_ms();
    let analysis_start = Instant::now();
    let result = gx_engine::runtime::analyze_with_options(request, None, None, budget);
    let full_analysis_ms = millis(analysis_start.elapsed());
    let cpu_after = cpu_time_ms();
    let analysis_stats = stats::snapshot();
    let allocation = alloc_delta(alloc_before, alloc_snapshot());

    debug_assert_eq!(objects, analysis_stats.objects_extracted as usize);
    let _ = objects;

    // Serialización del resultado (separada del análisis, A02.2).
    let serialization_start = Instant::now();
    let serialized = serde_json::to_vec(&result.findings).unwrap_or_default();
    let serialization_ms = millis(serialization_start.elapsed());

    let total_lines = analysis_stats.lines_evaluated;
    let throughput_lines_per_sec = if full_analysis_ms > 0.0 {
        total_lines as f64 / (full_analysis_ms / 1000.0)
    } else {
        0.0
    };
    let cpu_ms = match (cpu_before, cpu_after) {
        (Some(before), Some(after)) => Some((after - before).max(0.0)),
        _ => None,
    };

    // Latencia de cancelación cooperativa (sólo en modo benchmark).
    let cancellation_latency_ms = if check_mode {
        None
    } else {
        measure_cancellation(request, budget)
    };

    Ok(RunReport {
        run: run_index,
        temperature: if run_index == 0 { "cold" } else { "warm" },
        discovery_ms,
        extraction_ms,
        full_analysis_ms,
        serialization_ms,
        throughput_lines_per_sec,
        extraction_stats,
        analysis_stats,
        findings: result.metrics.total_findings,
        failures: result.failures.len(),
        result_bytes: serialized.len(),
        allocation,
        cpu_ms,
        cancellation_latency_ms,
        peak_working_set_bytes: peak_working_set_bytes(),
    })
}

/// Mide cuánto tarda una corrida en detenerse tras `cancel = true` (A02.3).
///
/// Best-effort: si el corpus es tan pequeño que el análisis termina antes de
/// la señal, devuelve `None` (no hay latencia que medir).
fn measure_cancellation(request: &AnalysisRequest, budget: &ExecutionBudget) -> Option<f64> {
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let cancel_thread = cancel.clone();
    let done_thread = done.clone();
    let request = request.clone();
    let budget = budget.clone();

    let handle = std::thread::spawn(move || {
        let _ =
            gx_engine::runtime::analyze_with_options(&request, None, Some(&cancel_thread), &budget);
        done_thread.store(true, Ordering::SeqCst);
    });

    std::thread::sleep(Duration::from_millis(1));
    if done.load(Ordering::SeqCst) {
        let _ = handle.join();
        return None;
    }
    let signaled = Instant::now();
    cancel.store(true, Ordering::SeqCst);
    let _ = handle.join();
    Some(millis(signaled.elapsed()))
}

/// Gate determinista de operation-counts (E01): no depende del timing del
/// runner, así que puede bloquear en CI compartido.
fn check_gates(manifest: &CorpusManifest, run: &RunReport, rule_count: usize) -> Result<()> {
    let stats = &run.analysis_stats;
    if manifest.total_lines > 0 && stats.lines_evaluated as usize != manifest.total_lines {
        bail!(
            "gate de líneas: esperadas {} y el engine evaluó {}",
            manifest.total_lines,
            stats.lines_evaluated
        );
    }
    if let Some(expected) = manifest.expected_objects {
        if stats.objects_extracted as usize != expected {
            bail!(
                "gate de objetos: esperados {expected} y el engine extrajo {}",
                stats.objects_extracted
            );
        }
        // D01: con packs habilitados (el bench corre todas las concretas) el
        // modelo semántico se calcula UNA vez por objeto.
        if stats.fact_model_requests as usize != expected {
            bail!(
                "gate de hechos: esperados {expected} modelos y hubo {}",
                stats.fact_model_requests
            );
        }
        // D04: el pase project-wide (GX.SEC.3 también corre en el bench)
        // recolecta exactamente los mismos objetos, sin duplicar ni perder.
        if stats.project_objects as usize != expected {
            bail!(
                "gate de proyecto: esperados {expected} objetos y hubo {}",
                stats.project_objects
            );
        }
    }
    if let Some(expected) = manifest.expected_xml_parses {
        // D04: cuando corre el pase project-wide (bench con packs profundos)
        // cada miembro XML se re-extrae una vez para recolectar el proyecto.
        let expected = if stats.project_objects > 0 {
            expected * 2
        } else {
            expected
        };
        if stats.parser_invocations as usize != expected {
            bail!(
                "gate de parser: esperadas {expected} invocaciones y hubo {}",
                stats.parser_invocations
            );
        }
    }
    // B02: las factories escalan con los rule-sets instanciados (jobs de
    // Rayon), no con archivos × catálogo. La RELACIÓN es determinista aunque
    // el número de jobs no lo sea.
    if stats.rule_set_instantiations == 0 {
        bail!("gate de factories: no se instanció ningún rule-set");
    }
    // B02/D04: como máximo un rule-set por worker/objeto, más UN set para el
    // pase project-wide cuando hay packs profundos seleccionados.
    if let Some(objects) = manifest.expected_objects {
        if stats.rule_set_instantiations > objects as u64 + 1 {
            bail!(
                "gate de factories: {} rule-sets para {objects} objetos (+1 de proyecto)",
                stats.rule_set_instantiations
            );
        }
    }
    let expected_factories = stats.rule_set_instantiations * rule_count as u64;
    if stats.rule_factory_invocations != expected_factories {
        bail!(
            "gate de factories: {expected_factories} esperadas ({} sets × {rule_count}) y hubo {}",
            stats.rule_set_instantiations,
            stats.rule_factory_invocations
        );
    }
    if stats.findings_emitted as usize != run.findings {
        bail!(
            "gate de findings: emitidos {} y reportados {}",
            stats.findings_emitted,
            run.findings
        );
    }
    if run.failures != 0 {
        bail!("el corpus de gate no debe tener fallos: {}", run.failures);
    }
    Ok(())
}

fn summarize(runs: &[RunReport]) -> Summary {
    let mut times: Vec<f64> = runs.iter().map(|r| r.full_analysis_ms).collect();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pick = |p: f64| -> f64 {
        if times.is_empty() {
            return 0.0;
        }
        let index = ((times.len() as f64 - 1.0) * p).ceil() as usize;
        times[index.min(times.len() - 1)]
    };
    Summary {
        runs: times.len(),
        min_ms: times.first().copied().unwrap_or(0.0),
        median_ms: pick(0.5),
        p95_ms: pick(0.95),
        max_ms: times.last().copied().unwrap_or(0.0),
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// Compilador usado en la medición (E01: trazabilidad del benchmark).
fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "desconocido".to_string())
}

fn timestamp() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("unix:{}", d.as_secs()),
        Err(_) => "unix:0".to_string(),
    }
}

/// CPU time (kernel+user) del proceso actual (A02.3). Windows: GetProcessTimes.
#[cfg(windows)]
fn cpu_time_ms() -> Option<f64> {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    impl FileTime {
        fn as_u64(&self) -> u64 {
            ((self.high as u64) << 32) | self.low as u64
        }
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn GetProcessTimes(
            process: *mut core::ffi::c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }

    unsafe {
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        let ok = GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        );
        if ok == 0 {
            return None;
        }
        Some((kernel.as_u64() + user.as_u64()) as f64 / 10_000.0)
    }
}

#[cfg(not(windows))]
fn cpu_time_ms() -> Option<f64> {
    None
}

/// Peak working set del proceso actual (A02.3). Windows via kernel32.
#[cfg(windows)]
fn peak_working_set_bytes() -> Option<u64> {
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut core::ffi::c_void,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }

    unsafe {
        let mut counters = ProcessMemoryCounters {
            cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
            page_fault_count: 0,
            peak_working_set_size: 0,
            working_set_size: 0,
            quota_peak_paged_pool_usage: 0,
            quota_paged_pool_usage: 0,
            quota_peak_non_paged_pool_usage: 0,
            quota_non_paged_pool_usage: 0,
            pagefile_usage: 0,
            peak_pagefile_usage: 0,
        };
        let ok = K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb);
        (ok != 0).then_some(counters.peak_working_set_size as u64)
    }
}

#[cfg(not(windows))]
fn peak_working_set_bytes() -> Option<u64> {
    None
}
